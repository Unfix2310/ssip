"""
Semantic Resolution Engine.

Resolves free-text LLM output to canonical catalog keys using four ordered tiers.
First match wins. Every decision is logged with tier + score for auditability.

Tiers:
  T1  Exact match            zero cost, deterministic
  T2  Alias + synonym table  covers known abbreviations / env prefixes
  T3  TF-IDF cosine sim      handles "production logs" → "server logs"
  T4  LLM bounded choice     last resort, bounded to catalog — cannot hallucinate

Hard contracts:
  - Never returns a key not in the candidate list.
  - Raises EntityResolutionError with scored candidates if all tiers fail.
  - Threshold for T3 is explicit and logged.
  - Pipeline order is: extract → normalize → validate canonical → compile.
    Validation must NOT run on raw LLM strings.
"""

from __future__ import annotations

import logging
import math
import os
import re
from typing import Literal, Optional

from .exceptions import EntityResolutionError

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# T2 — Alias + synonym table
# Maps raw free-text strings and env-prefixed variants → canonical catalog keys.
# Populated once at module load, used as O(1) dict lookup.
# Add rows here when new naming patterns emerge in production.
# ─────────────────────────────────────────────────────────────────────────────

_PRINCIPAL_ALIASES: dict[str, str] = {
    # developers
    "dev team":           "developers",
    "devs":               "developers",
    "dev":                "developers",
    "software engineers": "developers",
    "engineering team":   "developers",
    "engineers":          "developers",
    "swe team":           "developers",
    "backend team":       "developers",
    "backend engineers":  "developers",
    "frontend team":      "developers",
    # finance
    "finance":            "finance team",
    "finance dept":       "finance team",
    "finance department": "finance team",
    "accounting team":    "finance team",
    # admin
    "admins":             "admin team",
    "administrators":     "admin team",
    "admin":              "admin team",
    "ops team":           "admin team",
    "operations team":    "admin team",
    # security
    "security":           "security team",
    "sec team":           "security team",
    "infosec":            "security team",
    "infosec team":       "security team",
    "cybersecurity team": "security team",
    # data
    "data":               "data team",
    "data engineers":     "data team",
    "data engineering":   "data team",
    "analytics team":     "data team",
    # qa
    "qa":                 "qa team",
    "qe team":            "qa team",
    "quality assurance":  "qa team",
    "testers":            "qa team",
}

_RESOURCE_ALIASES: dict[str, str] = {
    # server logs — the canonical example of the problem
    "production logs":      "server logs",
    "prod logs":            "server logs",
    "prod server logs":     "server logs",
    "live server logs":     "server logs",
    "live logs":            "server logs",
    "app logs":             "server logs",
    "application logs":     "server logs",
    "runtime logs":         "server logs",
    "service logs":         "server logs",
    "system logs":          "server logs",
    "server log":           "server logs",
    "logs":                 "server logs",
    # audit logs
    "audit":                "audit logs",
    "audit trail":          "audit logs",
    "compliance logs":      "audit logs",
    "access logs":          "audit logs",
    # payroll
    "payroll":              "payroll bucket",
    "payroll data":         "payroll bucket",
    "payroll files":        "payroll bucket",
    "salary data":          "payroll bucket",
    "hr payroll":           "payroll bucket",
    # config
    "config":               "config bucket",
    "configuration":        "config bucket",
    "cfg":                  "config bucket",
    "settings":             "config bucket",
    "config data":          "config bucket",
    # ml models
    "ml models":            "ml models",
    "models":               "ml models",
    "model registry":       "ml models",
    "ai models":            "ml models",
    # user data
    "user data":            "user data",
    "user profiles":        "user data",
    "user records":         "user data",
    "customer data":        "user data",
}


# ─────────────────────────────────────────────────────────────────────────────
# T3 — TF-IDF cosine similarity
# ─────────────────────────────────────────────────────────────────────────────

# Similarity score threshold below which we don't trust the match.
# At 0.15 the vector space is sparse enough that false positives are rare.
_SIMILARITY_THRESHOLD = 0.25

# Domain synonym expansion applied during TF-IDF tokenization.
# Maps single tokens → canonical tokens so the vector space is denser.
_TFIDF_SYNONYMS: dict[str, str] = {
    "prod":          "production",
    "live":          "production",
    "srv":           "server",
    "svc":           "service",
    "app":           "application",
    "svc":           "service",
    "cfg":           "configuration",
    "config":        "configuration",
    "dev":           "developer",
    "devs":          "developer",
    "eng":           "engineer",
    "sec":           "security",
    "infosec":       "security",
    "hr":            "human resources",
    "payroll":       "payroll",
    "audit":         "audit",
    "runtime":       "server",
    "system":        "server",
}


def _expand_synonyms(text: str) -> str:
    """Replace known abbreviated tokens with canonical equivalents before vectorizing."""
    tokens = re.sub(r"[^\w\s]", " ", text.lower()).split()
    expanded = [_TFIDF_SYNONYMS.get(t, t) for t in tokens]
    return " ".join(expanded)


def _tfidf_match(
    raw: str,
    candidates: list[str],
) -> tuple[Optional[str], float]:
    """
    Compute TF-IDF cosine similarity between raw and all candidates.
    Returns (best_candidate, score) or (None, 0.0) if below threshold.
    """
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
    except ImportError:
        logger.warning("[Normalizer] scikit-learn not installed — T3 skipped.")
        return None, 0.0

    expanded_raw = _expand_synonyms(raw)
    expanded_candidates = [_expand_synonyms(c) for c in candidates]

    corpus = [expanded_raw] + expanded_candidates
    try:
        vec = TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 2),   # unigrams + bigrams
            min_df=1,
            token_pattern=r"(?u)\b\w+\b",
        )
        matrix = vec.fit_transform(corpus)
    except ValueError:
        return None, 0.0

    scores = cosine_similarity(matrix[0:1], matrix[1:]).flatten()
    best_idx = int(scores.argmax())
    best_score = float(scores[best_idx])

    if best_score >= _SIMILARITY_THRESHOLD:
        return candidates[best_idx], best_score
    return None, best_score


# ─────────────────────────────────────────────────────────────────────────────
# T4 — LLM bounded choice (last resort)
# ─────────────────────────────────────────────────────────────────────────────

def _llm_disambiguate(
    raw: str,
    entity_type: Literal["principal", "resource"],
    candidates: list[str],
) -> Optional[str]:
    """
    Ask the LLM to pick the best catalog key from the bounded candidate list.
    The model cannot return anything outside that list, so hallucination is impossible.
    Returns None if no match or if API is unavailable.
    """
    try:
        import anthropic
    except ImportError:
        logger.warning("[Normalizer] anthropic not installed — T4 skipped.")
        return None

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        logger.warning("[Normalizer] ANTHROPIC_API_KEY not set — T4 skipped.")
        return None

    client = anthropic.Anthropic(api_key=api_key)
    candidate_list = "\n".join(f"- {c}" for c in candidates)

    system = (
        f"You are a security entity mapper. Match a natural language {entity_type} "
        f"description to the single best entry in a catalog. "
        f"Return ONLY the exact catalog key string. "
        f"If no entry is a reasonable match, return exactly: NONE\n"
        f"No explanation. No quotes. No markdown."
    )
    user = (
        f'Input: "{raw}"\n\n'
        f"Catalog entries:\n{candidate_list}\n\n"
        f"Best match:"
    )

    try:
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=64,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text_blocks = [b.text for b in response.content if hasattr(b, "text")]
        answer = "".join(text_blocks).strip().strip('"').strip("'")
        logger.info("[Normalizer] T4 LLM returned: %r", answer)
        if answer == "NONE" or answer not in candidates:
            return None
        return answer
    except Exception as exc:  # noqa: BLE001
        logger.warning("[Normalizer] T4 LLM call failed: %s", exc)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Public interface
# ─────────────────────────────────────────────────────────────────────────────

ResolutionTier = Literal["exact", "alias", "tfidf", "llm"]


def normalize_entity(
    raw: str,
    entity_type: Literal["principal", "resource"],
    candidates: list[str],
) -> tuple[str, ResolutionTier, float]:
    """
    Normalize a free-text entity string to a canonical catalog key.

    Resolution order (first match wins):
      T1  Exact match against candidate list
      T2  Alias / synonym table lookup
      T3  TF-IDF cosine similarity (threshold: 0.15)
      T4  LLM bounded selection from candidate list

    Args:
        raw:         Lowercase, trimmed string from the LLM IR.
        entity_type: "principal" or "resource".
        candidates:  All valid canonical catalog keys of this type.

    Returns:
        (canonical_key, tier_used, confidence_score)
        confidence_score = 1.0 for T1/T2, cosine score for T3, 0.9 for T4.

    Raises:
        EntityResolutionError: All four tiers failed.
            The error message includes ranked candidates with their TF-IDF
            scores so the caller / operator can diagnose the gap.
    """
    alias_table = (
        _PRINCIPAL_ALIASES if entity_type == "principal" else _RESOURCE_ALIASES
    )

    # ── T1: Exact match ───────────────────────────────────────────────────────
    if raw in candidates:
        logger.info("[Normalizer] T1 exact  %s %r → %r", entity_type, raw, raw)
        return raw, "exact", 1.0

    # ── T2: Alias / synonym table ─────────────────────────────────────────────
    alias_hit = alias_table.get(raw)
    if alias_hit and alias_hit in candidates:
        logger.info(
            "[Normalizer] T2 alias  %s %r → %r", entity_type, raw, alias_hit
        )
        return alias_hit, "alias", 1.0

    # ── T3: TF-IDF cosine similarity ─────────────────────────────────────────
    tfidf_hit, tfidf_score = _tfidf_match(raw, candidates)
    if tfidf_hit:
        logger.info(
            "[Normalizer] T3 tfidf  %s %r → %r  (score=%.3f)",
            entity_type, raw, tfidf_hit, tfidf_score,
        )
        return tfidf_hit, "tfidf", tfidf_score

    # ── T4: LLM bounded selection ─────────────────────────────────────────────
    llm_hit = _llm_disambiguate(raw, entity_type, candidates)
    if llm_hit:
        logger.info(
            "[Normalizer] T4 llm    %s %r → %r", entity_type, raw, llm_hit
        )
        return llm_hit, "llm", 0.9

    # ── All tiers exhausted ───────────────────────────────────────────────────
    # Build a scored candidate list for the error message so operators can
    # immediately see what came closest and add an alias if needed.
    _, all_scores = _tfidf_match_all(raw, candidates)
    ranked = sorted(
        zip(candidates, all_scores), key=lambda x: x[1], reverse=True
    )
    ranked_str = ", ".join(
        f"{k!r} ({s:.2f})" for k, s in ranked[:3]
    )
    raise EntityResolutionError(
        f"Cannot resolve {entity_type}: {raw!r}. "
        f"Top candidates by similarity: [{ranked_str}]. "
        f"Add an alias to the resolution table or expand the catalog."
    )


def _tfidf_match_all(
    raw: str,
    candidates: list[str],
) -> tuple[Optional[str], list[float]]:
    """Return scores for ALL candidates (used in error reporting)."""
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
    except ImportError:
        return None, [0.0] * len(candidates)

    expanded_raw = _expand_synonyms(raw)
    expanded_candidates = [_expand_synonyms(c) for c in candidates]
    corpus = [expanded_raw] + expanded_candidates
    try:
        vec = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=1)
        matrix = vec.fit_transform(corpus)
    except ValueError:
        return None, [0.0] * len(candidates)

    scores = cosine_similarity(matrix[0:1], matrix[1:]).flatten().tolist()
    return None, scores
