"""
Regulatory Normalizer: resolves free-text LLM output to canonical catalog keys.

3-tier resolution for subjects, actions, and resources:
  T1  Exact match
  T2  Alias table lookup
  T3  TF-IDF cosine similarity (with domain synonym expansion)

Unlike the access-policy normalizer, this handles 3 entity types
(subject, action, resource) rather than 2 (principal, resource).
"""

from __future__ import annotations

import logging
import re
from typing import Literal, Optional

from .catalog import (
    SUBJECT_ALIASES,
    ACTION_ALIASES,
    RESOURCE_ALIASES,
    subject_keys,
    action_keys,
    resource_keys,
)

logger = logging.getLogger(__name__)

EntityType = Literal["subject", "action", "resource"]
ResolutionTier = Literal["exact", "alias", "tfidf", "unresolved"]

_SIMILARITY_THRESHOLD = 0.40

# Domain synonym expansion for TF-IDF
_TFIDF_SYNONYMS: dict[str, str] = {
    "va": "vulnerability assessment",
    "pt": "penetration testing",
    "dr": "disaster recovery",
    "mfa": "multi-factor authentication",
    "pso": "payment system operator",
    "rbi": "reserve bank of india",
    "nbfc": "non-banking financial company",
    "dmz": "demilitarized zone",
    "scb": "scheduled commercial bank",
    "it": "information technology",
    "apps": "applications",
    "crypto": "cryptographic",
    "auth": "authentication",
    "creds": "credentials",
    "infra": "infrastructure",
    "vuln": "vulnerability",
    "pentest": "penetration testing",
    "logs": "audit logs",
}


def _get_alias_table(entity_type: EntityType) -> dict[str, str]:
    """Return the alias table for the given entity type."""
    if entity_type == "subject":
        return SUBJECT_ALIASES
    elif entity_type == "action":
        return ACTION_ALIASES
    else:
        return RESOURCE_ALIASES


def _get_candidates(entity_type: EntityType) -> list[str]:
    """Return all canonical keys for the given entity type."""
    if entity_type == "subject":
        return subject_keys()
    elif entity_type == "action":
        return action_keys()
    else:
        return resource_keys()


def _expand_synonyms(text: str) -> str:
    """Replace abbreviated tokens with full forms for better TF-IDF matching."""
    tokens = re.sub(r"[^\w\s]", " ", text.lower()).split()
    expanded = [_TFIDF_SYNONYMS.get(t, t) for t in tokens]
    return " ".join(expanded)


def _tfidf_match(
    raw: str,
    candidates: list[str],
) -> tuple[Optional[str], float]:
    """TF-IDF cosine similarity against candidate keys."""
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
    except ImportError:
        logger.warning("[RegNormalizer] scikit-learn not installed — T3 skipped.")
        return None, 0.0

    # Also match against aliases for better coverage
    expanded_raw = _expand_synonyms(raw)
    expanded_candidates = [_expand_synonyms(c.replace("_", " ")) for c in candidates]

    corpus = [expanded_raw] + expanded_candidates
    try:
        vec = TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 3),
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


def normalize_entity(
    raw: str,
    entity_type: EntityType,
) -> tuple[str, ResolutionTier, float]:
    """
    Normalize a free-text entity string to a canonical catalog key.

    Resolution order (first match wins):
      T1  Exact match against canonical keys
      T2  Alias table lookup
      T3  TF-IDF cosine similarity

    Args:
        raw:         Lowercase, trimmed string from LLM extraction.
        entity_type: "subject", "action", or "resource".

    Returns:
        (canonical_key, tier_used, confidence_score)
    """
    raw_clean = raw.strip().lower()
    candidates = _get_candidates(entity_type)
    alias_table = _get_alias_table(entity_type)

    # ── T1: Exact match ───────────────────────────────────────────────────────
    if raw_clean in candidates:
        logger.info("[RegNormalizer] T1 exact  %s %r → %r", entity_type, raw_clean, raw_clean)
        return raw_clean, "exact", 1.0

    # ── T2: Alias lookup ──────────────────────────────────────────────────────
    alias_hit = alias_table.get(raw_clean)
    if alias_hit and alias_hit in candidates:
        logger.info("[RegNormalizer] T2 alias  %s %r → %r", entity_type, raw_clean, alias_hit)
        return alias_hit, "alias", 1.0

    # ── T3: TF-IDF cosine similarity ─────────────────────────────────────────
    tfidf_hit, tfidf_score = _tfidf_match(raw_clean, candidates)
    if tfidf_hit:
        logger.info("[RegNormalizer] T3 tfidf  %s %r → %r (score=%.3f)",
                    entity_type, raw_clean, tfidf_hit, tfidf_score)
        return tfidf_hit, "tfidf", tfidf_score

    # ── Unresolved ────────────────────────────────────────────────────────────
    logger.warning("[RegNormalizer] UNRESOLVED %s %r (no match above threshold %.2f)",
                   entity_type, raw_clean, _SIMILARITY_THRESHOLD)
    return raw_clean, "unresolved", 0.0
