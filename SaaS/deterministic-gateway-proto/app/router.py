"""
Confidence Router: routes policies based on entity resolution confidence scores.

Routing decisions:
  AUTO_APPROVE     — high confidence (≥ 0.90) → compile directly
  REVIEW_REQUIRED  — medium confidence (0.60–0.90) → human review queue
  REJECTED         — low confidence (< 0.60) → reject immediately

Additional rules:
  - deny/conditional effects → always REVIEW_REQUIRED
  - T4 (LLM) resolution tier → always REVIEW_REQUIRED
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class RoutingDecision(str, Enum):
    AUTO_APPROVE = "auto_approve"
    REVIEW_REQUIRED = "review_required"
    REJECTED = "rejected"


@dataclass
class RoutingResult:
    """Full routing decision with audit trail."""
    decision: RoutingDecision
    overall_confidence: float
    principal_confidence: float
    resource_confidence: float
    reason: str
    flags: list[str]


# ── Thresholds ─────────────────────────────────────────────────────────────────

HIGH_CONFIDENCE_THRESHOLD = 0.90
LOW_CONFIDENCE_THRESHOLD = 0.60

# Effects that always require review
_REVIEW_REQUIRED_EFFECTS = frozenset({"deny", "conditional"})

# Resolution tiers that trigger review
_REVIEW_REQUIRED_TIERS = frozenset({"llm"})


class ConfidenceRouter:
    """
    Routes policies based on confidence scores, resolution tiers, and effect type.
    
    Every routing decision is logged with full scoring details for auditability.
    """

    def __init__(
        self,
        high_threshold: float = HIGH_CONFIDENCE_THRESHOLD,
        low_threshold: float = LOW_CONFIDENCE_THRESHOLD,
    ) -> None:
        self.high_threshold = high_threshold
        self.low_threshold = low_threshold

    def route(
        self,
        principal_score: float,
        resource_score: float,
        principal_tier: str = "exact",
        resource_tier: str = "exact",
        effect: str = "permit",
    ) -> RoutingResult:
        """
        Determine routing decision based on confidence scores and metadata.

        Args:
            principal_score: Confidence score for principal resolution (0.0–1.0).
            resource_score:  Confidence score for resource resolution (0.0–1.0).
            principal_tier:  Resolution tier used for principal (exact/alias/tfidf/llm).
            resource_tier:   Resolution tier used for resource (exact/alias/tfidf/llm).
            effect:          Policy effect (permit/deny/conditional).

        Returns:
            RoutingResult with decision, scores, reason, and flags.
        """
        flags: list[str] = []
        overall = (principal_score + resource_score) / 2.0

        # ── Flag collection ───────────────────────────────────────────────────
        if effect in _REVIEW_REQUIRED_EFFECTS:
            flags.append(f"effect_requires_review:{effect}")

        if principal_tier in _REVIEW_REQUIRED_TIERS:
            flags.append(f"principal_resolved_via_llm")

        if resource_tier in _REVIEW_REQUIRED_TIERS:
            flags.append(f"resource_resolved_via_llm")

        if principal_score < self.high_threshold:
            flags.append(f"principal_below_high_threshold:{principal_score:.3f}")

        if resource_score < self.high_threshold:
            flags.append(f"resource_below_high_threshold:{resource_score:.3f}")

        # ── Decision logic ────────────────────────────────────────────────────

        # Rule 1: Reject if either score is below low threshold
        if principal_score < self.low_threshold or resource_score < self.low_threshold:
            decision = RoutingDecision.REJECTED
            reason = (
                f"Confidence too low (principal={principal_score:.3f}, "
                f"resource={resource_score:.3f}, threshold={self.low_threshold})"
            )

        # Rule 2: Force review for deny/conditional effects
        elif effect in _REVIEW_REQUIRED_EFFECTS:
            decision = RoutingDecision.REVIEW_REQUIRED
            reason = f"Effect '{effect}' requires human review"

        # Rule 3: Force review if either entity was resolved via LLM (T4)
        elif principal_tier in _REVIEW_REQUIRED_TIERS or resource_tier in _REVIEW_REQUIRED_TIERS:
            decision = RoutingDecision.REVIEW_REQUIRED
            reason = "Entity resolved via LLM (T4) — requires review"

        # Rule 4: Auto-approve if both scores are above high threshold
        elif overall >= self.high_threshold:
            decision = RoutingDecision.AUTO_APPROVE
            reason = f"High confidence (overall={overall:.3f})"

        # Rule 5: Review required for medium confidence
        else:
            decision = RoutingDecision.REVIEW_REQUIRED
            reason = (
                f"Medium confidence (overall={overall:.3f}, "
                f"threshold={self.high_threshold})"
            )

        result = RoutingResult(
            decision=decision,
            overall_confidence=round(overall, 4),
            principal_confidence=round(principal_score, 4),
            resource_confidence=round(resource_score, 4),
            reason=reason,
            flags=flags,
        )

        logger.info(
            "[Router] %s  overall=%.3f  principal=%.3f[%s]  resource=%.3f[%s]  effect=%s  flags=%s  reason=%s",
            decision.value, overall, principal_score, principal_tier,
            resource_score, resource_tier, effect, flags, reason,
        )

        return result


# ── Module-level singleton ─────────────────────────────────────────────────────

_router = ConfidenceRouter()


def route_policy(
    principal_score: float,
    resource_score: float,
    principal_tier: str = "exact",
    resource_tier: str = "exact",
    effect: str = "permit",
) -> RoutingResult:
    """Convenience function using the default router."""
    return _router.route(
        principal_score=principal_score,
        resource_score=resource_score,
        principal_tier=principal_tier,
        resource_tier=resource_tier,
        effect=effect,
    )
