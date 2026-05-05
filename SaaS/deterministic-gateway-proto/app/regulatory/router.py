"""
Regulatory Confidence Router: routes controls based on multi-field confidence.

Routing decisions:
  AUTO_APPROVE         — overall ≥ 0.85, all fields resolved, source present
  REVIEW_REQUIRED      — 0.60–0.84 overall, or any field below threshold
  CATALOG_ENRICHMENT   — unresolved subject/action/resource (needs catalog expansion)
  REJECTED             — missing action, no enforceable rule, or overall < 0.40
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

from .schema import ControlIR

logger = logging.getLogger(__name__)


class ControlRoutingDecision(str, Enum):
    AUTO_APPROVE = "auto_approve"
    REVIEW_REQUIRED = "review_required"
    CATALOG_ENRICHMENT = "catalog_enrichment"
    REJECTED = "rejected"


@dataclass
class ControlRoutingResult:
    """Full routing decision with audit trail."""
    decision: ControlRoutingDecision
    overall_confidence: float
    reason: str
    flags: list[str]


# ── Thresholds ─────────────────────────────────────────────────────────────────

HIGH_THRESHOLD = 0.85
MEDIUM_THRESHOLD = 0.60
REJECT_THRESHOLD = 0.40


def route_control(ir: ControlIR) -> ControlRoutingResult:
    """
    Route a ControlIR based on confidence scores and field resolution.

    Uses resolution_confidence for routing decisions (catalog quality)
    and extraction_confidence for diagnostic flags (LLM quality).
    """
    flags: list[str] = []

    s_res = ir.subject.resolution_confidence
    a_res = ir.action.resolution_confidence
    r_res = ir.resource.resolution_confidence
    t_conf = ir.confidence.temporal
    overall = ir.confidence.overall

    # ── Flag collection ───────────────────────────────────────────────────────
    has_unresolved = False
    if ir.subject.resolution_tier == "unresolved":
        flags.append("subject_unresolved")
        has_unresolved = True
    if ir.action.resolution_tier == "unresolved":
        flags.append("action_unresolved")
        has_unresolved = True
    if ir.resource.resolution_tier == "unresolved":
        flags.append("resource_unresolved")
        has_unresolved = True

    if not ir.source.document_id or not ir.source.section:
        flags.append("missing_source_attribution")

    if not ir.action.normalized and not ir.action.raw:
        flags.append("missing_action")

    if ir.subject.extraction_confidence == 0.0:
        flags.append("subject_not_extracted")
    if ir.action.extraction_confidence == 0.0:
        flags.append("action_not_extracted")
    if ir.resource.extraction_confidence == 0.0:
        flags.append("resource_not_extracted")

    if s_res < HIGH_THRESHOLD:
        flags.append(f"subject_resolution_below:{s_res:.3f}")
    if a_res < HIGH_THRESHOLD:
        flags.append(f"action_resolution_below:{a_res:.3f}")
    if r_res < HIGH_THRESHOLD:
        flags.append(f"resource_resolution_below:{r_res:.3f}")

    # ── Decision logic ────────────────────────────────────────────────────────

    # Rule 1: Reject if no action found
    if not ir.action.normalized and not ir.action.raw:
        decision = ControlRoutingDecision.REJECTED
        reason = "No enforceable action found in rule"

    # Rule 2: Reject if overall confidence too low
    elif overall < REJECT_THRESHOLD:
        decision = ControlRoutingDecision.REJECTED
        reason = f"Overall confidence too low ({overall:.3f} < {REJECT_THRESHOLD})"

    # Rule 3: Catalog enrichment if any entity is unresolved
    elif has_unresolved:
        decision = ControlRoutingDecision.CATALOG_ENRICHMENT
        unresolved_fields = [f for f in ["subject", "action", "resource"]
                            if getattr(ir, f).resolution_tier == "unresolved"]
        reason = f"Unresolved entities need catalog expansion: {unresolved_fields}"

    # Rule 4: Auto-approve if all high confidence + source present
    elif (overall >= HIGH_THRESHOLD
          and ir.source.document_id
          and ir.source.section):
        decision = ControlRoutingDecision.AUTO_APPROVE
        reason = f"High confidence ({overall:.3f}), source present"

    # Rule 5: Review required for medium confidence or missing source
    else:
        decision = ControlRoutingDecision.REVIEW_REQUIRED
        reasons = []
        if overall < HIGH_THRESHOLD:
            reasons.append(f"medium confidence ({overall:.3f})")
        if not ir.source.document_id or not ir.source.section:
            reasons.append("missing source attribution")
        reason = "; ".join(reasons) if reasons else "review recommended"

    result = ControlRoutingResult(
        decision=decision,
        overall_confidence=round(overall, 4),
        reason=reason,
        flags=flags,
    )

    logger.info(
        "[ControlRouter] %s  overall=%.3f  s_res=%.3f  a_res=%.3f  r_res=%.3f  flags=%s",
        decision.value, overall, s_res, a_res, r_res, flags,
    )

    return result
