"""
Regulatory Pipeline: end-to-end RBI rule text → Governance YAML.

6-stage pipeline:
  1. LLM Extraction       → raw ControlIR dict
  2. Normalization         → resolve subject/action/resource to canonical keys
  3. ControlIR Validation  → rule-type-specific field checks
  4. Confidence Routing    → auto-approve / review / catalog enrichment / reject
  5. YAML Compilation      → Governance YAML output
  6. Validation Report     → structured result with warnings

Retry policy: same as access pipeline (max 2 retries for extraction errors).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from ..exceptions import (
    ControlExtractionError,
    ControlValidationError,
    LLMExtractionError,
    MaxRetriesExceededError,
    RoutingError,
)
from .compiler import compile_governance_yaml
from .llm import extract_control_ir
from .normalizer import normalize_entity
from .router import ControlRoutingDecision, route_control
from .schema import (
    ActionField,
    ControlConstraint,
    ConfidenceScores,
    ControlIR,
    EvidenceRequirement,
    ResourceField,
    ReviewMetadata,
    SourceAttribution,
    SubjectField,
    TemporalConstraint,
    VALID_CONSTRAINT_OPERATORS,
    generate_control_id,
    generate_run_id,
)
from .validator import validate_control_ir

logger = logging.getLogger(__name__)

MAX_RETRIES = 2

# ── Access-policy gate patterns ───────────────────────────────────────────────

import re

_ACCESS_POLICY_PATTERNS = [
    re.compile(r"^\s*(allow|deny|permit|forbid|grant|revoke)\b", re.IGNORECASE),
    re.compile(r"\b(to\s+read|to\s+write|to\s+delete|to\s+access)\b", re.IGNORECASE),
    re.compile(r"\b(principals?|roles?)\s+(can|cannot|may|may not)\b", re.IGNORECASE),
]


def _is_access_policy_text(text: str) -> bool:
    """Detect if text is an access policy statement, not a regulatory rule."""
    matches = sum(1 for p in _ACCESS_POLICY_PATTERNS if p.search(text))
    return matches >= 1


@dataclass
class ControlPipelineResult:
    """Result of the regulatory pipeline."""
    control_id: str
    ir: dict[str, Any]
    compiled_yaml: str
    routing: dict[str, Any]
    validation_warnings: list[str]
    attempts: int


def _build_control_ir(
    raw: dict[str, Any],
    document_id: str,
    section: str,
    effective_date: Optional[str] = None,
) -> ControlIR:
    """
    Build a ControlIR from raw LLM extraction + normalization.
    Computes separate extraction_confidence and resolution_confidence.
    """
    run_id = generate_run_id()
    control_id = generate_control_id()

    # ── Normalize subject ─────────────────────────────────────────────────────
    raw_subject = str(raw.get("subject", "")).strip().lower()
    s_extract_conf = 1.0 if raw_subject else 0.0
    s_canonical, s_tier, s_resolve_conf = normalize_entity(raw_subject, "subject")

    # ── Normalize action ──────────────────────────────────────────────────────
    raw_action = str(raw.get("action", "")).strip().lower()
    a_extract_conf = 1.0 if raw_action else 0.0
    a_canonical, a_tier, a_resolve_conf = normalize_entity(raw_action, "action")

    # ── Normalize resource ────────────────────────────────────────────────────
    raw_resource = str(raw.get("resource", "")).strip().lower()
    r_extract_conf = 1.0 if raw_resource else 0.0
    r_canonical, r_tier, r_resolve_conf = normalize_entity(raw_resource, "resource")

    # ── Temporal ──────────────────────────────────────────────────────────────
    temporal_raw = raw.get("temporal", {})
    if not isinstance(temporal_raw, dict):
        temporal_raw = {}

    temporal = TemporalConstraint(
        frequency=temporal_raw.get("frequency"),
        deadline=temporal_raw.get("deadline"),
        retention=temporal_raw.get("retention"),
        cooling_period=temporal_raw.get("cooling_period"),
    )

    # Temporal confidence: 1.0 if temporal fields match rule_type, else lower
    t_score = 1.0
    rule_type = raw.get("rule_type", "obligation")
    if rule_type == "frequency_rule" and not temporal.frequency:
        t_score = 0.3
    elif rule_type == "deadline_rule" and not temporal.deadline:
        t_score = 0.3
    elif rule_type == "retention_rule" and not temporal.retention:
        t_score = 0.3
    elif rule_type == "cooling_period_rule" and not temporal.cooling_period:
        t_score = 0.3

    # ── Constraints ────────────────────────────────────────────────────────────
    constraints_raw = raw.get("constraints", [])
    constraints = []
    if isinstance(constraints_raw, list):
        for c in constraints_raw:
            if isinstance(c, dict) and c.get("field"):
                operator = c.get("operator", "equals")
                if operator not in VALID_CONSTRAINT_OPERATORS:
                    logger.warning("[RegPipeline] Unknown constraint operator %r, defaulting to 'equals'", operator)
                    operator = "equals"
                constraints.append(ControlConstraint(
                    field=c.get("field", ""),
                    operator=operator,
                    value=str(c.get("value", "")),
                    unit=c.get("unit"),
                    description=c.get("description"),
                    source_text=c.get("source_text"),
                ))

    # ── Evidence ──────────────────────────────────────────────────────────────
    evidence_raw = raw.get("evidence", {})
    if not isinstance(evidence_raw, dict):
        evidence_raw = {}

    evidence = EvidenceRequirement(
        required=evidence_raw.get("required", True),
        artifact_type=evidence_raw.get("artifact_type"),
    )

    # ── Confidence (split extraction vs resolution) ───────────────────────────
    # Overall = weighted average: resolution matters more for routing
    overall = (
        (s_resolve_conf + a_resolve_conf + r_resolve_conf + t_score) / 4.0
    )

    confidence = ConfidenceScores(
        overall=round(overall, 4),
        subject_extraction=round(s_extract_conf, 4),
        subject_resolution=round(s_resolve_conf, 4),
        action_extraction=round(a_extract_conf, 4),
        action_resolution=round(a_resolve_conf, 4),
        resource_extraction=round(r_extract_conf, 4),
        resource_resolution=round(r_resolve_conf, 4),
        temporal=round(t_score, 4),
    )

    # ── Build IR ──────────────────────────────────────────────────────────────
    ir = ControlIR(
        id=control_id,
        version="1.0.0",
        status="draft",
        rule_type=rule_type,
        effect=raw.get("effect", "required"),
        subject=SubjectField(
            raw=raw_subject,
            canonical_key=s_canonical,
            extraction_confidence=s_extract_conf,
            resolution_confidence=s_resolve_conf,
            resolution_tier=s_tier,
        ),
        action=ActionField(
            raw=raw_action,
            normalized=a_canonical,
            extraction_confidence=a_extract_conf,
            resolution_confidence=a_resolve_conf,
            resolution_tier=a_tier,
        ),
        resource=ResourceField(
            raw=raw_resource,
            canonical_key=r_canonical,
            extraction_confidence=r_extract_conf,
            resolution_confidence=r_resolve_conf,
            resolution_tier=r_tier,
        ),
        constraints=constraints,
        temporal=temporal,
        evidence=evidence,
        source=SourceAttribution(
            document_id=document_id,
            section=section,
            effective_date=effective_date,
        ),
        confidence=confidence,
        review=ReviewMetadata(),
        extraction_run=run_id,
    )

    logger.info(
        "[RegPipeline] IR built: id=%s type=%s subject=%s→%s[%s] action=%s→%s[%s] resource=%s→%s[%s]",
        control_id[:8], rule_type,
        raw_subject[:20], s_canonical, s_tier,
        raw_action[:20], a_canonical, a_tier,
        raw_resource[:20], r_canonical, r_tier,
    )

    return ir


def run_regulatory_pipeline(
    rule_text: str,
    document_id: str = "",
    section: str = "",
    effective_date: Optional[str] = None,
    parent_context: Optional[str] = None,
) -> ControlPipelineResult:
    """
    Execute the full RBI rule → Governance YAML pipeline.

    Args:
        rule_text:       Raw regulatory rule sentence.
        document_id:     Source document identifier.
        section:         Section number.
        effective_date:  Optional effective date.
        parent_context:  Full text of parent clause (for compound sub-clauses).

    Returns:
        ControlPipelineResult with IR, compiled YAML, routing, and warnings.
    """
    # ── Stage 0: Access-policy gate ───────────────────────────────────────
    if _is_access_policy_text(rule_text):
        raise ControlValidationError(
            "Input looks like an access policy (Allow/Deny/Permit), not a regulatory rule. "
            "Use POST /generate-policy instead."
        )

    error_context: Optional[str] = None
    last_error: Optional[Exception] = None

    for attempt in range(1, MAX_RETRIES + 2):
        logger.info("━━━ Regulatory Pipeline attempt %d / %d ━━━", attempt, MAX_RETRIES + 1)

        try:
            # ── Stage 1: LLM extraction ───────────────────────────────────────
            raw = extract_control_ir(
                rule_text,
                document_id=document_id,
                section=section,
                error_context=error_context,
                parent_context=parent_context,
            )

            # ── Stage 2: Normalization + IR construction ──────────────────────
            ir = _build_control_ir(raw, document_id, section, effective_date)

            # ── Stage 3: Validation ───────────────────────────────────────────
            warnings = validate_control_ir(ir)

            # ── Stage 4: Confidence routing ───────────────────────────────────
            routing = route_control(ir)

            if routing.decision == ControlRoutingDecision.REJECTED:
                raise RoutingError(
                    f"Control rejected by router: {routing.reason}"
                )

            # Update IR with routing result
            if routing.decision == ControlRoutingDecision.REVIEW_REQUIRED:
                ir.status = "pending_review"
                ir.review.required = True
                ir.review.reason = routing.reason
            elif routing.decision == ControlRoutingDecision.CATALOG_ENRICHMENT:
                ir.status = "pending_enrichment"
                ir.review.required = True
                ir.review.reason = routing.reason
            else:
                ir.status = "approved"

            # ── Stage 5: Governance YAML compilation ──────────────────────────
            compiled_yaml = compile_governance_yaml(ir)

            # ── Stage 6: Result ───────────────────────────────────────────────
            logger.info("[RegPipeline] Success after %d attempt(s). Routing: %s",
                        attempt, routing.decision.value)

            return ControlPipelineResult(
                control_id=ir.id,
                ir=ir.to_dict(),
                compiled_yaml=compiled_yaml,
                routing={
                    "decision": routing.decision.value,
                    "overall_confidence": routing.overall_confidence,
                    "reason": routing.reason,
                    "flags": routing.flags,
                },
                validation_warnings=warnings,
                attempts=attempt,
            )

        except (RoutingError, ControlValidationError):
            raise

        except (LLMExtractionError, ControlExtractionError) as exc:
            last_error = exc
            error_context = str(exc)
            logger.warning(
                "[RegPipeline] Retryable error attempt %d: %s", attempt, exc,
            )
            if attempt > MAX_RETRIES:
                break

        except Exception as exc:
            logger.error("[RegPipeline] Unexpected error: %s", exc)
            raise

    raise MaxRetriesExceededError(
        f"Regulatory pipeline failed after {MAX_RETRIES + 1} attempts. "
        f"Last: {type(last_error).__name__}: {last_error}"
    )
