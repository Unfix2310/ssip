"""
ControlIR Validator: validates extracted ControlIR before compilation.

Rule-type-specific validation ensures correct field presence:
  - All rules:        source.document_id, source.section, rule_type, subject, action, effect
  - frequency_rule:   temporal.frequency required
  - deadline_rule:    temporal.deadline required
  - retention_rule:   temporal.retention required
  - cooling_period:   temporal.cooling_period required
"""

from __future__ import annotations

import logging
from typing import Optional

from ..exceptions import ControlValidationError
from .schema import ALLOWED_EFFECTS, ALLOWED_RULE_TYPES, VALID_CONSTRAINT_OPERATORS, ControlIR

logger = logging.getLogger(__name__)


def validate_control_ir(ir: ControlIR) -> list[str]:
    """
    Validate a ControlIR for completeness and correctness.

    Args:
        ir: The ControlIR to validate.

    Returns:
        List of validation warnings (non-fatal).

    Raises:
        ControlValidationError: On fatal validation failures.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # ── 1. Mandatory fields ───────────────────────────────────────────────────
    if not ir.source.document_id:
        errors.append("Missing source.document_id")
    if not ir.source.section:
        errors.append("Missing source.section")
    if not ir.rule_type:
        errors.append("Missing rule_type")
    if not ir.subject.raw and not ir.subject.canonical_key:
        errors.append("Missing subject (raw and canonical_key both empty)")
    if not ir.action.raw and not ir.action.normalized:
        errors.append("Missing action (raw and normalized both empty)")
    if not ir.effect:
        errors.append("Missing effect")

    # ── 2. Allowed values ─────────────────────────────────────────────────────
    if ir.rule_type and ir.rule_type not in ALLOWED_RULE_TYPES:
        warnings.append(f"Unknown rule_type: {ir.rule_type!r}")

    if ir.effect and ir.effect not in ALLOWED_EFFECTS:
        errors.append(f"Invalid effect: {ir.effect!r}. Allowed: {sorted(ALLOWED_EFFECTS)}")

    # ── 3. Rule-type-specific validation ──────────────────────────────────────
    if ir.rule_type == "frequency_rule" or (ir.rule_type == "obligation" and ir.temporal.frequency):
        if not ir.temporal.frequency:
            warnings.append("frequency_rule without temporal.frequency")

    if ir.rule_type == "deadline_rule":
        if not ir.temporal.deadline:
            warnings.append("deadline_rule without temporal.deadline")

    if ir.rule_type == "retention_rule":
        if not ir.temporal.retention:
            warnings.append("retention_rule without temporal.retention")

    if ir.rule_type == "cooling_period_rule":
        if not ir.temporal.cooling_period:
            warnings.append("cooling_period_rule without temporal.cooling_period")

    # ── 4. Resource (recommended but not fatal) ───────────────────────────────
    if not ir.resource.raw and not ir.resource.canonical_key:
        warnings.append("Missing resource — rule may be too broad")

    # ── 5. Constraint validation ──────────────────────────────────────────────
    for i, c in enumerate(ir.constraints):
        if not c.field:
            warnings.append(f"Constraint [{i}] has empty field name")
        if c.operator not in VALID_CONSTRAINT_OPERATORS:
            warnings.append(f"Constraint [{i}] has invalid operator: {c.operator!r}")
        if not c.value:
            warnings.append(f"Constraint [{i}] ({c.field}) has empty value")

    # ── 6. Fatal confidence gate ──────────────────────────────────────────────
    overall_confidence = ir.confidence.overall
    if ir.action.resolution_confidence == 0.0 and overall_confidence < 0.40:
        errors.append(
            "Action has zero resolution confidence and overall confidence is low — "
            "extraction is not actionable. Not stored."
        )

    # ── 7. Resolution quality warnings ────────────────────────────────────────
    if ir.subject.resolution_tier == "unresolved":
        warnings.append(f"Subject unresolved: {ir.subject.raw!r}")
    if ir.action.resolution_tier == "unresolved":
        warnings.append(f"Action unresolved: {ir.action.raw!r} (resolution_confidence={ir.action.resolution_confidence})")
    if ir.resource.resolution_tier == "unresolved":
        warnings.append(f"Resource unresolved: {ir.resource.raw!r} (resolution_confidence={ir.resource.resolution_confidence})")

    # ── Fail on errors ────────────────────────────────────────────────────────
    if errors:
        raise ControlValidationError(
            f"ControlIR validation failed: {'; '.join(errors)}"
        )

    if warnings:
        logger.warning("[Validator] Warnings for control %s: %s",
                       ir.id[:8] if ir.id else "?", "; ".join(warnings))

    return warnings
