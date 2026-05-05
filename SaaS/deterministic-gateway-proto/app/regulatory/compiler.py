"""
Governance YAML Compiler: converts ControlIR → audit-ready YAML.

Pure deterministic template. Zero LLM involvement.
Output is designed for compliance/audit workflows.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

import yaml

from .schema import ControlIR

logger = logging.getLogger(__name__)


def _generate_control_id(ir: ControlIR) -> str:
    """Generate a human-readable control ID from source and action."""
    doc = ir.source.document_id or "UNKNOWN"
    section = ir.source.section or "0"
    action = ir.action.normalized or ir.action.raw or "control"

    # Clean up for ID generation
    doc_clean = re.sub(r"[/\s.]+", "-", doc).strip("-")
    action_clean = action.upper().replace("_", "-")
    section_clean = re.sub(r"[^\w]", "", section)

    return f"{doc_clean}-{section_clean}-{action_clean}"


def compile_governance_yaml(ir: ControlIR) -> str:
    """
    Compile a ControlIR into Governance YAML format.

    Args:
        ir: Validated ControlIR with resolved entities.

    Returns:
        Formatted YAML string.
    """
    control_id = _generate_control_id(ir)

    # Build the YAML structure
    control_dict = {
        "control": {
            "id": control_id,
            "version": ir.version,
            "status": ir.status,
            "rule_type": ir.rule_type,
            "source": {
                "document": ir.source.document_id,
                "section": ir.source.section,
            },
            "requirement": {
                "subject": ir.subject.canonical_key or ir.subject.raw,
                "action": ir.action.normalized or ir.action.raw,
                "resource": ir.resource.canonical_key or ir.resource.raw,
                "effect": ir.effect,
            },
            "constraints": [
                {
                    k: v for k, v in {
                        "field": c.field,
                        "operator": c.operator,
                        "value": c.value,
                        "unit": c.unit,
                        "description": c.description,
                        "source_text": c.source_text,
                    }.items() if v is not None
                }
                for c in ir.constraints
            ] if ir.constraints else [],
        },
    }

    # Add effective date if present
    if ir.source.effective_date:
        control_dict["control"]["source"]["effective_date"] = ir.source.effective_date

    # Add temporal constraints (only non-null fields)
    temporal = {}
    if ir.temporal.frequency:
        temporal["frequency"] = ir.temporal.frequency
    if ir.temporal.deadline:
        temporal["deadline"] = ir.temporal.deadline
    if ir.temporal.retention:
        temporal["retention"] = ir.temporal.retention
    if ir.temporal.cooling_period:
        temporal["cooling_period"] = ir.temporal.cooling_period
    if temporal:
        control_dict["control"]["temporal"] = temporal

    # Add evidence
    control_dict["control"]["evidence"] = {
        "required": ir.evidence.required,
    }
    if ir.evidence.artifact_type:
        control_dict["control"]["evidence"]["artifact"] = ir.evidence.artifact_type

    # Add confidence and review
    control_dict["control"]["confidence"] = {
        "overall": round(ir.confidence.overall, 3),
        "subject_extraction": round(ir.confidence.subject_extraction, 3),
        "subject_resolution": round(ir.confidence.subject_resolution, 3),
        "action_extraction": round(ir.confidence.action_extraction, 3),
        "action_resolution": round(ir.confidence.action_resolution, 3),
        "resource_extraction": round(ir.confidence.resource_extraction, 3),
        "resource_resolution": round(ir.confidence.resource_resolution, 3),
    }

    control_dict["control"]["review"] = {
        "required": ir.review.required,
    }
    if ir.review.reason:
        control_dict["control"]["review"]["reason"] = ir.review.reason

    output = yaml.dump(
        control_dict,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )

    logger.info("[YAMLCompiler] Governance YAML generated for %s (%d chars).",
                control_id, len(output))
    return output
