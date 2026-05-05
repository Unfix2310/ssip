"""
ControlIR: Intermediate Representation for regulatory controls.

Unlike PolicyIR (access-focused: permit/deny), ControlIR handles compliance
obligations, prohibitions, deadlines, frequencies, retention periods, and
cooling periods from RBI/DPSS regulatory text.

Key differences from PolicyIR:
  - effect: required | prohibited | conditional (not permit/deny)
  - temporal: frequency, deadline, retention, cooling_period
  - evidence: required artifacts for compliance proof
  - source: mandatory document_id + section attribution
  - rule_type: obligation, prohibition, deadline_rule, frequency_rule,
               retention_rule, cooling_period_rule
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

EXTRACTOR_VERSION = "v1.0.0-regulatory"

# ── Allowed values ────────────────────────────────────────────────────────────

ALLOWED_RULE_TYPES = frozenset({
    "obligation",
    "prohibition",
    "deadline_rule",
    "frequency_rule",
    "retention_rule",
    "cooling_period_rule",
})

ALLOWED_EFFECTS = frozenset({
    "required",
    "prohibited",
    "conditional",
})


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class SubjectField:
    """Who must comply."""
    raw: str = ""
    canonical_key: str = ""
    extraction_confidence: float = 0.0    # LLM extraction quality
    resolution_confidence: float = 0.0    # catalog matching quality
    resolution_tier: str = "unresolved"


@dataclass
class ActionField:
    """What must be done."""
    raw: str = ""
    normalized: str = ""
    extraction_confidence: float = 0.0
    resolution_confidence: float = 0.0
    resolution_tier: str = "unresolved"


@dataclass
class ResourceField:
    """What is affected."""
    raw: str = ""
    canonical_key: str = ""
    extraction_confidence: float = 0.0
    resolution_confidence: float = 0.0
    resolution_tier: str = "unresolved"


# ── Constraint operators ──────────────────────────────────────────────────────

VALID_CONSTRAINT_OPERATORS = frozenset({
    "equals",
    "not_equals",
    "greater_than",
    "greater_than_or_equal",
    "less_than",
    "less_than_or_equal",
    "contains",
    "not_contains",
    "is_true",
    "is_false",
})


@dataclass
class ControlConstraint:
    """A structured constraint extracted from regulatory text.

    Replaces the simpler ConditionItem. Captures numeric thresholds,
    boolean requirements, qualitative constraints, and their source text
    for audit traceability.
    """
    field: str = ""                        # e.g. "min_directors"
    operator: str = "equals"               # from VALID_CONSTRAINT_OPERATORS
    value: str = ""                        # e.g. "3", "independent_director", "true"
    unit: Optional[str] = None             # e.g. "years", "months", "days"
    description: Optional[str] = None      # human-readable summary
    source_text: Optional[str] = None      # exact phrase from the document


@dataclass
class TemporalConstraint:
    """Temporal requirements for the control."""
    frequency: Optional[str] = None        # e.g., "every_6_months", "every_12_months"
    deadline: Optional[str] = None         # e.g., "within_6_hours", "immediately"
    retention: Optional[str] = None        # e.g., "minimum_5_years"
    cooling_period: Optional[str] = None   # e.g., "12_hours"


@dataclass
class EvidenceRequirement:
    """What proof is needed for compliance."""
    required: bool = True
    artifact_type: Optional[str] = None    # e.g., "va_report", "audit_trail_report"


@dataclass
class SourceAttribution:
    """Link back to the source regulatory document."""
    document_id: str = ""                  # e.g., "RBI/2023-24/107"
    section: str = ""                      # e.g., "26"
    effective_date: Optional[str] = None   # ISO 8601


@dataclass
class ConfidenceScores:
    """Aggregate confidence scores (combines extraction + resolution)."""
    overall: float = 0.0
    subject_extraction: float = 0.0
    subject_resolution: float = 0.0
    action_extraction: float = 0.0
    action_resolution: float = 0.0
    resource_extraction: float = 0.0
    resource_resolution: float = 0.0
    temporal: float = 0.0


@dataclass
class ReviewMetadata:
    """Human review tracking."""
    required: bool = False
    reason: Optional[str] = None
    reviewer: Optional[str] = None
    decision: Optional[str] = None
    timestamp: Optional[str] = None
    correction: Optional[dict] = None


@dataclass
class ControlIR:
    """
    Intermediate Representation for a regulatory control extracted from
    RBI/DPSS rule text.
    """
    # Identity
    id: str = ""
    version: str = "1.0.0"
    status: str = "draft"

    # Core fields
    rule_type: str = "obligation"
    effect: str = "required"

    # Entities
    subject: SubjectField = field(default_factory=SubjectField)
    action: ActionField = field(default_factory=ActionField)
    resource: ResourceField = field(default_factory=ResourceField)

    # Constraints (replaces old conditions — superset with unit, description, source_text)
    constraints: list[ControlConstraint] = field(default_factory=list)

    # Temporal
    temporal: TemporalConstraint = field(default_factory=TemporalConstraint)

    # Evidence
    evidence: EvidenceRequirement = field(default_factory=EvidenceRequirement)

    # Source
    source: SourceAttribution = field(default_factory=SourceAttribution)

    # Confidence
    confidence: ConfidenceScores = field(default_factory=ConfidenceScores)

    # Review
    review: ReviewMetadata = field(default_factory=ReviewMetadata)

    # Derivation
    extraction_run: str = ""
    extractor_version: str = EXTRACTOR_VERSION

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dictionary."""
        return {
            "id": self.id,
            "version": self.version,
            "status": self.status,
            "rule_type": self.rule_type,
            "effect": self.effect,
            "subject": {
                "raw": self.subject.raw,
                "canonical_key": self.subject.canonical_key,
                "extraction_confidence": self.subject.extraction_confidence,
                "resolution_confidence": self.subject.resolution_confidence,
                "resolution_tier": self.subject.resolution_tier,
            },
            "action": {
                "raw": self.action.raw,
                "normalized": self.action.normalized,
                "extraction_confidence": self.action.extraction_confidence,
                "resolution_confidence": self.action.resolution_confidence,
                "resolution_tier": self.action.resolution_tier,
            },
            "resource": {
                "raw": self.resource.raw,
                "canonical_key": self.resource.canonical_key,
                "extraction_confidence": self.resource.extraction_confidence,
                "resolution_confidence": self.resource.resolution_confidence,
                "resolution_tier": self.resource.resolution_tier,
            },
            "constraints": [
                {
                    "field": c.field,
                    "operator": c.operator,
                    "value": c.value,
                    "unit": c.unit,
                    "description": c.description,
                    "source_text": c.source_text,
                }
                for c in self.constraints
            ],
            "temporal": {
                "frequency": self.temporal.frequency,
                "deadline": self.temporal.deadline,
                "retention": self.temporal.retention,
                "cooling_period": self.temporal.cooling_period,
            },
            "evidence": {
                "required": self.evidence.required,
                "artifact_type": self.evidence.artifact_type,
            },
            "source": {
                "document_id": self.source.document_id,
                "section": self.source.section,
                "effective_date": self.source.effective_date,
            },
            "confidence": {
                "overall": self.confidence.overall,
                "subject_extraction": self.confidence.subject_extraction,
                "subject_resolution": self.confidence.subject_resolution,
                "action_extraction": self.confidence.action_extraction,
                "action_resolution": self.confidence.action_resolution,
                "resource_extraction": self.confidence.resource_extraction,
                "resource_resolution": self.confidence.resource_resolution,
                "temporal": self.confidence.temporal,
            },
            "review": {
                "required": self.review.required,
                "reason": self.review.reason,
                "reviewer": self.review.reviewer,
                "decision": self.review.decision,
                "timestamp": self.review.timestamp,
                "correction": self.review.correction,
            },
            "extraction_run": self.extraction_run,
            "extractor_version": self.extractor_version,
        }


def generate_control_id() -> str:
    """Generate a unique control ID."""
    return str(uuid.uuid4())


def generate_run_id() -> str:
    """Generate a unique extraction run ID."""
    now = datetime.now(timezone.utc)
    return f"reg_run_{now.strftime('%Y_%m_%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
