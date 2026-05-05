"""
Schema: Intermediate Representation (IR) definition and validation.
No LLM output is trusted until it passes through here.

Extended IR includes: temporal constraints, derivation chain, scope,
confidence tracking, and review metadata.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .exceptions import InvalidActionError, SchemaValidationError

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

EXTRACTOR_VERSION = "v1.2.0"

ALLOWED_ACTIONS: frozenset[str] = frozenset({"read", "write", "admin"})
ALLOWED_EFFECTS: frozenset[str] = frozenset({"permit", "deny", "conditional"})
ALLOWED_STATUSES: frozenset[str] = frozenset({
    "pending_review", "approved", "rejected", "active", "draft",
})
ALLOWED_ENVIRONMENTS: frozenset[str] = frozenset({
    "production", "staging", "development", "testing",
})

REQUIRED_TOP_LEVEL = {"principal_intent", "action_intent", "resource_intent", "effect", "conditions"}
REQUIRED_CONDITIONS = {"network_restriction", "time_restriction"}

_ACTION_SYNONYMS: dict[str, str] = {
    "view": "read",
    "get": "read",
    "list": "read",
    "fetch": "read",
    "access": "read",
    "create": "write",
    "update": "write",
    "put": "write",
    "delete": "write",
    "modify": "write",
    "manage": "admin",
    "control": "admin",
    "administer": "admin",
}

# Effects that require human review
_REVIEW_REQUIRED_EFFECTS: frozenset[str] = frozenset({"deny", "conditional"})


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class Conditions:
    network_restriction: Optional[str] = None
    time_restriction: Optional[str] = None


@dataclass
class TemporalConstraint:
    """Temporal bounds for policy validity."""
    valid_from: Optional[str] = None     # ISO 8601 datetime
    valid_until: Optional[str] = None    # ISO 8601 datetime
    recurrence: Optional[str] = None     # Cron-like or descriptive (e.g., "weekdays 09:00-18:00")


@dataclass
class Derivation:
    """Audit trail linking IR back to source document and extraction run."""
    doc_id: Optional[str] = None
    clause_id: Optional[str] = None
    extraction_run: str = ""             # Auto-generated run ID
    extractor_version: str = EXTRACTOR_VERSION


@dataclass
class Scope:
    """Organizational scope for the policy."""
    org_unit: Optional[str] = None       # e.g., "engineering", "finance"
    environment: Optional[str] = None    # e.g., "production", "staging"
    region: Optional[str] = None         # e.g., "ap-south-1", "us-east-1"


@dataclass
class ConfidenceScores:
    """Per-field confidence scores from entity resolution."""
    overall: float = 0.0
    principal: float = 0.0
    resource: float = 0.0
    action: float = 1.0                  # Always 1.0 — action is deterministic


@dataclass
class ReviewMetadata:
    """Human review tracking."""
    required: bool = False
    reviewer: Optional[str] = None
    decision: Optional[str] = None       # approve, reject, modify
    timestamp: Optional[str] = None
    correction: Optional[dict] = None
    reason: Optional[str] = None         # Why review was triggered


@dataclass
class PolicyIR:
    """
    Extended Intermediate Representation of a security policy.
    
    Core fields are extracted by LLM + validated.
    Extended fields (temporal, derivation, scope) are populated
    from LLM extraction where available, with system defaults.
    """
    # Identity
    id: str = ""
    version: str = "1.0.0"
    status: str = "draft"

    # Core fields (from LLM extraction)
    principal_intent: str = ""
    action_intent: str = ""
    resource_intent: str = ""
    effect: str = "permit"
    conditions: Conditions = field(default_factory=Conditions)

    # Extended fields
    temporal: TemporalConstraint = field(default_factory=TemporalConstraint)
    derivation: Derivation = field(default_factory=Derivation)
    scope: Scope = field(default_factory=Scope)
    exceptions: list[str] = field(default_factory=list)

    # Populated after entity resolution (not from LLM)
    confidence: ConfidenceScores = field(default_factory=ConfidenceScores)
    review: ReviewMetadata = field(default_factory=ReviewMetadata)

    def requires_review(self) -> bool:
        """Check if this IR needs human review (effect-based or confidence-based)."""
        return self.effect in _REVIEW_REQUIRED_EFFECTS or self.review.required

    def to_dict(self) -> dict[str, Any]:
        """Serialize IR to a full JSON-compatible dictionary."""
        return {
            "id": self.id,
            "version": self.version,
            "status": self.status,
            "effect": self.effect,
            "principal": {
                "intent": self.principal_intent,
            },
            "action": {
                "intent": self.action_intent,
            },
            "resource": {
                "intent": self.resource_intent,
            },
            "conditions": {
                "network_restriction": self.conditions.network_restriction,
                "time_restriction": self.conditions.time_restriction,
            },
            "temporal": {
                "valid_from": self.temporal.valid_from,
                "valid_until": self.temporal.valid_until,
                "recurrence": self.temporal.recurrence,
            },
            "derivation": {
                "doc_id": self.derivation.doc_id,
                "clause_id": self.derivation.clause_id,
                "extraction_run": self.derivation.extraction_run,
                "extractor_version": self.derivation.extractor_version,
            },
            "scope": {
                "org_unit": self.scope.org_unit,
                "environment": self.scope.environment,
                "region": self.scope.region,
            },
            "exceptions": self.exceptions,
            "confidence": {
                "overall": self.confidence.overall,
                "principal": self.confidence.principal,
                "resource": self.confidence.resource,
                "action": self.confidence.action,
            },
            "review": {
                "required": self.review.required,
                "reviewer": self.review.reviewer,
                "decision": self.review.decision,
                "timestamp": self.review.timestamp,
                "correction": self.review.correction,
                "reason": self.review.reason,
            },
        }


# ── Validation ─────────────────────────────────────────────────────────────────

def _generate_run_id() -> str:
    """Generate a unique extraction run ID."""
    now = datetime.now(timezone.utc)
    return f"run_{now.strftime('%Y_%m_%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"


def _parse_conditions(cond: Any) -> Conditions:
    """Parse and validate condition fields."""
    if not isinstance(cond, dict):
        raise SchemaValidationError("'conditions' must be a JSON object.")

    missing_cond = REQUIRED_CONDITIONS - cond.keys()
    if missing_cond:
        raise SchemaValidationError(f"Missing condition fields: {missing_cond}")

    network_restriction = cond.get("network_restriction")
    time_restriction = cond.get("time_restriction")

    if network_restriction is not None and not isinstance(network_restriction, str):
        network_restriction = str(network_restriction)
    if time_restriction is not None and not isinstance(time_restriction, str):
        time_restriction = str(time_restriction)

    return Conditions(
        network_restriction=network_restriction,
        time_restriction=time_restriction,
    )


def _parse_temporal(raw: dict[str, Any]) -> TemporalConstraint:
    """Parse optional temporal constraint fields from raw IR."""
    temporal_raw = raw.get("temporal", {})
    if not isinstance(temporal_raw, dict):
        temporal_raw = {}

    return TemporalConstraint(
        valid_from=temporal_raw.get("valid_from"),
        valid_until=temporal_raw.get("valid_until"),
        recurrence=temporal_raw.get("recurrence"),
    )


def _parse_scope(raw: dict[str, Any]) -> Scope:
    """Parse optional scope fields from raw IR."""
    scope_raw = raw.get("scope", {})
    if not isinstance(scope_raw, dict):
        scope_raw = {}

    environment = scope_raw.get("environment")
    if environment and environment not in ALLOWED_ENVIRONMENTS:
        logger.warning("[Schema] Unknown environment %r, accepting anyway.", environment)

    return Scope(
        org_unit=scope_raw.get("org_unit"),
        environment=environment,
        region=scope_raw.get("region"),
    )


def _parse_derivation(raw: dict[str, Any], run_id: str) -> Derivation:
    """Parse optional derivation fields from raw IR."""
    deriv_raw = raw.get("derivation", {})
    if not isinstance(deriv_raw, dict):
        deriv_raw = {}

    return Derivation(
        doc_id=deriv_raw.get("doc_id"),
        clause_id=deriv_raw.get("clause_id"),
        extraction_run=run_id,
        extractor_version=EXTRACTOR_VERSION,
    )


def validate_ir(raw: dict[str, Any]) -> PolicyIR:
    """
    Validate raw LLM output against the extended IR schema.

    Raises:
        SchemaValidationError – missing/wrong fields or types.
        InvalidActionError    – action not in allowed set.
    """
    # ── 1. Top-level keys ─────────────────────────────────────────────────────
    missing_top = REQUIRED_TOP_LEVEL - raw.keys()
    if missing_top:
        raise SchemaValidationError(f"Missing top-level fields: {missing_top}")

    # ── 2. String fields ──────────────────────────────────────────────────────
    for f in ("principal_intent", "action_intent", "resource_intent", "effect"):
        if not isinstance(raw[f], str) or not raw[f].strip():
            raise SchemaValidationError(f"Field '{f}' must be a non-empty string.")

    # ── 3. Effect ─────────────────────────────────────────────────────────────
    effect = raw["effect"].strip().lower()
    if effect not in ALLOWED_EFFECTS:
        raise SchemaValidationError(f"Invalid effect '{effect}'. Allowed: {ALLOWED_EFFECTS}")

    # ── 4. Action ─────────────────────────────────────────────────────────────
    action = raw["action_intent"].strip().lower()
    action = _ACTION_SYNONYMS.get(action, action)
    if action not in ALLOWED_ACTIONS:
        raise InvalidActionError(
            f"Invalid action '{action}'. Allowed: {sorted(ALLOWED_ACTIONS)}"
        )

    # ── 5. Conditions ─────────────────────────────────────────────────────────
    conditions = _parse_conditions(raw.get("conditions"))

    # ── 6. Extended fields (all optional, with defaults) ──────────────────────
    run_id = _generate_run_id()
    temporal = _parse_temporal(raw)
    scope = _parse_scope(raw)
    derivation = _parse_derivation(raw, run_id)

    # ── 7. Exceptions (optional list of strings) ──────────────────────────────
    exceptions_raw = raw.get("exceptions", [])
    if not isinstance(exceptions_raw, list):
        exceptions_raw = []
    exceptions = [str(e) for e in exceptions_raw if e]

    # ── 8. Generate ID ────────────────────────────────────────────────────────
    ir_id = str(uuid.uuid4())

    # ── 9. Determine review requirement ───────────────────────────────────────
    review_required = effect in _REVIEW_REQUIRED_EFFECTS
    review_reason = None
    if review_required:
        review_reason = f"Effect '{effect}' requires human review"

    logger.info(
        "[Schema] IR validated. id=%s action=%s effect=%s principal=%s resource=%s review_required=%s",
        ir_id[:8], action, effect, raw["principal_intent"], raw["resource_intent"], review_required,
    )

    return PolicyIR(
        id=ir_id,
        version="1.0.0",
        status="pending_review" if review_required else "draft",
        principal_intent=raw["principal_intent"].strip().lower(),
        action_intent=action,
        resource_intent=raw["resource_intent"].strip().lower(),
        effect=effect,
        conditions=conditions,
        temporal=temporal,
        derivation=derivation,
        scope=scope,
        exceptions=exceptions,
        confidence=ConfidenceScores(),
        review=ReviewMetadata(
            required=review_required,
            reason=review_reason,
        ),
    )
