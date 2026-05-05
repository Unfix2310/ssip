"""
Pipeline Orchestrator.

Full 8-stage pipeline:
  1. LLM extraction      → raw IR dict (extended fields)
  2. Pre-normalization   → resolve principal/resource intents to canonical keys
  3. IR validation       → runs on canonical strings, produces PolicyIR
  4. Entity resolution   → catalog lookup (guaranteed hit after normalization)
  5. Confidence routing  → auto-approve / review / reject
  6. Multi-format compilation → Cedar + OPA + YAML + XACML
  7. Verification        → parse + conflict detection + simulation
  8. Persistence         → save to DB with versioning

Retry policy:
  - Retryable:     schema/action/LLM/verification errors → re-prompt with context
  - Non-retryable: EntityResolutionError (genuine unknown) → fail immediately
  - Routing:       REJECTED → fail immediately; REVIEW_REQUIRED → proceed but flag
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Optional

from .catalog import get_principal, get_resource, principal_keys, resource_keys
from .compilers import ResolvedEntities as CompilerEntities
from .compilers import compile_all
from .exceptions import (
    EntityResolutionError,
    InvalidActionError,
    LLMExtractionError,
    MaxRetriesExceededError,
    PolicyCompilerError,
    RoutingError,
    SchemaValidationError,
    VerificationError,
)
from .llm import extract_policy_ir
from .normalizer import ResolutionTier, normalize_entity
from .resolver import ResolvedEntities
from .router import RoutingDecision, route_policy
from .schema import ConfidenceScores, PolicyIR, validate_ir

logger = logging.getLogger(__name__)

MAX_RETRIES = 2

_RETRYABLE     = (InvalidActionError, SchemaValidationError, VerificationError, LLMExtractionError)
_NON_RETRYABLE = (EntityResolutionError, RoutingError)


@dataclass
class PipelineResult:
    policy_id: str
    policy: str                      # Primary format (Cedar)
    compiled_policies: dict[str, str]  # All formats
    resolved_entities: dict
    ir: dict                         # Full IR as dict
    routing: dict                    # Routing decision details
    verification: dict               # Verification results
    attempts: int


def _pre_normalize(raw_ir: dict) -> dict:
    """
    Stage 2: resolve principal_intent and resource_intent to canonical catalog
    keys BEFORE the IR validator sees them.
    """
    ir = dict(raw_ir)

    # Normalize principal
    raw_principal = str(ir.get("principal_intent", "")).strip().lower()
    canonical_principal, p_tier, p_score = normalize_entity(
        raw=raw_principal,
        entity_type="principal",
        candidates=principal_keys(),
    )
    ir["principal_intent"] = canonical_principal
    ir["_principal_raw"]   = raw_principal
    ir["_principal_tier"]  = p_tier
    ir["_principal_score"] = round(p_score, 3)

    # Normalize resource
    raw_resource = str(ir.get("resource_intent", "")).strip().lower()
    canonical_resource, r_tier, r_score = normalize_entity(
        raw=raw_resource,
        entity_type="resource",
        candidates=resource_keys(),
    )
    ir["resource_intent"] = canonical_resource
    ir["_resource_raw"]   = raw_resource
    ir["_resource_tier"]  = r_tier
    ir["_resource_score"] = round(r_score, 3)

    logger.info(
        "[Pipeline] Pre-norm: principal %r → %r [%s %.2f]  resource %r → %r [%s %.2f]",
        raw_principal, canonical_principal, p_tier, p_score,
        raw_resource,  canonical_resource,  r_tier, r_score,
    )
    return ir


def run_pipeline(input_text: str, output_formats: Optional[list[str]] = None) -> PipelineResult:
    """
    Execute the full NL → multi-format policy pipeline with up to MAX_RETRIES retries.

    Stage order:
      LLM extraction → pre-normalization → IR validation → entity resolution
      → confidence routing → multi-format compilation → verification → persistence

    EntityResolutionError and RoutingError (rejected) bypass retry and propagate immediately.
    """
    if output_formats is None:
        output_formats = ["cedar", "opa", "yaml", "xacml"]

    error_context: Optional[str] = None
    last_error: Optional[Exception] = None

    for attempt in range(1, MAX_RETRIES + 2):
        logger.info("━━━ Pipeline attempt %d / %d ━━━", attempt, MAX_RETRIES + 1)

        try:
            # ── Stage 1: LLM extraction ───────────────────────────────────────
            raw_ir = extract_policy_ir(input_text, error_context=error_context)

            # ── Stage 2: Pre-normalization (entity resolution) ────────────────
            normalized_ir = _pre_normalize(raw_ir)

            # ── Stage 3: IR validation ────────────────────────────────────────
            ir: PolicyIR = validate_ir(normalized_ir)

            # ── Stage 4: Build resolved entities ──────────────────────────────
            principal_arn = get_principal(ir.principal_intent)
            resource_arn  = get_resource(ir.resource_intent)

            p_tier  = normalized_ir["_principal_tier"]
            r_tier  = normalized_ir["_resource_tier"]
            p_score = normalized_ir["_principal_score"]
            r_score = normalized_ir["_resource_score"]
            p_raw   = normalized_ir["_principal_raw"]
            r_raw   = normalized_ir["_resource_raw"]

            resolved = ResolvedEntities(
                principal       = principal_arn,
                resource        = resource_arn,
                action          = ir.action_intent,
                effect          = ir.effect,
                principal_tier  = p_tier,
                resource_tier   = r_tier,
                principal_raw   = p_raw,
                resource_raw    = r_raw,
                principal_score = p_score,
                resource_score  = r_score,
            )

            # Update IR confidence scores
            ir.confidence = ConfidenceScores(
                overall=(p_score + r_score) / 2.0,
                principal=p_score,
                resource=r_score,
                action=1.0,
            )

            # ── Stage 5: Confidence routing ───────────────────────────────────
            routing_result = route_policy(
                principal_score=p_score,
                resource_score=r_score,
                principal_tier=p_tier,
                resource_tier=r_tier,
                effect=ir.effect,
            )

            if routing_result.decision == RoutingDecision.REJECTED:
                raise RoutingError(
                    f"Policy rejected by confidence router: {routing_result.reason}"
                )

            # Update IR review metadata based on routing
            if routing_result.decision == RoutingDecision.REVIEW_REQUIRED:
                ir.status = "pending_review"
                ir.review.required = True
                ir.review.reason = routing_result.reason
            else:
                ir.status = "approved"

            # ── Stage 6: Multi-format compilation ─────────────────────────────
            compiler_entities = CompilerEntities(
                principal=resolved.principal,
                resource=resolved.resource,
                action=resolved.action,
                effect=resolved.effect,
                principal_tier=resolved.principal_tier,
                resource_tier=resolved.resource_tier,
                principal_raw=resolved.principal_raw,
                resource_raw=resolved.resource_raw,
                principal_score=resolved.principal_score,
                resource_score=resolved.resource_score,
            )

            compiled_policies = compile_all(
                compiler_entities,
                conditions=ir.conditions,
                formats=output_formats,
            )

            # Primary policy is Cedar
            cedar_policy = compiled_policies.get("cedar", "")

            # ── Stage 7: Verification (Cedar parse check) ────────────────────
            # Use sync verification for the Cedar parse check
            from .verification.cedar_verifier import verify_cedar_parse
            verify_cedar_parse(cedar_policy)

            # ── Stage 8: Build result ─────────────────────────────────────────
            ir_dict = ir.to_dict()

            # Enrich IR dict with resolution details
            ir_dict["principal"]["raw"] = p_raw
            ir_dict["principal"]["canonical_key"] = ir.principal_intent
            ir_dict["principal"]["arn"] = principal_arn
            ir_dict["principal"]["confidence"] = p_score
            ir_dict["principal"]["resolution_tier"] = p_tier

            ir_dict["resource"]["raw"] = r_raw
            ir_dict["resource"]["canonical_key"] = ir.resource_intent
            ir_dict["resource"]["arn"] = resource_arn
            ir_dict["resource"]["confidence"] = r_score
            ir_dict["resource"]["resolution_tier"] = r_tier

            ir_dict["action"]["raw"] = normalized_ir.get("action_intent", ir.action_intent)
            ir_dict["action"]["normalized"] = ir.action_intent

            logger.info("[Pipeline] Success after %d attempt(s). Routing: %s", attempt, routing_result.decision.value)

            return PipelineResult(
                policy_id=ir.id,
                policy=cedar_policy,
                compiled_policies=compiled_policies,
                resolved_entities={
                    "principal":       resolved.principal,
                    "action":          resolved.action,
                    "resource":        resolved.resource,
                    "effect":          resolved.effect,
                    "principal_raw":   p_raw,
                    "principal_tier":  p_tier,
                    "principal_score": p_score,
                    "resource_raw":    r_raw,
                    "resource_tier":   r_tier,
                    "resource_score":  r_score,
                },
                ir=ir_dict,
                routing={
                    "decision": routing_result.decision.value,
                    "overall_confidence": routing_result.overall_confidence,
                    "principal_confidence": routing_result.principal_confidence,
                    "resource_confidence": routing_result.resource_confidence,
                    "reason": routing_result.reason,
                    "flags": routing_result.flags,
                },
                verification={
                    "cedar_parse": True,
                    "conflicts_checked": False,  # Async — done in main.py
                    "simulations_run": False,     # Async — done in main.py
                },
                attempts=attempt,
            )

        except _NON_RETRYABLE as exc:
            logger.error("[Pipeline] Non-retryable: %s", exc)
            raise

        except _RETRYABLE as exc:
            last_error    = exc
            error_context = str(exc)
            logger.warning(
                "[Pipeline] Retryable error attempt %d [%s]: %s",
                attempt, type(exc).__name__, exc,
            )
            if attempt > MAX_RETRIES:
                break

        except PolicyCompilerError as exc:
            logger.error("[Pipeline] Unexpected pipeline error: %s", exc)
            raise

    raise MaxRetriesExceededError(
        f"Pipeline failed after {MAX_RETRIES + 1} attempts. "
        f"Last: {type(last_error).__name__}: {last_error}"
    )
