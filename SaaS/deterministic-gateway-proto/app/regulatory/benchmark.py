"""
Benchmark Runner: tests all POC rules against the regulatory pipeline.

Loads rules from data/rbi_poc_rules.yaml, runs each through the pipeline,
and compares actual output against expected values.

Metrics:
  - extraction accuracy (rule_type, action, resource match)
  - temporal extraction accuracy
  - catalog resolution accuracy
  - review routing rate
  - compile success rate
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
POC_RULES_PATH = os.path.join(DATA_DIR, "rbi_poc_rules.yaml")


@dataclass
class RuleResult:
    """Result of benchmarking a single rule."""
    rule_id: str
    document_id: str
    section: str
    input_text: str
    success: bool
    error: Optional[str] = None

    # Match results
    rule_type_match: bool = False
    action_match: bool = False
    resource_match: bool = False
    effect_match: bool = False
    temporal_match: bool = False

    # Extracted values
    extracted_rule_type: str = ""
    extracted_action: str = ""
    extracted_resource: str = ""
    extracted_effect: str = ""
    extracted_temporal: dict = field(default_factory=dict)

    # Expected values
    expected_rule_type: str = ""
    expected_action: str = ""
    expected_resource: str = ""
    expected_effect: str = ""
    expected_temporal: dict = field(default_factory=dict)

    # Routing
    routing_decision: str = ""
    confidence: float = 0.0

    # Compiled output
    compiled_yaml: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "document_id": self.document_id,
            "section": self.section,
            "success": self.success,
            "error": self.error,
            "matches": {
                "rule_type": self.rule_type_match,
                "action": self.action_match,
                "resource": self.resource_match,
                "effect": self.effect_match,
                "temporal": self.temporal_match,
            },
            "extracted": {
                "rule_type": self.extracted_rule_type,
                "action": self.extracted_action,
                "resource": self.extracted_resource,
                "effect": self.extracted_effect,
                "temporal": self.extracted_temporal,
            },
            "expected": {
                "rule_type": self.expected_rule_type,
                "action": self.expected_action,
                "resource": self.expected_resource,
                "effect": self.expected_effect,
                "temporal": self.expected_temporal,
            },
            "routing_decision": self.routing_decision,
            "confidence": self.confidence,
        }


@dataclass
class BenchmarkSummary:
    """Aggregate benchmark metrics."""
    total_rules: int = 0
    successful_extractions: int = 0
    failed_extractions: int = 0

    rule_type_matches: int = 0
    action_matches: int = 0
    resource_matches: int = 0
    effect_matches: int = 0
    temporal_matches: int = 0

    compile_successes: int = 0
    review_routed: int = 0
    auto_approved: int = 0
    catalog_enrichment: int = 0
    rejected: int = 0

    results: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        total = max(self.total_rules, 1)
        success = max(self.successful_extractions, 1)
        return {
            "total_rules": self.total_rules,
            "successful_extractions": self.successful_extractions,
            "failed_extractions": self.failed_extractions,
            "accuracy": {
                "extraction_rate": round(self.successful_extractions / total * 100, 1),
                "rule_type_accuracy": round(self.rule_type_matches / success * 100, 1),
                "action_accuracy": round(self.action_matches / success * 100, 1),
                "resource_accuracy": round(self.resource_matches / success * 100, 1),
                "effect_accuracy": round(self.effect_matches / success * 100, 1),
                "temporal_accuracy": round(self.temporal_matches / success * 100, 1),
                "compile_success_rate": round(self.compile_successes / success * 100, 1),
            },
            "routing": {
                "auto_approved": self.auto_approved,
                "review_required": self.review_routed,
                "catalog_enrichment": self.catalog_enrichment,
                "rejected": self.rejected,
                "review_rate": round(
                    (self.review_routed + self.catalog_enrichment) / total * 100, 1
                ),
            },
            "results": self.results,
        }


def _check_temporal_match(extracted: dict, expected: dict) -> bool:
    """Check if extracted temporal fields match expected values."""
    for key in ["frequency", "deadline", "retention", "cooling_period"]:
        exp_val = expected.get(key)
        ext_val = extracted.get(key)
        if exp_val is not None and ext_val != exp_val:
            return False
        if exp_val is None and ext_val is not None:
            # Extra temporal field — not a failure, just unexpected
            pass
    return True


def load_poc_rules() -> list[dict]:
    """Load the POC rules from the YAML file."""
    if not os.path.exists(POC_RULES_PATH):
        raise FileNotFoundError(f"POC rules file not found: {POC_RULES_PATH}")

    with open(POC_RULES_PATH, "r") as f:
        data = yaml.safe_load(f)

    return data.get("rules", [])


def run_benchmark() -> BenchmarkSummary:
    """
    Run all POC rules through the regulatory pipeline and compare results.

    Returns:
        BenchmarkSummary with per-rule results and aggregate metrics.
    """
    from .pipeline import run_regulatory_pipeline

    rules = load_poc_rules()
    summary = BenchmarkSummary(total_rules=len(rules))

    for rule in rules:
        rule_id = rule.get("id", "unknown")
        doc_id = rule.get("document_id", "")
        section = rule.get("section", "")
        text = rule.get("text", "")
        expected = rule.get("expected", {})

        logger.info("━━━ Benchmark: %s (§%s) ━━━", rule_id, section)

        result = RuleResult(
            rule_id=rule_id,
            document_id=doc_id,
            section=section,
            input_text=text,
            success=False,
            expected_rule_type=expected.get("rule_type", ""),
            expected_action=expected.get("action", ""),
            expected_resource=expected.get("resource", ""),
            expected_effect=expected.get("effect", "required"),
            expected_temporal=expected.get("temporal", {}),
        )

        try:
            pipeline_result = run_regulatory_pipeline(
                rule_text=text,
                document_id=doc_id,
                section=section,
            )

            result.success = True
            summary.successful_extractions += 1

            ir = pipeline_result.ir

            # Extract values for comparison
            result.extracted_rule_type = ir.get("rule_type", "")
            result.extracted_action = ir.get("action", {}).get("normalized", "")
            result.extracted_resource = ir.get("resource", {}).get("canonical_key", "")
            result.extracted_effect = ir.get("effect", "")
            result.extracted_temporal = ir.get("temporal", {})

            # Check matches
            result.rule_type_match = result.extracted_rule_type == result.expected_rule_type
            result.action_match = result.extracted_action == result.expected_action
            result.resource_match = result.extracted_resource == result.expected_resource
            result.effect_match = result.extracted_effect == result.expected_effect
            result.temporal_match = _check_temporal_match(
                result.extracted_temporal, result.expected_temporal
            )

            if result.rule_type_match:
                summary.rule_type_matches += 1
            if result.action_match:
                summary.action_matches += 1
            if result.resource_match:
                summary.resource_matches += 1
            if result.effect_match:
                summary.effect_matches += 1
            if result.temporal_match:
                summary.temporal_matches += 1

            # Routing
            result.routing_decision = pipeline_result.routing.get("decision", "")
            result.confidence = pipeline_result.routing.get("overall_confidence", 0.0)

            if result.routing_decision == "auto_approve":
                summary.auto_approved += 1
            elif result.routing_decision == "review_required":
                summary.review_routed += 1
            elif result.routing_decision == "catalog_enrichment":
                summary.catalog_enrichment += 1
            elif result.routing_decision == "rejected":
                summary.rejected += 1

            # Compilation
            if pipeline_result.compiled_yaml:
                summary.compile_successes += 1
                result.compiled_yaml = pipeline_result.compiled_yaml

            logger.info(
                "[Benchmark] %s: rule_type=%s action=%s resource=%s temporal=%s routing=%s",
                rule_id,
                "✓" if result.rule_type_match else "✗",
                "✓" if result.action_match else "✗",
                "✓" if result.resource_match else "✗",
                "✓" if result.temporal_match else "✗",
                result.routing_decision,
            )

        except Exception as exc:
            result.error = str(exc)
            summary.failed_extractions += 1
            logger.error("[Benchmark] %s FAILED: %s", rule_id, exc)

        summary.results.append(result.to_dict())

    logger.info(
        "[Benchmark] COMPLETE: %d/%d extracted, action=%d/%d, temporal=%d/%d",
        summary.successful_extractions, summary.total_rules,
        summary.action_matches, summary.successful_extractions,
        summary.temporal_matches, summary.successful_extractions,
    )

    return summary
