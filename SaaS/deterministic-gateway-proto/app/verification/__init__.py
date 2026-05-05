"""
Verification Package: multi-stage policy verification.

Orchestrates:
  1. Cedar CLI / structural lint (parse validation)
  2. Conflict detection (cross-policy contradictions)
  3. Simulation (scenario-based testing)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from ..exceptions import VerificationError

logger = logging.getLogger(__name__)


@dataclass
class ConflictInfo:
    """Description of a detected policy conflict."""
    type: str               # "contradiction", "shadow", "overlap"
    policy_a_id: str
    policy_b_id: str
    description: str
    severity: str = "warning"  # "warning", "error"


@dataclass
class SimulationResult:
    """Result of a single simulation scenario."""
    scenario_name: str
    principal: str
    action: str
    resource: str
    expected: str           # "allow", "deny"
    actual: str             # "allow", "deny", "no_match"
    passed: bool


@dataclass
class VerificationResult:
    """Aggregated result from all verification stages."""
    passed: bool
    parse_ok: bool = True
    parse_errors: list[str] = field(default_factory=list)
    conflicts: list[ConflictInfo] = field(default_factory=list)
    simulation_results: list[SimulationResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "parse_ok": self.parse_ok,
            "parse_errors": self.parse_errors,
            "conflicts": [
                {
                    "type": c.type,
                    "policy_a_id": c.policy_a_id,
                    "policy_b_id": c.policy_b_id,
                    "description": c.description,
                    "severity": c.severity,
                }
                for c in self.conflicts
            ],
            "simulation_results": [
                {
                    "scenario_name": s.scenario_name,
                    "expected": s.expected,
                    "actual": s.actual,
                    "passed": s.passed,
                }
                for s in self.simulation_results
            ],
            "warnings": self.warnings,
        }


async def verify_full(
    cedar_policy: str,
    policy_id: str = "",
    compiled_policies: Optional[dict[str, str]] = None,
    check_conflicts: bool = True,
    run_simulations: bool = True,
) -> VerificationResult:
    """
    Run the full verification pipeline.

    Args:
        cedar_policy:       The Cedar policy string to verify.
        policy_id:          ID of the policy being verified.
        compiled_policies:  All compiled formats (for format-specific checks).
        check_conflicts:    Whether to run conflict detection.
        run_simulations:    Whether to run scenario simulations.

    Returns:
        VerificationResult with aggregated results from all stages.
    """
    result = VerificationResult(passed=True)

    # ── Stage 1: Parse validation (Cedar) ─────────────────────────────────────
    from .cedar_verifier import verify_cedar_parse
    try:
        verify_cedar_parse(cedar_policy)
        result.parse_ok = True
        logger.info("[Verification] Stage 1: Cedar parse — PASSED")
    except VerificationError as exc:
        result.parse_ok = False
        result.passed = False
        result.parse_errors.append(str(exc))
        logger.warning("[Verification] Stage 1: Cedar parse — FAILED: %s", exc)
        # Don't return early — still useful to check conflicts

    # ── Stage 2: Conflict detection ───────────────────────────────────────────
    if check_conflicts:
        from .conflict import detect_conflicts
        try:
            conflicts = await detect_conflicts(policy_id, cedar_policy)
            result.conflicts = conflicts
            if any(c.severity == "error" for c in conflicts):
                result.passed = False
            if conflicts:
                logger.warning(
                    "[Verification] Stage 2: Conflict detection — %d conflicts found",
                    len(conflicts),
                )
            else:
                logger.info("[Verification] Stage 2: Conflict detection — PASSED (no conflicts)")
        except Exception as exc:
            result.warnings.append(f"Conflict detection error: {exc}")
            logger.warning("[Verification] Stage 2: Conflict detection — ERROR: %s", exc)

    # ── Stage 3: Simulation ───────────────────────────────────────────────────
    if run_simulations:
        from .simulation import run_simulations as _run_sims
        try:
            sim_results = await _run_sims(policy_id, cedar_policy)
            result.simulation_results = sim_results
            failed_sims = [s for s in sim_results if not s.passed]
            if failed_sims:
                result.warnings.append(f"{len(failed_sims)} simulation(s) failed")
                logger.warning(
                    "[Verification] Stage 3: Simulation — %d/%d passed",
                    len(sim_results) - len(failed_sims), len(sim_results),
                )
            else:
                logger.info("[Verification] Stage 3: Simulation — PASSED (%d scenarios)", len(sim_results))
        except Exception as exc:
            result.warnings.append(f"Simulation error: {exc}")
            logger.warning("[Verification] Stage 3: Simulation — ERROR: %s", exc)

    logger.info(
        "[Verification] Final result: passed=%s parse_ok=%s conflicts=%d simulations=%d warnings=%d",
        result.passed, result.parse_ok, len(result.conflicts),
        len(result.simulation_results), len(result.warnings),
    )

    return result
