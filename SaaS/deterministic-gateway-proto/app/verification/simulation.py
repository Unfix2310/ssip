"""
Policy Simulation: test policies against predefined scenarios.

Scenarios define an access request (principal, action, resource) and the
expected outcome (allow/deny). The simulation engine evaluates each scenario
against the policy and reports pass/fail.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from . import SimulationResult

logger = logging.getLogger(__name__)

# ── Predefined test scenarios ──────────────────────────────────────────────────
# These scenarios represent common access patterns to validate against.

DEFAULT_SCENARIOS = [
    {
        "name": "developers_read_logs",
        "principal": 'Role::"arn:aws:iam::2222:role/DevTeam"',
        "action": "read",
        "resource": 'Bucket::"arn:aws:s3:::app-logs-01"',
        "expected": "allow",
    },
    {
        "name": "finance_write_payroll",
        "principal": 'Role::"arn:aws:iam::1111:role/Finance"',
        "action": "write",
        "resource": 'Bucket::"arn:aws:s3:::corp-payroll-prod"',
        "expected": "allow",
    },
    {
        "name": "developers_no_write_payroll",
        "principal": 'Role::"arn:aws:iam::2222:role/DevTeam"',
        "action": "write",
        "resource": 'Bucket::"arn:aws:s3:::corp-payroll-prod"',
        "expected": "deny",
    },
    {
        "name": "admin_manage_config",
        "principal": 'Role::"arn:aws:iam::3333:role/Admins"',
        "action": "admin",
        "resource": 'Bucket::"arn:aws:s3:::corp-config-store"',
        "expected": "allow",
    },
]


def _evaluate_scenario(
    cedar_policy: str,
    scenario: dict,
) -> SimulationResult:
    """
    Evaluate a single scenario against a Cedar policy.

    Simple pattern matching — checks if the policy would match the scenario's
    principal/action/resource and what effect it would produce.
    """
    name = scenario["name"]
    s_principal = scenario["principal"]
    s_action = scenario["action"]
    s_resource = scenario["resource"]
    expected = scenario["expected"]

    # Parse the Cedar policy
    is_permit = "permit(" in cedar_policy
    is_deny = "forbid(" in cedar_policy

    # Check if the policy matches this scenario
    principal_match = s_principal in cedar_policy
    action_match = f'Action::"{s_action}"' in cedar_policy
    resource_match = s_resource in cedar_policy

    all_match = principal_match and action_match and resource_match

    if all_match:
        actual = "allow" if is_permit else "deny"
    else:
        actual = "no_match"

    # Determine pass/fail
    if actual == "no_match":
        # No match — policy doesn't apply to this scenario
        # If expected is "deny", a non-matching permit policy is fine (deny-by-default)
        passed = expected == "deny" if is_permit else expected == "allow"
    else:
        passed = actual == expected

    return SimulationResult(
        scenario_name=name,
        principal=s_principal,
        action=s_action,
        resource=s_resource,
        expected=expected,
        actual=actual,
        passed=passed,
    )


async def run_simulations(
    policy_id: str,
    cedar_policy: str,
    scenarios: Optional[list[dict]] = None,
) -> list[SimulationResult]:
    """
    Run scenario-based simulations against a policy.

    Args:
        policy_id:    ID of the policy being tested.
        cedar_policy: The Cedar policy string to test.
        scenarios:    Optional list of custom scenarios. Uses defaults if None.

    Returns:
        List of SimulationResult objects.
    """
    test_scenarios = scenarios or DEFAULT_SCENARIOS
    results: list[SimulationResult] = []

    for scenario in test_scenarios:
        result = _evaluate_scenario(cedar_policy, scenario)
        results.append(result)
        logger.info(
            "[Simulation] %s: expected=%s actual=%s passed=%s",
            result.scenario_name, result.expected, result.actual, result.passed,
        )

    passed_count = sum(1 for r in results if r.passed)
    logger.info(
        "[Simulation] Policy %s: %d/%d scenarios passed.",
        policy_id[:8], passed_count, len(results),
    )

    return results
