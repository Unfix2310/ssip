from typing import Any

from app.models import NumericAssertion, RuleAction


def validate_numeric_rules(
    output_payload: dict[str, Any],
    assertions: list[NumericAssertion],
    policy: dict[str, Any],
) -> tuple[bool, list[RuleAction], str | None]:
    if not assertions:
        return True, [], None

    actions: list[RuleAction] = []
    rate_cards = policy.get("numeric_rules", {})

    for assertion in assertions:
        actual = output_payload.get(assertion.field)
        if actual is None:
            actions.append(
                RuleAction(
                    rule=f"numeric.{assertion.rule}",
                    action="block",
                    detail=f"Missing field: {assertion.field}",
                )
            )
            return False, actions, f"Missing numeric field: {assertion.field}"

        expected_group = rate_cards.get(assertion.rule, {})
        expected_value = expected_group.get(assertion.product) if assertion.product else expected_group.get("default")
        if expected_value is None:
            actions.append(
                RuleAction(
                    rule=f"numeric.{assertion.rule}",
                    action="block",
                    detail=f"No policy value for product: {assertion.product}",
                )
            )
            return False, actions, f"Missing policy numeric value for rule {assertion.rule}"

        try:
            actual_f = float(actual)
        except (TypeError, ValueError):
            actions.append(
                RuleAction(
                    rule=f"numeric.{assertion.rule}",
                    action="block",
                    detail=f"Field {assertion.field} is not numeric",
                )
            )
            return False, actions, f"Field {assertion.field} is not numeric"

        tolerance = float(policy.get("numeric_tolerance", 0.0))
        if abs(actual_f - float(expected_value)) > tolerance:
            actions.append(
                RuleAction(
                    rule=f"numeric.{assertion.rule}",
                    action="block",
                    detail=f"Expected {expected_value}, got {actual_f}",
                )
            )
            return False, actions, f"Numeric assertion failed for {assertion.field}"

        actions.append(
            RuleAction(
                rule=f"numeric.{assertion.rule}",
                action="allow",
                detail=f"Expected {expected_value}, got {actual_f}",
            )
        )

    return True, actions, None
