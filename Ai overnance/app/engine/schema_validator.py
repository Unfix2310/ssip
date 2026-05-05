from typing import Any

from jsonschema import SchemaError, ValidationError, validate

from app.models import RuleAction


def validate_schema(output_payload: dict[str, Any], schema: dict[str, Any] | None) -> tuple[bool, list[RuleAction], str | None]:
    if schema is None:
        return True, [], None
    try:
        validate(instance=output_payload, schema=schema)
        return True, [RuleAction(rule="schema.validation", action="allow", detail="Schema validated")], None
    except (ValidationError, SchemaError) as exc:
        return (
            False,
            [RuleAction(rule="schema.validation", action="block", detail=str(exc.message))],
            "Schema validation failed",
        )
