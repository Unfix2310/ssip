"""
OPA/Rego Compiler: converts ResolvedEntities → Open Policy Agent Rego policy.
Pure deterministic template. Zero LLM involvement.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from ..exceptions import PolicyCompilationError
from ..schema import Conditions
from . import PolicyCompiler, ResolvedEntities

logger = logging.getLogger(__name__)


def _extract_arn(cedar_entity: str) -> str:
    """Extract raw ARN from Cedar entity string like Role::"arn:aws:..."."""
    match = re.search(r'"([^"]+)"', cedar_entity)
    return match.group(1) if match else cedar_entity


def _build_conditions(conditions: Conditions) -> list[str]:
    """Build Rego condition expressions."""
    conds: list[str] = []
    if conditions.network_restriction:
        conds.append(f'    input.context.source_ip == "{conditions.network_restriction}"')
    if conditions.time_restriction:
        conds.append(f'    time.now_ns() # time_restriction: {conditions.time_restriction}')
    return conds


class OPACompiler(PolicyCompiler):
    """Deterministic OPA/Rego policy compiler."""

    format_name = "opa"

    def compile(
        self,
        resolved: ResolvedEntities,
        conditions: Optional[Conditions] = None,
    ) -> str:
        """Produce an OPA/Rego policy string from resolved entities."""
        try:
            principal_arn = _extract_arn(resolved.principal)
            resource_arn = _extract_arn(resolved.resource)
            effect = getattr(resolved, "effect", "permit")

            lines: list[str] = []
            lines.append("package policy.access")
            lines.append("")

            if effect == "permit":
                lines.append("default allow = false")
                lines.append("")
                lines.append("allow {")
                lines.append(f'    input.principal == "{principal_arn}"')
                lines.append(f'    input.action == "{resolved.action}"')
                lines.append(f'    input.resource == "{resource_arn}"')
                if conditions:
                    for cond_line in _build_conditions(conditions):
                        lines.append(cond_line)
                lines.append("}")
            elif effect == "deny":
                lines.append("default deny = false")
                lines.append("")
                lines.append("deny {")
                lines.append(f'    input.principal == "{principal_arn}"')
                lines.append(f'    input.action == "{resolved.action}"')
                lines.append(f'    input.resource == "{resource_arn}"')
                if conditions:
                    for cond_line in _build_conditions(conditions):
                        lines.append(cond_line)
                lines.append("}")
            else:
                # Conditional — output both with a note
                lines.append("# CONDITIONAL POLICY — requires manual review")
                lines.append("default allow = false")
                lines.append("")
                lines.append("allow {")
                lines.append(f'    input.principal == "{principal_arn}"')
                lines.append(f'    input.action == "{resolved.action}"')
                lines.append(f'    input.resource == "{resource_arn}"')
                lines.append("    # TODO: Add conditional logic")
                if conditions:
                    for cond_line in _build_conditions(conditions):
                        lines.append(cond_line)
                lines.append("}")

            policy = "\n".join(lines)
            logger.info("[OPACompiler] Rego policy generated (%d chars).", len(policy))
            return policy

        except Exception as exc:
            raise PolicyCompilationError(f"OPA/Rego compilation failed: {exc}") from exc
