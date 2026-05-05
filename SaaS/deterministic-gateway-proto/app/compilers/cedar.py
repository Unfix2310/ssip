"""
Cedar Compiler: converts ResolvedEntities → Cedar policy string.
Pure deterministic template. Zero LLM involvement.

Migrated from the original compiler.py into the compilers package.
"""

from __future__ import annotations

import logging
from textwrap import dedent
from typing import Optional

from ..exceptions import PolicyCompilationError
from ..schema import Conditions
from . import PolicyCompiler, ResolvedEntities

logger = logging.getLogger(__name__)

# ── Cedar policy templates ────────────────────────────────────────────────────

_CEDAR_PERMIT = """\
permit(
    principal == {principal},
    action == Action::"{action}",
    resource == {resource}
){when_clause};
"""

_CEDAR_DENY = """\
forbid(
    principal == {principal},
    action == Action::"{action}",
    resource == {resource}
){when_clause};
"""

_CEDAR_WHEN = """
when {{
{conditions}
}}"""


def _build_when_clause(conditions: Conditions) -> str:
    """Compile optional Cedar `when` clause from IR conditions."""
    clauses: list[str] = []

    if conditions.network_restriction:
        clauses.append(
            f'    context.sourceIp == "{conditions.network_restriction}"'
        )

    if conditions.time_restriction:
        clauses.append(
            f'    context.currentTime like "{conditions.time_restriction}"'
        )

    if not clauses:
        return ""

    body = " &&\n".join(clauses)
    return _CEDAR_WHEN.format(conditions=body)


class CedarCompiler(PolicyCompiler):
    """Deterministic Cedar policy compiler."""

    format_name = "cedar"

    def compile(
        self,
        resolved: ResolvedEntities,
        conditions: Optional[Conditions] = None,
    ) -> str:
        """
        Produce a Cedar policy string from resolved entities.

        Supports both permit and deny (forbid) effects.
        """
        try:
            when_clause = _build_when_clause(conditions) if conditions else ""

            # Select template based on effect
            effect = getattr(resolved, "effect", "permit")
            template = _CEDAR_DENY if effect == "deny" else _CEDAR_PERMIT

            policy = template.format(
                principal=resolved.principal,
                action=resolved.action,
                resource=resolved.resource,
                when_clause=when_clause,
            )
            policy = dedent(policy).strip()
            logger.info("[CedarCompiler] Policy generated (%d chars, effect=%s).", len(policy), effect)
            return policy

        except KeyError as exc:
            raise PolicyCompilationError(f"Cedar template substitution failed: {exc}") from exc
