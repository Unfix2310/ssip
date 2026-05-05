"""
YAML Compiler: converts ResolvedEntities → Governance YAML policy.
Pure deterministic template. Zero LLM involvement.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

import yaml

from ..exceptions import PolicyCompilationError
from ..schema import Conditions
from . import PolicyCompiler, ResolvedEntities

logger = logging.getLogger(__name__)


def _extract_arn(cedar_entity: str) -> str:
    """Extract raw ARN from Cedar entity string."""
    match = re.search(r'"([^"]+)"', cedar_entity)
    return match.group(1) if match else cedar_entity


class YAMLCompiler(PolicyCompiler):
    """Deterministic Governance YAML policy compiler."""

    format_name = "yaml"

    def compile(
        self,
        resolved: ResolvedEntities,
        conditions: Optional[Conditions] = None,
    ) -> str:
        """Produce a Governance YAML policy from resolved entities."""
        try:
            effect = getattr(resolved, "effect", "permit")
            principal_arn = _extract_arn(resolved.principal)
            resource_arn = _extract_arn(resolved.resource)

            policy_dict = {
                "policy": {
                    "effect": effect,
                    "principal": {
                        "type": resolved.principal.split("::")[0] if "::" in resolved.principal else "Unknown",
                        "arn": principal_arn,
                    },
                    "action": resolved.action,
                    "resource": {
                        "type": resolved.resource.split("::")[0] if "::" in resolved.resource else "Unknown",
                        "arn": resource_arn,
                    },
                    "conditions": [],
                    "metadata": {
                        "resolution": {
                            "principal_tier": getattr(resolved, "principal_tier", "unknown"),
                            "resource_tier": getattr(resolved, "resource_tier", "unknown"),
                            "principal_confidence": getattr(resolved, "principal_score", 0.0),
                            "resource_confidence": getattr(resolved, "resource_score", 0.0),
                        },
                    },
                },
            }

            # Add conditions
            if conditions:
                if conditions.network_restriction:
                    policy_dict["policy"]["conditions"].append({
                        "type": "network",
                        "operator": "equals",
                        "field": "source_ip",
                        "value": conditions.network_restriction,
                    })
                if conditions.time_restriction:
                    policy_dict["policy"]["conditions"].append({
                        "type": "time",
                        "operator": "between",
                        "value": conditions.time_restriction,
                    })

            policy = yaml.dump(policy_dict, default_flow_style=False, sort_keys=False)
            logger.info("[YAMLCompiler] YAML policy generated (%d chars).", len(policy))
            return policy

        except Exception as exc:
            raise PolicyCompilationError(f"YAML compilation failed: {exc}") from exc
