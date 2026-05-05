"""
Compilers Package: multi-format policy compilation.

Provides a base compiler interface and a registry of all available compilers.
Each compiler converts ResolvedEntities → a policy string in a specific format.

Available formats:
  - cedar:  AWS Cedar policy language
  - opa:    Open Policy Agent (Rego)
  - yaml:   Governance YAML
  - xacml:  XACML 3.0 XML
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Optional

from ..exceptions import PolicyCompilationError
from ..schema import Conditions

logger = logging.getLogger(__name__)


class ResolvedEntities:
    """
    Resolved entity data passed to compilers.
    
    Re-exported here so compilers can import from the package.
    """
    def __init__(
        self,
        principal: str,
        resource: str,
        action: str,
        effect: str = "permit",
        principal_tier: str = "exact",
        resource_tier: str = "exact",
        principal_raw: str = "",
        resource_raw: str = "",
        principal_score: float = 1.0,
        resource_score: float = 1.0,
    ):
        self.principal = principal
        self.resource = resource
        self.action = action
        self.effect = effect
        self.principal_tier = principal_tier
        self.resource_tier = resource_tier
        self.principal_raw = principal_raw
        self.resource_raw = resource_raw
        self.principal_score = principal_score
        self.resource_score = resource_score


class PolicyCompiler(ABC):
    """Abstract base class for policy compilers."""

    format_name: str = "unknown"

    @abstractmethod
    def compile(
        self,
        resolved: ResolvedEntities,
        conditions: Optional[Conditions] = None,
    ) -> str:
        """
        Compile resolved entities into a policy string.

        Args:
            resolved:   ResolvedEntities with principal, action, resource ARNs.
            conditions: Optional conditions (network, time restrictions).

        Returns:
            Formatted policy string.

        Raises:
            PolicyCompilationError: If compilation fails.
        """
        ...


# ── Compiler Registry ─────────────────────────────────────────────────────────

COMPILER_REGISTRY: dict[str, PolicyCompiler] = {}


def register_compiler(compiler: PolicyCompiler) -> None:
    """Register a compiler instance in the global registry."""
    COMPILER_REGISTRY[compiler.format_name] = compiler
    logger.info("[Compilers] Registered compiler: %s", compiler.format_name)


def compile_policy(
    resolved: ResolvedEntities,
    conditions: Optional[Conditions] = None,
    fmt: str = "cedar",
) -> str:
    """Compile a policy using a specific format compiler."""
    compiler = COMPILER_REGISTRY.get(fmt)
    if not compiler:
        raise PolicyCompilationError(f"Unknown compiler format: {fmt}. Available: {list(COMPILER_REGISTRY.keys())}")
    return compiler.compile(resolved, conditions)


def compile_all(
    resolved: ResolvedEntities,
    conditions: Optional[Conditions] = None,
    formats: Optional[list[str]] = None,
) -> dict[str, str]:
    """
    Compile a policy to multiple formats.

    Args:
        resolved:   ResolvedEntities.
        conditions: Optional conditions.
        formats:    List of format names. If None, compiles to ALL registered formats.

    Returns:
        Dict of format_name → compiled policy string.
    """
    target_formats = formats or list(COMPILER_REGISTRY.keys())
    results: dict[str, str] = {}

    for fmt in target_formats:
        compiler = COMPILER_REGISTRY.get(fmt)
        if not compiler:
            logger.warning("[Compilers] Skipping unknown format: %s", fmt)
            continue
        try:
            results[fmt] = compiler.compile(resolved, conditions)
            logger.info("[Compilers] Compiled %s (%d chars).", fmt, len(results[fmt]))
        except PolicyCompilationError as exc:
            logger.error("[Compilers] Failed to compile %s: %s", fmt, exc)
            results[fmt] = f"# COMPILATION ERROR: {exc}"

    return results


# ── Auto-register all compilers on import ──────────────────────────────────────

def _init_compilers() -> None:
    """Import and register all built-in compilers."""
    from .cedar import CedarCompiler
    from .opa import OPACompiler
    from .yaml_compiler import YAMLCompiler
    from .xacml import XACMLCompiler

    register_compiler(CedarCompiler())
    register_compiler(OPACompiler())
    register_compiler(YAMLCompiler())
    register_compiler(XACMLCompiler())


_init_compilers()
