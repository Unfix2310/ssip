"""
Entity Resolver: maps IR intents → deterministic Cedar entity strings.

Pipeline position: Pre-normalization → Schema validation → [THIS MODULE] → Compilation

Uses the catalog package (abstract interface) instead of direct dict access.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .catalog import get_principal, get_resource, principal_keys, resource_keys
from .exceptions import EntityResolutionError
from .normalizer import ResolutionTier, normalize_entity
from .schema import PolicyIR

logger = logging.getLogger(__name__)


@dataclass
class ResolvedEntities:
    principal: str               # Cedar-formatted entity string
    resource: str                # Cedar-formatted entity string
    action: str                  # Validated action (read | write | admin)
    effect: str                  # Policy effect (permit | deny | conditional)
    principal_tier: ResolutionTier
    resource_tier: ResolutionTier
    principal_raw: str           # Original LLM string
    resource_raw: str
    principal_score: float       # Confidence score (1.0 for exact/alias, cosine for tfidf)
    resource_score: float
