"""
Catalog Package: abstract interface for entity → Cedar ARN mappings.

The catalog is the single source of truth for all known entities.
Concrete implementations can be static (Python dict) or live (IAM, CMDB).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from .static import StaticCatalogProvider


class CatalogProvider(ABC):
    """Abstract interface for catalog implementations."""

    @abstractmethod
    def principal_keys(self) -> list[str]:
        """Return all canonical principal keys."""
        ...

    @abstractmethod
    def resource_keys(self) -> list[str]:
        """Return all canonical resource keys."""
        ...

    @abstractmethod
    def get_principal(self, key: str) -> Optional[str]:
        """Return Cedar ARN for a canonical principal key."""
        ...

    @abstractmethod
    def get_resource(self, key: str) -> Optional[str]:
        """Return Cedar ARN for a canonical resource key."""
        ...


# ── Singleton catalog instance ─────────────────────────────────────────────────
# Default to static catalog. Can be swapped at startup for live adapters.

_active_catalog: CatalogProvider = StaticCatalogProvider()


def get_catalog() -> CatalogProvider:
    """Return the currently active catalog provider."""
    return _active_catalog


def set_catalog(provider: CatalogProvider) -> None:
    """Swap the active catalog provider (e.g., for testing or live adapters)."""
    global _active_catalog
    _active_catalog = provider


# ── Convenience functions (preserve backward compatibility) ────────────────────

def principal_keys() -> list[str]:
    return _active_catalog.principal_keys()


def resource_keys() -> list[str]:
    return _active_catalog.resource_keys()


def get_principal(canonical_key: str) -> Optional[str]:
    return _active_catalog.get_principal(canonical_key)


def get_resource(canonical_key: str) -> Optional[str]:
    return _active_catalog.get_resource(canonical_key)
