"""
Catalog Adapters: interface stubs for live catalog integration.

These are placeholder implementations for future IAM, CMDB, and cloud
inventory adapters. They demonstrate the adapter pattern but do not
connect to real services.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class IAMCatalogAdapter:
    """
    Placeholder adapter for AWS IAM integration.
    
    In production, this would:
    - Connect to AWS IAM via boto3
    - List all roles/users/groups as principals
    - Sync periodically or on-demand
    """

    def __init__(self, region: str = "ap-south-1") -> None:
        self.region = region
        logger.info("[CatalogAdapter] IAM adapter initialized (region=%s) — STUB ONLY", region)

    def principal_keys(self) -> list[str]:
        logger.warning("[CatalogAdapter] IAM adapter not implemented — returning empty list.")
        return []

    def resource_keys(self) -> list[str]:
        return []

    def get_principal(self, key: str) -> Optional[str]:
        return None

    def get_resource(self, key: str) -> Optional[str]:
        return None


class CMDBCatalogAdapter:
    """
    Placeholder adapter for CMDB (Configuration Management Database) integration.
    
    In production, this would:
    - Query a CMDB API (ServiceNow, Device42, etc.)
    - List all managed resources (servers, databases, buckets)
    - Map CMDB CIs to Cedar resource identifiers
    """

    def __init__(self, api_url: str = "") -> None:
        self.api_url = api_url
        logger.info("[CatalogAdapter] CMDB adapter initialized (url=%s) — STUB ONLY", api_url)

    def principal_keys(self) -> list[str]:
        return []

    def resource_keys(self) -> list[str]:
        logger.warning("[CatalogAdapter] CMDB adapter not implemented — returning empty list.")
        return []

    def get_principal(self, key: str) -> Optional[str]:
        return None

    def get_resource(self, key: str) -> Optional[str]:
        return None
