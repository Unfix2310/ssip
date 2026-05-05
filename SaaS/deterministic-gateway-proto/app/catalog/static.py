"""
Static Catalog Provider: in-memory Python dictionary.

This is the original catalog implementation, now wrapped in the
CatalogProvider interface. Keys are lowercase canonical strings.
Alias resolution is the normalizer's job — not the catalog's.
"""

from __future__ import annotations

from typing import Optional


class StaticCatalogProvider:
    """
    Static in-memory catalog for prototype use.
    
    Contains 6 principals and 6 resources mapped to Cedar ARN strings.
    """

    def __init__(self) -> None:
        self._data: dict[str, dict[str, str]] = {
            "principals": {
                "finance team":  'Role::"arn:aws:iam::1111:role/Finance"',
                "developers":    'Role::"arn:aws:iam::2222:role/DevTeam"',
                "admin team":    'Role::"arn:aws:iam::3333:role/Admins"',
                "security team": 'Role::"arn:aws:iam::4444:role/Security"',
                "data team":     'Role::"arn:aws:iam::5555:role/DataEng"',
                "qa team":       'Role::"arn:aws:iam::6666:role/QAEngineers"',
            },
            "resources": {
                "payroll bucket": 'Bucket::"arn:aws:s3:::corp-payroll-prod"',
                "server logs":    'Bucket::"arn:aws:s3:::app-logs-01"',
                "audit logs":     'Bucket::"arn:aws:s3:::audit-logs-prod"',
                "config bucket":  'Bucket::"arn:aws:s3:::corp-config-store"',
                "ml models":      'Bucket::"arn:aws:s3:::ml-model-registry"',
                "user data":      'Bucket::"arn:aws:s3:::user-profile-data"',
            },
        }

    def principal_keys(self) -> list[str]:
        return list(self._data["principals"].keys())

    def resource_keys(self) -> list[str]:
        return list(self._data["resources"].keys())

    def get_principal(self, key: str) -> Optional[str]:
        return self._data["principals"].get(key)

    def get_resource(self, key: str) -> Optional[str]:
        return self._data["resources"].get(key)
