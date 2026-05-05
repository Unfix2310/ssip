"""
Deployment Package: policy deployment and versioning management.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from ..database import get_db
from ..exceptions import DeploymentError

logger = logging.getLogger(__name__)


async def save_policy_version(
    policy_id: str,
    version: str,
    ir_json: str,
    compiled_policies: str,
) -> int:
    """
    Save a version snapshot of a policy.

    Returns the version row ID.
    """
    db = await get_db()
    try:
        cursor = await db.execute(
            """
            INSERT INTO policy_versions (policy_id, version, ir_json, compiled_policies)
            VALUES (?, ?, ?, ?)
            """,
            (policy_id, version, ir_json, compiled_policies),
        )
        await db.commit()
        version_id = cursor.lastrowid
        logger.info("[Deployment] Saved version %s for policy %s (row=%d).", version, policy_id[:8], version_id)
        return version_id
    finally:
        await db.close()


async def get_version_history(policy_id: str) -> list[dict[str, Any]]:
    """Get all versions of a policy, newest first."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """
            SELECT version, ir_json, compiled_policies, created_at, rolled_back
            FROM policy_versions
            WHERE policy_id = ?
            ORDER BY created_at DESC
            """,
            (policy_id,),
        )
        rows = await cursor.fetchall()
        results = []
        for row in rows:
            try:
                compiled = json.loads(row["compiled_policies"])
            except (json.JSONDecodeError, TypeError):
                compiled = {}
            results.append({
                "version": row["version"],
                "compiled_policies": compiled,
                "created_at": row["created_at"],
                "rolled_back": bool(row["rolled_back"]),
            })
        return results
    finally:
        await db.close()


async def rollback_policy(policy_id: str, target_version: str) -> dict[str, str]:
    """
    Rollback a policy to a specific previous version.

    Args:
        policy_id:      The policy UUID.
        target_version: The version string to rollback to.

    Returns:
        Dict with policy_id, rolled_back_to, and new_version.

    Raises:
        DeploymentError: If the target version doesn't exist.
    """
    db = await get_db()
    try:
        # Find the target version
        cursor = await db.execute(
            """
            SELECT version, ir_json, compiled_policies
            FROM policy_versions
            WHERE policy_id = ? AND version = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (policy_id, target_version),
        )
        row = await cursor.fetchone()

        if not row:
            raise DeploymentError(
                f"Version {target_version} not found for policy {policy_id[:8]}."
            )

        # Mark current version as rolled back
        await db.execute(
            """
            UPDATE policy_versions
            SET rolled_back = 1
            WHERE policy_id = ? AND version != ?
            """,
            (policy_id, target_version),
        )

        # Increment version number
        # Get current max version
        cursor = await db.execute(
            "SELECT COUNT(*) as cnt FROM policy_versions WHERE policy_id = ?",
            (policy_id,),
        )
        count_row = await cursor.fetchone()
        new_version = f"1.0.{count_row['cnt']}"

        # Save the rollback as a new version
        await db.execute(
            """
            INSERT INTO policy_versions (policy_id, version, ir_json, compiled_policies)
            VALUES (?, ?, ?, ?)
            """,
            (policy_id, new_version, row["ir_json"], row["compiled_policies"]),
        )

        # Update the main policy record
        now = datetime.now(timezone.utc).isoformat()
        await db.execute(
            """
            UPDATE policies
            SET version = ?, ir_json = ?, compiled_policies = ?, updated_at = ?, status = 'active'
            WHERE id = ?
            """,
            (new_version, row["ir_json"], row["compiled_policies"], now, policy_id),
        )

        await db.commit()

        logger.info(
            "[Deployment] Policy %s rolled back from current to version %s (new: %s).",
            policy_id[:8], target_version, new_version,
        )

        return {
            "policy_id": policy_id,
            "rolled_back_to": target_version,
            "new_version": new_version,
        }
    finally:
        await db.close()


async def get_deployment_status(policy_id: str) -> dict[str, Any]:
    """Get current deployment status for a policy."""
    db = await get_db()
    try:
        # Get policy info
        cursor = await db.execute(
            "SELECT id, version, status FROM policies WHERE id = ?",
            (policy_id,),
        )
        policy_row = await cursor.fetchone()
        if not policy_row:
            raise DeploymentError(f"Policy {policy_id[:8]} not found.")

        # Count versions
        cursor = await db.execute(
            "SELECT COUNT(*) as cnt FROM policy_versions WHERE policy_id = ?",
            (policy_id,),
        )
        version_count = (await cursor.fetchone())["cnt"]

        return {
            "policy_id": policy_id,
            "deployment_status": policy_row["status"],
            "current_version": policy_row["version"],
            "total_versions": version_count,
        }
    finally:
        await db.close()
