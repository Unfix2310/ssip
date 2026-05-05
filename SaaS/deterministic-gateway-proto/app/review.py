"""
Review Service: human review queue management.

Provides async functions for:
  - Submitting policies for review
  - Listing pending reviews
  - Submitting review decisions (approve/reject/modify)
  - Feeding corrections back into the system
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from .database import get_db

logger = logging.getLogger(__name__)


async def submit_for_review(
    policy_id: str,
    reason: str,
) -> None:
    """
    Mark a policy as pending review.

    Args:
        policy_id: The policy UUID.
        reason:    Why review is required.
    """
    db = await get_db()
    try:
        await db.execute(
            "UPDATE policies SET status = 'pending_review', routing_reason = ? WHERE id = ?",
            (reason, policy_id),
        )
        await db.commit()
        logger.info("[Review] Policy %s submitted for review: %s", policy_id[:8], reason)
    finally:
        await db.close()


async def get_pending_reviews() -> list[dict[str, Any]]:
    """Return all policies with status 'pending_review'."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """
            SELECT id, input_text, confidence_score, routing_reason, effect,
                   principal_raw, resource_raw, created_at
            FROM policies
            WHERE status = 'pending_review'
            ORDER BY created_at DESC
            """
        )
        rows = await cursor.fetchall()
        return [
            {
                "policy_id": row["id"],
                "input_text": row["input_text"],
                "confidence_score": row["confidence_score"] or 0.0,
                "routing_reason": row["routing_reason"],
                "effect": row["effect"],
                "principal_raw": row["principal_raw"],
                "resource_raw": row["resource_raw"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    finally:
        await db.close()


async def submit_review_decision(
    policy_id: str,
    reviewer: str,
    decision: str,
    correction: Optional[dict] = None,
    reason: Optional[str] = None,
) -> dict[str, str]:
    """
    Submit a review decision for a policy.

    Args:
        policy_id:  The policy UUID.
        reviewer:   Reviewer name or ID.
        decision:   "approve", "reject", or "modify".
        correction: Optional correction data (for "modify" decision).
        reason:     Optional reason for the decision.

    Returns:
        Dict with policy_id, decision, and new_status.
    """
    # Map decision → new status
    status_map = {
        "approve": "approved",
        "reject": "rejected",
        "modify": "pending_review",  # Stays in review if modified
    }
    new_status = status_map.get(decision, "pending_review")

    # If approved, mark as active
    if decision == "approve":
        new_status = "active"

    db = await get_db()
    try:
        # Insert review record
        await db.execute(
            """
            INSERT INTO reviews (policy_id, reviewer, decision, correction, reason)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                policy_id,
                reviewer,
                decision,
                json.dumps(correction) if correction else None,
                reason,
            ),
        )

        # Update policy status
        now = datetime.now(timezone.utc).isoformat()
        await db.execute(
            "UPDATE policies SET status = ?, updated_at = ? WHERE id = ?",
            (new_status, now, policy_id),
        )

        await db.commit()
        logger.info(
            "[Review] Policy %s reviewed by %s: decision=%s → status=%s",
            policy_id[:8], reviewer, decision, new_status,
        )

        return {
            "policy_id": policy_id,
            "decision": decision,
            "new_status": new_status,
        }
    finally:
        await db.close()


async def get_review_history(policy_id: str) -> list[dict[str, Any]]:
    """Get all review decisions for a policy."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """
            SELECT reviewer, decision, correction, reason, timestamp
            FROM reviews
            WHERE policy_id = ?
            ORDER BY timestamp DESC
            """,
            (policy_id,),
        )
        rows = await cursor.fetchall()
        return [
            {
                "reviewer": row["reviewer"],
                "decision": row["decision"],
                "correction": json.loads(row["correction"]) if row["correction"] else None,
                "reason": row["reason"],
                "timestamp": row["timestamp"],
            }
            for row in rows
        ]
    finally:
        await db.close()
