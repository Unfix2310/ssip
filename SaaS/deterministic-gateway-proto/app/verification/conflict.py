"""
Conflict Detection: identifies contradictions and overlaps across policies.

Conflict types:
  - contradiction: Same principal+resource with opposing effects (permit vs deny)
  - shadow:        Broader policy makes a narrower one unreachable
  - overlap:       Multiple policies match the same request
"""

from __future__ import annotations

import json
import logging
import re
from typing import Optional

from . import ConflictInfo

logger = logging.getLogger(__name__)


def _parse_cedar_policy(policy_text: str) -> Optional[dict]:
    """
    Extract principal, action, resource, and effect from a Cedar policy string.
    Returns None if parsing fails.
    """
    effect = "permit" if "permit(" in policy_text else "deny" if "forbid(" in policy_text else None
    if not effect:
        return None

    principal_match = re.search(r'principal\s*==\s*(.+)', policy_text)
    action_match = re.search(r'action\s*==\s*Action::"(\w+)"', policy_text)
    resource_match = re.search(r'resource\s*==\s*(.+)', policy_text)

    if not all([principal_match, action_match, resource_match]):
        return None

    # Clean up captured groups (remove trailing comma/paren/newline)
    principal = re.sub(r'[,\s)]+$', '', principal_match.group(1).strip())
    resource = re.sub(r'[,\s)]+$', '', resource_match.group(1).strip())

    return {
        "effect": effect,
        "principal": principal,
        "action": action_match.group(1),
        "resource": resource,
    }


async def detect_conflicts(
    policy_id: str,
    cedar_policy: str,
) -> list[ConflictInfo]:
    """
    Detect conflicts between the new policy and existing policies in the database.

    Checks for:
      1. Contradictions — same principal+action+resource with opposing effects
      2. Shadows — broader existing policy makes new one unreachable
      3. Overlaps — multiple policies match the same request pattern

    Args:
        policy_id:    ID of the new policy being verified.
        cedar_policy: The Cedar policy string to check.

    Returns:
        List of ConflictInfo objects describing each detected conflict.
    """
    conflicts: list[ConflictInfo] = []

    new_parsed = _parse_cedar_policy(cedar_policy)
    if not new_parsed:
        logger.warning("[Conflict] Could not parse new policy — skipping conflict detection.")
        return conflicts

    # Load existing policies from database
    try:
        from ..database import get_db
        db = await get_db()
        try:
            cursor = await db.execute(
                "SELECT id, compiled_policies, status FROM policies WHERE status IN ('active', 'approved') AND id != ?",
                (policy_id,),
            )
            rows = await cursor.fetchall()
        finally:
            await db.close()
    except Exception as exc:
        logger.warning("[Conflict] Could not load existing policies: %s", exc)
        return conflicts

    for row in rows:
        existing_id = row["id"]
        try:
            compiled = json.loads(row["compiled_policies"])
            existing_cedar = compiled.get("cedar", "")
        except (json.JSONDecodeError, TypeError):
            continue

        existing_parsed = _parse_cedar_policy(existing_cedar)
        if not existing_parsed:
            continue

        # ── Check 1: Contradiction ────────────────────────────────────────────
        if (
            existing_parsed["principal"] == new_parsed["principal"]
            and existing_parsed["action"] == new_parsed["action"]
            and existing_parsed["resource"] == new_parsed["resource"]
            and existing_parsed["effect"] != new_parsed["effect"]
        ):
            conflicts.append(ConflictInfo(
                type="contradiction",
                policy_a_id=policy_id,
                policy_b_id=existing_id,
                description=(
                    f"Contradicting effects: new policy '{new_parsed['effect']}' vs "
                    f"existing policy '{existing_parsed['effect']}' for same "
                    f"principal/action/resource combination."
                ),
                severity="error",
            ))

        # ── Check 2: Exact duplicate ──────────────────────────────────────────
        elif (
            existing_parsed["principal"] == new_parsed["principal"]
            and existing_parsed["action"] == new_parsed["action"]
            and existing_parsed["resource"] == new_parsed["resource"]
            and existing_parsed["effect"] == new_parsed["effect"]
        ):
            conflicts.append(ConflictInfo(
                type="overlap",
                policy_a_id=policy_id,
                policy_b_id=existing_id,
                description=(
                    f"Duplicate policy: identical principal/action/resource/effect "
                    f"already exists in policy {existing_id[:8]}."
                ),
                severity="warning",
            ))

        # ── Check 3: Same principal+resource, different action ────────────────
        elif (
            existing_parsed["principal"] == new_parsed["principal"]
            and existing_parsed["resource"] == new_parsed["resource"]
            and existing_parsed["effect"] != new_parsed["effect"]
        ):
            conflicts.append(ConflictInfo(
                type="shadow",
                policy_a_id=policy_id,
                policy_b_id=existing_id,
                description=(
                    f"Potential shadow: same principal+resource with "
                    f"'{new_parsed['effect']}' (action: {new_parsed['action']}) vs "
                    f"'{existing_parsed['effect']}' (action: {existing_parsed['action']})."
                ),
                severity="warning",
            ))

    if conflicts:
        logger.warning("[Conflict] Detected %d conflict(s) for policy %s.", len(conflicts), policy_id[:8])
    else:
        logger.info("[Conflict] No conflicts detected for policy %s.", policy_id[:8])

    return conflicts
