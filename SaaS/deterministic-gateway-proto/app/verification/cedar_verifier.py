"""
Cedar Verifier: validates Cedar policy syntax.
Uses Cedar CLI if available, falls back to structural lint.

Migrated from the original verifier.py.
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile

from ..exceptions import VerificationError

logger = logging.getLogger(__name__)

# Cedar keywords that must be present in a valid policy
_PERMIT_KEYWORDS = ("permit(", "principal ==", "action ==", "resource ==")
_DENY_KEYWORDS = ("forbid(", "principal ==", "action ==", "resource ==")


def _structural_lint(policy: str) -> None:
    """
    Lightweight structural check used when Cedar CLI is unavailable.
    Validates the policy contains all required Cedar keywords.
    """
    # Determine if it's a permit or deny policy
    if "forbid(" in policy:
        required = _DENY_KEYWORDS
    else:
        required = _PERMIT_KEYWORDS

    for kw in required:
        if kw not in policy:
            raise VerificationError(f"Policy missing required Cedar keyword: '{kw}'")

    # Check balanced parentheses and semicolon
    if policy.count("(") != policy.count(")"):
        raise VerificationError("Unbalanced parentheses in policy.")
    if not policy.rstrip().endswith(";"):
        raise VerificationError("Policy must end with a semicolon.")

    logger.info("[CedarVerifier] Structural lint passed (Cedar CLI not found).")


def verify_cedar_parse(policy: str) -> None:
    """
    Save policy to a temp file and verify it with the Cedar CLI.
    If Cedar CLI is not on PATH, falls back to structural linting.

    Args:
        policy: Compiled Cedar policy string.

    Raises:
        VerificationError: On any verification failure.
    """
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".cedar",
        delete=False,
        prefix="policy_",
    )
    try:
        tmp.write(policy)
        tmp.flush()
        tmp_path = tmp.name
    finally:
        tmp.close()

    try:
        result = subprocess.run(
            ["cedar", "check-parse", "-p", tmp_path],
            capture_output=True,
            text=True,
            timeout=10,
        )

        logger.info("[CedarVerifier] Cedar CLI exit code: %d", result.returncode)
        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip()
            raise VerificationError(f"Cedar CLI validation failed: {stderr}")

        logger.info("[CedarVerifier] Cedar CLI validation passed.")

    except FileNotFoundError:
        logger.warning("[CedarVerifier] Cedar CLI not found. Using structural lint.")
        _structural_lint(policy)

    except subprocess.TimeoutExpired as exc:
        raise VerificationError("Cedar CLI timed out during validation.") from exc

    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
