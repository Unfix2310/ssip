import hashlib
import hmac
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from app.config import settings


class PolicyLoader:
    def __init__(self) -> None:
        self._cache: dict[str, tuple[str, float, dict[str, Any]]] = {}

    def _canonical_json(self, policy: dict[str, Any]) -> str:
        canonical_policy = deepcopy(policy)
        canonical_policy.setdefault("meta", {})
        canonical_policy["meta"].pop("signature", None)
        canonical_policy["meta"].pop("hash", None)
        return json.dumps(canonical_policy, sort_keys=True, separators=(",", ":"))

    def _compute_hash(self, policy: dict[str, Any]) -> str:
        canonical = self._canonical_json(policy).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _verify_hmac_signature(self, policy: dict[str, Any]) -> None:
        if not settings.policy_hmac_secret:
            return
        provided = str(policy.get("meta", {}).get("signature", ""))
        if not provided:
            raise ValueError("Policy signature missing while POLICY_HMAC_SECRET is set")
        digest = hmac.new(
            settings.policy_hmac_secret.encode("utf-8"),
            self._canonical_json(policy).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(provided, digest):
            raise ValueError("Policy signature verification failed")

    def _normalize_policy(self, raw: dict[str, Any]) -> dict[str, Any]:
        policy = deepcopy(raw)
        policy.setdefault("meta", {})
        policy.setdefault("rate_limit_per_minute", settings.rate_limit_per_minute)
        policy.setdefault("numeric_tolerance", 0.0)
        policy.setdefault("pii_patterns", {})
        policy.setdefault("jailbreak_deny_list", [])
        policy.setdefault("jailbreak_regex_deny_list", [])
        policy.setdefault("numeric_rules", {})
        policy.setdefault(
            "semantic_layer",
            {
                "enabled": settings.semantic_enabled_default,
                "mode": settings.semantic_mode_default,
                "timeout_ms": settings.semantic_timeout_ms_default,
                "min_risk_score": settings.semantic_min_risk_score_default,
                "fail_mode": settings.semantic_fail_mode_default,
                "min_confidence": settings.semantic_min_confidence_default,
            },
        )
        policy_hash = self._compute_hash(policy)
        policy["meta"].setdefault("version", policy_hash[:12])
        policy["meta"]["hash"] = policy_hash
        return policy

    def load(self, tenant_id: str) -> dict[str, Any]:
        policy_path = Path(settings.policy_dir) / f"{tenant_id}.yaml"
        if not policy_path.exists():
            policy_path = Path(settings.policy_dir) / "default.yaml"

        mtime = policy_path.stat().st_mtime
        cached = self._cache.get(tenant_id)
        policy_path_str = str(policy_path.resolve())
        if cached and cached[0] == policy_path_str and cached[1] == mtime:
            return cached[2]

        with policy_path.open("r", encoding="utf-8") as f:
            raw_policy = yaml.safe_load(f) or {}

        self._verify_hmac_signature(raw_policy)
        policy = self._normalize_policy(raw_policy)

        self._cache[tenant_id] = (policy_path_str, mtime, policy)
        return policy


policy_loader = PolicyLoader()
