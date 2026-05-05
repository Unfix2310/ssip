#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
import sys
from copy import deepcopy
from pathlib import Path

import yaml


def canonical(policy: dict) -> str:
    value = deepcopy(policy)
    value.setdefault("meta", {})
    value["meta"].pop("signature", None)
    value["meta"].pop("hash", None)
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: sign_policy.py <path-to-policy-yaml>")
        return 1

    secret = os.environ.get("POLICY_HMAC_SECRET")
    if not secret:
        print("POLICY_HMAC_SECRET is required")
        return 1

    path = Path(sys.argv[1])
    with path.open("r", encoding="utf-8") as f:
        policy = yaml.safe_load(f) or {}

    digest = hmac.new(secret.encode("utf-8"), canonical(policy).encode("utf-8"), hashlib.sha256).hexdigest()
    policy.setdefault("meta", {})
    policy["meta"]["signature"] = digest

    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(policy, f, sort_keys=False)

    print(f"Signed policy: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
