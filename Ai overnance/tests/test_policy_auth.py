import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import jwt
import pytest
import yaml
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.config import settings
from app.engine.policy_loader import PolicyLoader
from app.services.auth import authorize_request


def test_authorize_api_key_mode() -> None:
    old_mode = settings.auth_mode
    old_key = settings.gateway_api_key
    try:
        settings.auth_mode = "api_key"
        settings.gateway_api_key = "gateway-test"
        ctx = authorize_request(api_key="gateway-test", bearer=None)
        assert ctx.auth_mode == "api_key"
        with pytest.raises(HTTPException):
            authorize_request(api_key="bad-key", bearer=None)
    finally:
        settings.auth_mode = old_mode
        settings.gateway_api_key = old_key


def test_authorize_jwt_mode() -> None:
    old_mode = settings.auth_mode
    old_secret = settings.jwt_secret
    old_issuer = settings.jwt_issuer
    old_audience = settings.jwt_audience
    try:
        settings.auth_mode = "jwt"
        settings.jwt_secret = "jwt-test-secret"
        settings.jwt_issuer = "issuer-test"
        settings.jwt_audience = "aud-test"
        token = jwt.encode(
            {
                "sub": "svc-user",
                "tenant_id": "tenant-a",
                "iss": settings.jwt_issuer,
                "aud": settings.jwt_audience,
                "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
            },
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
        )
        bearer = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        ctx = authorize_request(api_key=None, bearer=bearer)
        assert ctx.auth_mode == "jwt"
        assert ctx.tenant_scope == "tenant-a"
    finally:
        settings.auth_mode = old_mode
        settings.jwt_secret = old_secret
        settings.jwt_issuer = old_issuer
        settings.jwt_audience = old_audience


def test_policy_loader_signature_verification(tmp_path) -> None:
    old_dir = settings.policy_dir
    old_secret = settings.policy_hmac_secret
    try:
        settings.policy_dir = str(tmp_path)
        settings.policy_hmac_secret = "policy-secret"
        policy = {
            "meta": {"version": "v1", "signature": ""},
            "rate_limit_per_minute": 50,
            "pii_patterns": {"pan": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"},
            "jailbreak_deny_list": ["ignore previous instructions"],
            "numeric_rules": {"loan_rate_card": {"default": 10.0}},
        }
        loader = PolicyLoader()
        canonical = loader._canonical_json(policy)
        signature = hmac.new(
            settings.policy_hmac_secret.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        policy["meta"]["signature"] = signature
        with (tmp_path / "default.yaml").open("w", encoding="utf-8") as f:
            yaml.safe_dump(policy, f)

        loaded = loader.load("tenant-does-not-exist")
        assert loaded["meta"]["version"] == "v1"
        assert "hash" in loaded["meta"]
    finally:
        settings.policy_dir = old_dir
        settings.policy_hmac_secret = old_secret
