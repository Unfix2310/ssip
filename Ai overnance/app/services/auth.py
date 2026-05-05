import secrets

import jwt
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.security import APIKeyHeader

from app.config import settings
from app.models import AuthContext

api_key_header = APIKeyHeader(name="x-gateway-key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


def _decode_jwt(credentials: HTTPAuthorizationCredentials | None) -> AuthContext | None:
    if credentials is None:
        return None
    if credentials.scheme.lower() != "bearer":
        return None
    try:
        claims = jwt.decode(
            credentials.credentials,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
        )
        return AuthContext(
            subject=str(claims.get("sub", "jwt-subject")),
            tenant_scope=claims.get("tenant_id"),
            auth_mode="jwt",
        )
    except Exception:
        return None


def _check_api_key(api_key: str | None) -> AuthContext | None:
    if not api_key:
        return None
    if not secrets.compare_digest(api_key, settings.gateway_api_key):
        return None
    return AuthContext(subject="api-key-client", tenant_scope=None, auth_mode="api_key")


def authorize_request(
    api_key: str | None = Security(api_key_header),
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> AuthContext:
    mode = settings.auth_mode.lower()
    api_ctx = _check_api_key(api_key)
    jwt_ctx = _decode_jwt(bearer)

    if mode == "api_key":
        if api_ctx:
            return api_ctx
    elif mode == "jwt":
        if jwt_ctx:
            return jwt_ctx
    elif mode == "either":
        if jwt_ctx:
            return jwt_ctx
        if api_ctx:
            return api_ctx
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Invalid auth mode: {mode}",
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized request",
    )
