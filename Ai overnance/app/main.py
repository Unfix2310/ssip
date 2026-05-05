import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response

from app.config import settings
from app.engine.jailbreak import check_jailbreak
from app.engine.math_validator import validate_numeric_rules
from app.engine.pii import redact_pii
from app.engine.policy_loader import policy_loader
from app.engine.schema_validator import validate_schema
from app.models import AuthContext, GatewayRequest, GatewayResponse, GovernanceReport, RuleAction
from app.services.audit import audit_logger
from app.services.auth import authorize_request
from app.services.llm_client import call_upstream_llm, extract_json_content, upstream_circuit_breaker
from app.services.observability import (
    POLICY_BLOCKS,
    REQUEST_COUNT,
    REQUEST_LATENCY,
    LatencyTimer,
    configure_logging,
    log_json,
    metrics_payload,
)
from app.services.rate_limit import rate_limiter
from app.services.semantic import semantic_layer

app = FastAPI(title=settings.app_name)


def _parse_time(value: str) -> datetime:
    text = value.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
    request.state.request_id = request_id
    timer = LatencyTimer()
    try:
        response = await call_next(request)
    except Exception:
        REQUEST_COUNT.labels(endpoint=request.url.path, tenant_id="unknown", outcome="error").inc()
        REQUEST_LATENCY.labels(endpoint=request.url.path).observe(timer.elapsed_ms() / 1000.0)
        raise
    response.headers["x-request-id"] = request_id
    REQUEST_LATENCY.labels(endpoint=request.url.path).observe(timer.elapsed_ms() / 1000.0)
    return response


@app.on_event("startup")
async def startup() -> None:
    configure_logging(settings.log_level)
    await audit_logger.start()
    log_json("service_startup", env=settings.env, app_name=settings.app_name)


@app.on_event("shutdown")
async def shutdown() -> None:
    await audit_logger.stop()
    log_json("service_shutdown", app_name=settings.app_name)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready")
async def ready() -> dict[str, object]:
    audit_ok = await audit_logger.readiness()
    redis_ok = await rate_limiter.readiness()
    circuit = upstream_circuit_breaker.snapshot()
    semantic_runtime = semantic_layer.runtime_status()
    ready_state = audit_ok and redis_ok and circuit["status"] != "open"
    return {
        "ready": ready_state,
        "dependencies": {
            "audit_db": audit_ok,
            "redis": redis_ok,
            "upstream_circuit": circuit,
            "semantic_runtime": semantic_runtime,
        },
    }


@app.get("/metrics")
async def metrics() -> Response:
    payload, content_type = metrics_payload()
    return Response(content=payload, media_type=content_type)


@app.get("/v1/governance/report", response_model=GovernanceReport)
async def governance_report(
    tenant_id: str = Query(...),
    from_ts: str | None = Query(default=None),
    to_ts: str | None = Query(default=None),
    auth: AuthContext = Depends(authorize_request),
) -> GovernanceReport:
    if auth.tenant_scope and auth.tenant_scope != tenant_id:
        raise HTTPException(status_code=403, detail="Token not allowed for this tenant")
    try:
        to_time = _parse_time(to_ts) if to_ts else datetime.now(timezone.utc)
        from_time = _parse_time(from_ts) if from_ts else to_time - timedelta(hours=24)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid from_ts/to_ts format")
    if from_time > to_time:
        raise HTTPException(status_code=400, detail="from_ts must be <= to_ts")
    return await audit_logger.report(tenant_id, from_time, to_time)


@app.post("/v1/gateway/chat", response_model=GatewayResponse)
async def gateway_chat(
    payload: GatewayRequest,
    request: Request,
    auth: AuthContext = Depends(authorize_request),
) -> GatewayResponse:
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    if auth.tenant_scope and auth.tenant_scope != payload.tenant_id:
        REQUEST_COUNT.labels(endpoint="/v1/gateway/chat", tenant_id=payload.tenant_id, outcome="blocked").inc()
        asyncio.create_task(
            audit_logger.log(
                payload.tenant_id,
                True,
                "Token not allowed for this tenant",
                "",
                [RuleAction(rule="auth.tenant_scope", action="block", detail=auth.tenant_scope or "none")],
                request_id,
                auth.subject,
                "n/a",
            )
        )
        raise HTTPException(status_code=403, detail="Token not allowed for this tenant")

    try:
        policy = policy_loader.load(payload.tenant_id)
    except Exception as exc:
        REQUEST_COUNT.labels(endpoint="/v1/gateway/chat", tenant_id=payload.tenant_id, outcome="error").inc()
        log_json(
            "policy_load_error",
            request_id=request_id,
            tenant_id=payload.tenant_id,
            error=str(exc),
        )
        raise HTTPException(status_code=500, detail="Policy load failure")
    policy_version = str(policy.get("meta", {}).get("version", "unknown"))
    applied_actions: list[RuleAction] = []

    limit = int(policy.get("rate_limit_per_minute", settings.rate_limit_per_minute))
    allowed, limit_source = await rate_limiter.check(payload.tenant_id, limit)
    if not allowed:
        applied_actions.append(
            RuleAction(rule="rate_limit", action="block", detail=f"Exceeded limit ({limit_source})")
        )
        reason = "Rate limit exceeded"
        POLICY_BLOCKS.labels(rule="rate_limit").inc()
        REQUEST_COUNT.labels(endpoint="/v1/gateway/chat", tenant_id=payload.tenant_id, outcome="blocked").inc()
        asyncio.create_task(
            audit_logger.log(
                payload.tenant_id,
                True,
                reason,
                "",
                applied_actions,
                request_id,
                auth.subject,
                policy_version,
            )
        )
        raise HTTPException(status_code=429, detail=reason)

    redacted_messages = []
    merged_text = []
    for message in payload.messages:
        redacted, pii_actions = redact_pii(message.content, policy)
        applied_actions.extend(pii_actions)

        blocked_jb, jb_actions = check_jailbreak(redacted, policy)
        applied_actions.extend(jb_actions)
        if blocked_jb:
            reason = "Blocked by jailbreak policy"
            POLICY_BLOCKS.labels(rule="jailbreak").inc()
            REQUEST_COUNT.labels(endpoint="/v1/gateway/chat", tenant_id=payload.tenant_id, outcome="blocked").inc()
            asyncio.create_task(
                audit_logger.log(
                    payload.tenant_id,
                    True,
                    reason,
                    redacted,
                    applied_actions,
                    request_id,
                    auth.subject,
                    policy_version,
                )
            )
            return GatewayResponse(blocked=True, reason=reason, applied_actions=applied_actions)
        redacted_messages.append(message.model_copy(update={"content": redacted}))
        merged_text.append(redacted)

    semantic_eval = await semantic_layer.evaluate(
        "\n".join(merged_text),
        policy,
        tenant_id=payload.tenant_id,
        request_id=request_id,
    )
    applied_actions.extend(semantic_eval.actions)
    if semantic_eval.blocked:
        reason = semantic_eval.reason or "Blocked by semantic policy"
        POLICY_BLOCKS.labels(rule="semantic.classifier").inc()
        REQUEST_COUNT.labels(endpoint="/v1/gateway/chat", tenant_id=payload.tenant_id, outcome="blocked").inc()
        asyncio.create_task(
            audit_logger.log(
                payload.tenant_id,
                True,
                reason,
                "\n".join(merged_text),
                applied_actions,
                request_id,
                auth.subject,
                policy_version,
            )
        )
        return GatewayResponse(blocked=True, reason=reason, applied_actions=applied_actions)

    try:
        upstream = await call_upstream_llm(payload.model, redacted_messages, payload.temperature)
    except Exception as exc:
        reason = f"Upstream unavailable: {exc.__class__.__name__}"
        REQUEST_COUNT.labels(endpoint="/v1/gateway/chat", tenant_id=payload.tenant_id, outcome="error").inc()
        asyncio.create_task(
            audit_logger.log(
                payload.tenant_id,
                True,
                reason,
                "\n".join(merged_text),
                applied_actions,
                request_id,
                auth.subject,
                policy_version,
            )
        )
        raise HTTPException(status_code=502, detail=reason)

    parsed_output = extract_json_content(upstream)
    ok_schema, schema_actions, schema_reason = validate_schema(parsed_output, payload.expected_schema)
    applied_actions.extend(schema_actions)
    if not ok_schema:
        POLICY_BLOCKS.labels(rule="schema.validation").inc()
        REQUEST_COUNT.labels(endpoint="/v1/gateway/chat", tenant_id=payload.tenant_id, outcome="blocked").inc()
        asyncio.create_task(
            audit_logger.log(
                payload.tenant_id,
                True,
                schema_reason,
                "\n".join(merged_text),
                applied_actions,
                request_id,
                auth.subject,
                policy_version,
            )
        )
        return GatewayResponse(blocked=True, reason=schema_reason, applied_actions=applied_actions)

    ok_math, math_actions, math_reason = validate_numeric_rules(parsed_output, payload.numeric_assertions, policy)
    applied_actions.extend(math_actions)
    if not ok_math:
        POLICY_BLOCKS.labels(rule="numeric.validation").inc()
        REQUEST_COUNT.labels(endpoint="/v1/gateway/chat", tenant_id=payload.tenant_id, outcome="blocked").inc()
        asyncio.create_task(
            audit_logger.log(
                payload.tenant_id,
                True,
                math_reason,
                "\n".join(merged_text),
                applied_actions,
                request_id,
                auth.subject,
                policy_version,
            )
        )
        return GatewayResponse(blocked=True, reason=math_reason, applied_actions=applied_actions)

    REQUEST_COUNT.labels(endpoint="/v1/gateway/chat", tenant_id=payload.tenant_id, outcome="allowed").inc()
    asyncio.create_task(
        audit_logger.log(
            payload.tenant_id,
            False,
            None,
            "\n".join(merged_text),
            applied_actions,
            request_id,
            auth.subject,
            policy_version,
        )
    )
    log_json(
        "gateway_request_allowed",
        request_id=request_id,
        tenant_id=payload.tenant_id,
        policy_version=policy_version,
        auth_mode=auth.auth_mode,
    )
    return GatewayResponse(blocked=False, upstream_response=upstream, applied_actions=applied_actions)
