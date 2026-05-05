import asyncio
import json
from typing import Any

import httpx

from app.config import settings
from app.models import Message
from app.services.circuit_breaker import CircuitBreaker
from app.services.observability import UPSTREAM_ERRORS

upstream_circuit_breaker = CircuitBreaker(
    failure_threshold=settings.cb_failure_threshold,
    recovery_seconds=settings.cb_recovery_seconds,
)


def _is_retryable_status(code: int) -> bool:
    return code == 429 or 500 <= code <= 599


async def call_upstream_llm(
    model: str,
    messages: list[Message],
    temperature: float | None,
) -> dict[str, Any]:
    if not upstream_circuit_breaker.allow_request():
        raise RuntimeError("Upstream circuit is open")

    payload: dict[str, Any] = {
        "model": model,
        "messages": [m.model_dump() for m in messages],
    }
    if temperature is not None:
        payload["temperature"] = temperature

    headers = {
        "Authorization": f"Bearer {settings.upstream_llm_api_key}",
        "Content-Type": "application/json",
    }

    max_attempts = settings.llm_max_retries + 1
    last_error: Exception | None = None

    for attempt in range(max_attempts):
        try:
            async with httpx.AsyncClient(timeout=settings.llm_timeout_seconds) as client:
                response = await client.post(settings.upstream_llm_url, json=payload, headers=headers)
            if response.status_code >= 400:
                error = httpx.HTTPStatusError(
                    message="upstream status error",
                    request=response.request,
                    response=response,
                )
                if _is_retryable_status(response.status_code) and attempt < max_attempts - 1:
                    UPSTREAM_ERRORS.labels(error_type=f"http_{response.status_code}").inc()
                    await asyncio.sleep(settings.llm_retry_backoff_seconds * (2**attempt))
                    continue
                raise error

            upstream_circuit_breaker.record_success()
            return response.json()
        except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError, RuntimeError) as exc:
            last_error = exc
            UPSTREAM_ERRORS.labels(error_type=exc.__class__.__name__).inc()
            if attempt < max_attempts - 1:
                await asyncio.sleep(settings.llm_retry_backoff_seconds * (2**attempt))
                continue
            upstream_circuit_breaker.record_failure()
            raise

    upstream_circuit_breaker.record_failure()
    if last_error:
        raise last_error
    raise RuntimeError("Unknown upstream failure")

def extract_json_content(upstream_payload: dict[str, Any]) -> dict[str, Any]:
    if isinstance(upstream_payload.get("output_text"), str):
        try:
            return json.loads(upstream_payload["output_text"])
        except Exception:
            pass

    choices = upstream_payload.get("choices", [])
    if not choices:
        return {}

    message = choices[0].get("message", {})
    content = message.get("content", "")
    if isinstance(content, list):
        # Handle structured content array responses.
        for part in content:
            if isinstance(part, dict) and "text" in part:
                content = part["text"]
                break
    if isinstance(content, dict):
        return content
    if not isinstance(content, str):
        return {}

    try:
        return json.loads(content)
    except Exception:
        return {}
