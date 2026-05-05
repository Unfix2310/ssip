"""
LLM Extraction Layer: converts natural language → strict IR JSON.
The prompt is engineered to suppress ALL non-JSON output.

Uses Google Gemini API (default: gemini-2.5-flash, configurable via GEMINI_MODEL env var).
Extended prompt requests temporal, scope, and exception fields.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional
from dotenv import load_dotenv

load_dotenv()

from .exceptions import LLMExtractionError

logger = logging.getLogger(__name__)

# ── System prompt ─────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a security policy parser. You extract structured data from natural language \
security policy statements. 

You MUST respond with ONLY a valid JSON object. No markdown. No explanation. \
No preamble. No trailing text. Just raw JSON.

The JSON MUST match this exact schema:
{
  "principal_intent": "<who is being granted access, lowercase>",
  "action_intent": "<exactly one of: read, write, admin>",
  "resource_intent": "<what resource, lowercase>",
  "effect": "<one of: permit, deny, conditional>",
  "conditions": {
    "network_restriction": "<CIDR or IP string, or null>",
    "time_restriction": "<time range string, or null>"
  },
  "temporal": {
    "valid_from": "<ISO 8601 datetime if mentioned, or null>",
    "valid_until": "<ISO 8601 datetime if mentioned, or null>",
    "recurrence": "<recurrence pattern if mentioned, e.g. 'weekdays 09:00-18:00', or null>"
  },
  "scope": {
    "org_unit": "<organizational unit if mentioned, e.g. 'engineering', or null>",
    "environment": "<one of: production, staging, development, testing, or null>",
    "region": "<cloud region if mentioned, e.g. 'ap-south-1', or null>"
  },
  "exceptions": ["<list of exception descriptions, or empty array>"]
}

Rules:
- action_intent MUST be exactly "read", "write", or "admin". Never any other word.
- Map synonyms: view/get/list/fetch/access → "read"; create/update/put/delete/modify → "write"; manage/control/administer → "admin"
- effect: use "permit" for allow/grant statements, "deny" for deny/block/prevent statements, "conditional" if the policy has complex conditions
- All string values lowercase and trimmed
- If no condition, temporal, scope, or exception applies, use null or empty array
- temporal: only extract dates/times explicitly mentioned in the policy
- scope: only extract org/env/region explicitly mentioned in the policy
- exceptions: extract any "except", "unless", "excluding" clauses
"""

_KEY_ALIASES: dict[str, str] = {
    "principal": "principal_intent",
    "subject": "principal_intent",
    "who": "principal_intent",
    "action": "action_intent",
    "operation": "action_intent",
    "resource": "resource_intent",
    "object": "resource_intent",
}


def _build_user_prompt(input_text: str, error_context: Optional[str] = None) -> str:
    """Construct the user-turn message, optionally with retry error context."""
    base = f'Parse this security policy statement:\n"{input_text}"'
    if error_context:
        base += f"\n\n[CORRECTION REQUIRED] Previous attempt failed: {error_context}\nFix and return valid JSON only."
    return base


def _extract_first_json_object(raw_output: str) -> str:
    """
    Return the first balanced JSON object found in text.
    This makes extraction robust when the model wraps JSON with extra text.
    """
    text = raw_output.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(line for line in lines if not line.startswith("```")).strip()

    # Fast path: already a valid object string.
    if text.startswith("{") and text.endswith("}"):
        return text

    start = text.find("{")
    if start == -1:
        return text

    depth = 0
    in_string = False
    escaped = False
    for idx, ch in enumerate(text[start:], start=start):
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : idx + 1]

    return text


def _canonicalize_ir_shape(parsed: dict[str, Any]) -> dict[str, Any]:
    """Normalize common key variants and ensure optional shape defaults."""
    canonical: dict[str, Any] = {}
    for key, value in parsed.items():
        mapped = _KEY_ALIASES.get(key, key)
        canonical[mapped] = value

    # ── Conditions defaults ───────────────────────────────────────────────────
    canonical.setdefault("conditions", {})
    if canonical["conditions"] is None:
        canonical["conditions"] = {}
    if not isinstance(canonical["conditions"], dict):
        canonical["conditions"] = {}
    canonical["conditions"].setdefault("network_restriction", None)
    canonical["conditions"].setdefault("time_restriction", None)

    # ── Temporal defaults ─────────────────────────────────────────────────────
    canonical.setdefault("temporal", {})
    if canonical["temporal"] is None:
        canonical["temporal"] = {}
    if not isinstance(canonical["temporal"], dict):
        canonical["temporal"] = {}
    canonical["temporal"].setdefault("valid_from", None)
    canonical["temporal"].setdefault("valid_until", None)
    canonical["temporal"].setdefault("recurrence", None)

    # ── Scope defaults ────────────────────────────────────────────────────────
    canonical.setdefault("scope", {})
    if canonical["scope"] is None:
        canonical["scope"] = {}
    if not isinstance(canonical["scope"], dict):
        canonical["scope"] = {}
    canonical["scope"].setdefault("org_unit", None)
    canonical["scope"].setdefault("environment", None)
    canonical["scope"].setdefault("region", None)

    # ── Exceptions defaults ───────────────────────────────────────────────────
    canonical.setdefault("exceptions", [])
    if canonical["exceptions"] is None:
        canonical["exceptions"] = []
    if not isinstance(canonical["exceptions"], list):
        canonical["exceptions"] = []

    # ── Effect default ────────────────────────────────────────────────────────
    canonical.setdefault("effect", "permit")

    return canonical


def _call_gemini(messages: list[dict]) -> str:
    """
    Call the Google Gemini API for structured extraction.
    Reads GEMINI_API_KEY from environment.
    """
    try:
        import google.generativeai as genai
    except ImportError as exc:
        raise LLMExtractionError(
            "google-generativeai package not installed. Run: pip install google-generativeai"
        ) from exc

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise LLMExtractionError("GEMINI_API_KEY environment variable is not set.")

    model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        model_name=model_name,
        generation_config=genai.types.GenerationConfig(
            temperature=0.0,
            response_mime_type="application/json",
        ),
    )

    # Combine system + user messages into a single prompt for Gemini
    system_text = messages[0]["content"] if messages[0]["role"] == "system" else ""
    user_text = messages[-1]["content"]
    full_prompt = f"{system_text}\n\n{user_text}" if system_text else user_text

    try:
        response = model.generate_content(full_prompt)
        logger.info("[LLM] Model=%s", model_name)
        return response.text
    except Exception as exc:
        raise LLMExtractionError(f"Gemini API call failed: {exc}") from exc


def extract_policy_ir(
    input_text: str,
    error_context: Optional[str] = None,
) -> dict[str, Any]:
    """
    Send input to LLM and extract strict JSON IR.

    Args:
        input_text:    Raw natural language policy statement.
        error_context: Optional error message from previous failed attempt (retry path).

    Returns:
        Parsed Python dict matching the extended IR schema.

    Raises:
        LLMExtractionError: On API failure or JSON parse failure.
    """
    user_message = _build_user_prompt(input_text, error_context)
    
    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_message}
    ]

    logger.info("[LLM] Sending extraction request (retry_context=%s).", bool(error_context))

    raw_output = _call_gemini(messages)

    logger.debug("[LLM] Raw output: %s", raw_output)

    cleaned = _extract_first_json_object(raw_output)

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise LLMExtractionError(
            f"LLM returned non-JSON output: {exc}\nRaw: {raw_output[:300]}"
        ) from exc

    if not isinstance(parsed, dict):
        raise LLMExtractionError("LLM JSON is not an object.")

    parsed = _canonicalize_ir_shape(parsed)

    logger.info("[LLM] Extraction successful (fields: %s).", list(parsed.keys()))
    return parsed
