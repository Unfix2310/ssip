"""
Regulatory LLM Extractor: converts RBI/DPSS rule text → ControlIR JSON.

Separate prompt from the access-policy extractor. Key differences:
  - Maps shall/must/required → effect: required
  - Maps shall not/must not/prohibited → effect: prohibited
  - Extracts temporal patterns (within 6 hours, every 6 months, minimum 5 years)
  - Does NOT force into read/write/admin — uses regulatory action vocabulary
  - Source attribution (document_id, section) is mandatory input
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

from dotenv import load_dotenv

load_dotenv()

from ..exceptions import LLMExtractionError

logger = logging.getLogger(__name__)

# ── System prompt ─────────────────────────────────────────────────────────────

_REGULATORY_SYSTEM_PROMPT = """\
You are a regulatory compliance parser for Indian financial regulation (RBI/DPSS). \
You extract structured control data from regulatory rule text.

You MUST respond with ONLY a valid JSON object. No markdown. No explanation. \
No preamble. No trailing text. Just raw JSON.

The JSON MUST match this exact schema:
{
  "rule_type": "<one of: obligation, prohibition, deadline_rule, frequency_rule, retention_rule, cooling_period_rule>",
  "subject": "<who must comply, lowercase. e.g. 'regulated entities', 'banks', 'payment system operators'>",
  "action": "<what must be done, lowercase. e.g. 'conduct vulnerability assessment', 'preserve audit logs', 'report incident to rbi'>",
  "resource": "<what is affected, lowercase. e.g. 'critical systems in dmz', 'audit logs', 'privileged accounts'>",
  "effect": "<one of: required, prohibited, conditional>",
  "constraints": [
    {
      "field": "<snake_case field name, e.g. 'min_directors', 'mfa_required', 'chair_independence'>",
      "operator": "<equals, not_equals, greater_than, greater_than_or_equal, less_than, less_than_or_equal, is_true, is_false>",
      "value": "<the value, e.g. '3', 'true', 'independent_director'>",
      "unit": "<years, months, days, hours, or null>",
      "description": "<human readable description>",
      "source_text": "<exact phrase from input text that produced this constraint>"
    }
  ],
  "temporal": {
    "frequency": "<recurring schedule if mentioned, e.g. 'every_6_months', 'every_12_months', 'annually', 'half_yearly', or null>",
    "deadline": "<time limit if mentioned, e.g. 'within_6_hours', 'immediately', 'within_1_month', or null>",
    "retention": "<retention period if mentioned, e.g. 'minimum_5_years', 'minimum_10_years', or null>",
    "cooling_period": "<cooling period if mentioned, e.g. '12_hours', '24_hours', or null>"
  },
  "evidence": {
    "required": true,
    "artifact_type": "<type of evidence needed, e.g. 'va_report', 'audit_trail_report', 'incident_report', or null>"
  }
}

Rules:
- rule_type mapping:
  - If the rule requires periodic action → "frequency_rule" or "obligation" (with frequency in temporal)
  - If the rule has a deadline (within X hours/days) → "deadline_rule"
  - If the rule requires retaining data for a period → "retention_rule"
  - If the rule requires a cooling/waiting period → "cooling_period_rule"
  - If the rule prohibits something → "prohibition"
  - Otherwise → "obligation"

- effect mapping:
  - "shall", "must", "required", "mandatory" → "required"
  - "shall not", "must not", "prohibited", "not permitted" → "prohibited"
  - Complex/conditional → "conditional"

- temporal mapping:
  - CRITICAL: temporal.frequency MUST be null unless the source text contains an explicit \
time interval such as 'every X months', 'at least once in X', 'on a X basis', or \
'within X hours/days'. Do NOT infer, assume, or carry over frequency from other rules. \
If the text says 'shall maintain audit trails' with no time interval, frequency is null.
  - "every six months", "half-yearly", "semi-annually" → frequency: "every_6_months"
  - "annually", "once a year", "every year", "every 12 months" → frequency: "every_12_months"
  - "quarterly", "every 3 months" → frequency: "every_3_months"
  - "within 6 hours" → deadline: "within_6_hours"
  - "immediately", "upon availability", "without delay" → deadline: "within_24_hours"
  - "within one month", "within 30 days" → deadline: "within_1_month"
  - "minimum 5 years", "at least five years" → retention: "minimum_5_years"
  - "minimum 10 years" → retention: "minimum_10_years"
  - "12 hours", "12-hour" (cooling/waiting) → cooling_period: "12_hours"
  - "24 hours" (cooling) → cooling_period: "24_hours"

- resource extraction — CRITICAL:
  - The "resource" is the OBJECT being acted upon or produced, NOT the triggering event.
  - For reporting rules: resource = the REPORT being filed, not the incident that triggers it.
  - For patching rules: resource = the SYSTEMS being patched, not the patches themselves.
  - For session rules: resource = the SYSTEMS/APPLICATIONS with session controls.
  - For cooling period rules: resource = the CREDENTIALS being changed (mobile number, email).

- evidence: always set required to true for regulatory rules
- constraints extraction — CRITICAL:
  - Extract ALL numeric thresholds (min members, years of experience, meeting intervals)
  - Extract ALL boolean requirements (independence required, MFA required, logging required)
  - Extract ALL qualitative requirements (role type, reporting line, expertise type)
  - Use snake_case for field names: "min_directors" not "minimum directors"
  - source_text MUST be the exact phrase from the input that produced this constraint
  - If no constraints exist in the text, return empty array []
  - IMPORTANT: Only extract constraints explicitly stated. Do not infer.
- All string values lowercase and trimmed
- If a field does not apply, use null or empty array

FEW-SHOT EXAMPLES:

Input: "Incidents shall be reported to RBI within 6 hours of detection."
Output:
{
  "rule_type": "deadline_rule",
  "subject": "regulated entities",
  "action": "report incident to rbi",
  "resource": "incident reports",
  "effect": "required",
  "constraints": [],
  "temporal": {"frequency": null, "deadline": "within_6_hours", "retention": null, "cooling_period": null},
  "evidence": {"required": true, "artifact_type": "incident_report"}
}
Note: resource is "incident reports" (the thing produced), NOT "cybersecurity incidents" (the trigger).

Input: "A minimum cooling period of 12 hours shall be enforced before activating a new mobile number or email address."
Output:
{
  "rule_type": "cooling_period_rule",
  "subject": "regulated entities",
  "action": "enforce cooling period",
  "resource": "mobile number or email address",
  "effect": "required",
  "constraints": [],
  "temporal": {"frequency": null, "deadline": null, "retention": null, "cooling_period": "12_hours"},
  "evidence": {"required": true, "artifact_type": "cooling_period_log"}
}

Input: "Critical patches released by the vendor must be applied immediately."
Output:
{
  "rule_type": "obligation",
  "subject": "regulated entities",
  "action": "apply critical patches",
  "resource": "payment systems",
  "effect": "required",
  "constraints": [],
  "temporal": {"frequency": null, "deadline": "within_24_hours", "retention": null, "cooling_period": null},
  "evidence": {"required": true, "artifact_type": "patch_compliance_report"}
}
Note: resource is the SYSTEMS being patched, NOT "critical patches".

Input: "The ITSC shall have minimum of three directors. The Chairperson shall be an \
independent director with minimum seven years of IT expertise. The ITSC shall meet \
at least on a quarterly basis."
Output:
{
  "rule_type": "obligation",
  "subject": "regulated entities",
  "action": "establish board-level it strategy committee",
  "resource": "it governance framework",
  "effect": "required",
  "constraints": [
    {"field": "min_directors", "operator": "greater_than_or_equal", "value": "3", "unit": null, \
"description": "Minimum three directors required on ITSC", \
"source_text": "minimum of three directors"},
    {"field": "chair_independence", "operator": "equals", "value": "independent_director", "unit": null, \
"description": "Chairperson must be an independent director", \
"source_text": "Chairperson shall be an independent director"},
    {"field": "chair_min_experience_years", "operator": "greater_than_or_equal", "value": "7", "unit": "years", \
"description": "Chair requires minimum 7 years IT experience", \
"source_text": "minimum seven years of IT expertise"},
    {"field": "meeting_frequency_days", "operator": "less_than_or_equal", "value": "90", "unit": "days", \
"description": "ITSC must meet at least quarterly", \
"source_text": "meet at least on a quarterly basis"}
  ],
  "temporal": {"frequency": "every_3_months", "deadline": null, "retention": null, "cooling_period": null},
  "evidence": {"required": true, "artifact_type": "itsc_meeting_minutes"}
}

Input: "REs shall adopt multi-factor authentication for privileged users of critical information systems."
Output:
{
  "rule_type": "obligation",
  "subject": "regulated entities",
  "action": "enforce mfa",
  "resource": "privileged accounts",
  "effect": "required",
  "constraints": [
    {"field": "mfa_required", "operator": "is_true", "value": "true", "unit": null, \
"description": "MFA mandatory for privileged users of critical systems", \
"source_text": "adopt multi-factor authentication for privileged users"}
  ],
  "temporal": {"frequency": null, "deadline": null, "retention": null, "cooling_period": null},
  "evidence": {"required": true, "artifact_type": "access_control_report"}
}

Input: "Regulated entities shall use only non-deprecated and approved cryptographic algorithms for protecting sensitive data."
Output:
{
  "rule_type": "obligation",
  "subject": "regulated entities",
  "action": "enforce cryptographic standards",
  "resource": "cryptographic algorithms",
  "effect": "required",
  "constraints": [],
  "temporal": {"frequency": null, "deadline": null, "retention": null, "cooling_period": null},
  "evidence": {"required": true, "artifact_type": "crypto_compliance_report"}
}
Note: action is "enforce cryptographic standards" (the compliance obligation), NOT "use non-deprecated cryptographic algorithms" (a description of how).
Resource is the TECHNOLOGY being regulated ("cryptographic algorithms"), not the data it protects.
"""


def _build_regulatory_prompt(
    rule_text: str,
    document_id: str = "",
    section: str = "",
    error_context: Optional[str] = None,
    parent_context: Optional[str] = None,
) -> str:
    """Build the user prompt for regulatory extraction."""
    base = f'Parse this regulatory rule:\n"{rule_text}"'
    if parent_context and parent_context != rule_text:
        base += f'\n\nThis is a sub-clause split from a compound rule. Full parent clause for context:\n"{parent_context}"'
        base += '\nUse the parent clause to resolve any missing subject or resource references.'
    if document_id:
        base += f"\n\nSource document: {document_id}"
    if section:
        base += f"\nSection: {section}"
    if error_context:
        base += f"\n\n[CORRECTION REQUIRED] Previous attempt failed: {error_context}\nFix and return valid JSON only."
    return base


def _extract_first_json_object(raw_output: str) -> str:
    """Extract the first balanced JSON object from text."""
    text = raw_output.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(line for line in lines if not line.startswith("```")).strip()

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


def _canonicalize_regulatory_shape(parsed: dict[str, Any]) -> dict[str, Any]:
    """Ensure all optional fields have safe defaults."""
    parsed.setdefault("rule_type", "obligation")
    parsed.setdefault("subject", "")
    parsed.setdefault("action", "")
    parsed.setdefault("resource", "")
    parsed.setdefault("effect", "required")

    parsed.setdefault("constraints", [])
    if parsed["constraints"] is None:
        parsed["constraints"] = []
    if not isinstance(parsed["constraints"], list):
        parsed["constraints"] = []

    parsed.setdefault("temporal", {})
    if parsed["temporal"] is None:
        parsed["temporal"] = {}
    if not isinstance(parsed["temporal"], dict):
        parsed["temporal"] = {}
    parsed["temporal"].setdefault("frequency", None)
    parsed["temporal"].setdefault("deadline", None)
    parsed["temporal"].setdefault("retention", None)
    parsed["temporal"].setdefault("cooling_period", None)

    parsed.setdefault("evidence", {})
    if parsed["evidence"] is None:
        parsed["evidence"] = {}
    if not isinstance(parsed["evidence"], dict):
        parsed["evidence"] = {}
    parsed["evidence"].setdefault("required", True)
    parsed["evidence"].setdefault("artifact_type", None)

    return parsed


def _call_gemini(messages: list[dict]) -> str:
    """Call the Google Gemini API for regulatory extraction."""
    try:
        import google.generativeai as genai
    except ImportError as exc:
        raise LLMExtractionError("google-generativeai package not installed.") from exc

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
        logger.info("[RegulatoryLLM] Model=%s", model_name)
        return response.text
    except Exception as exc:
        raise LLMExtractionError(f"Gemini API call failed: {exc}") from exc


def extract_control_ir(
    rule_text: str,
    document_id: str = "",
    section: str = "",
    error_context: Optional[str] = None,
    parent_context: Optional[str] = None,
) -> dict[str, Any]:
    """
    Extract structured ControlIR from RBI/DPSS regulatory rule text.

    Args:
        rule_text:      The raw regulatory rule sentence.
        document_id:    Source document identifier (e.g., "RBI/2023-24/107").
        section:        Section number (e.g., "26").
        error_context:  Error message from a previous failed attempt (retry path).
        parent_context:  Full text of parent clause (for compound sub-clauses).

    Returns:
        Parsed dict matching the ControlIR extraction schema.

    Raises:
        LLMExtractionError: On API failure or JSON parse failure.
    """
    user_message = _build_regulatory_prompt(
        rule_text, document_id, section, error_context, parent_context
    )

    messages = [
        {"role": "system", "content": _REGULATORY_SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ]

    logger.info("[RegulatoryLLM] Extracting control (doc=%s §%s, retry=%s).",
                document_id, section, bool(error_context))

    raw_output = _call_gemini(messages)
    logger.debug("[RegulatoryLLM] Raw output: %s", raw_output)

    cleaned = _extract_first_json_object(raw_output)

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise LLMExtractionError(
            f"LLM returned non-JSON: {exc}\nRaw: {raw_output[:300]}"
        ) from exc

    if not isinstance(parsed, dict):
        raise LLMExtractionError("LLM JSON is not an object.")

    parsed = _canonicalize_regulatory_shape(parsed)

    logger.info("[RegulatoryLLM] Extraction successful: rule_type=%s effect=%s action=%r",
                parsed.get("rule_type"), parsed.get("effect"), parsed.get("action"))
    return parsed
