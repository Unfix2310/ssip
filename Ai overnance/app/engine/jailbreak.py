import re
from typing import Any

from app.models import RuleAction


def _normalize_for_obfuscation(text: str) -> str:
    # Reduce spacing and punctuation to catch basic obfuscation variants.
    return re.sub(r"[^a-z0-9]", "", text.lower())


def check_jailbreak(text: str, policy: dict[str, Any]) -> tuple[bool, list[RuleAction]]:
    deny_list = [item.lower() for item in policy.get("jailbreak_deny_list", [])]
    lowered = text.lower()
    collapsed = _normalize_for_obfuscation(text)

    for token in deny_list:
        cleaned_token = _normalize_for_obfuscation(token)
        if token and (token in lowered or (cleaned_token and cleaned_token in collapsed)):
            return True, [
                RuleAction(
                    rule="jailbreak.deny_list",
                    action="block",
                    detail=f"Matched deny-list token: {token}",
                )
            ]

    for pattern in policy.get("jailbreak_regex_deny_list", []):
        regex = re.compile(pattern, flags=re.IGNORECASE)
        if regex.search(text):
            return True, [
                RuleAction(
                    rule="jailbreak.regex_deny_list",
                    action="block",
                    detail=f"Matched regex deny-list pattern: {pattern}",
                )
            ]

    return False, []
