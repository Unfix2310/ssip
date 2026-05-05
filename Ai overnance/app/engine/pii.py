import re
from typing import Any

from app.models import RuleAction


def luhn_checksum_ok(card_number: str) -> bool:
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def redact_pii(text: str, policy: dict[str, Any]) -> tuple[str, list[RuleAction]]:
    actions: list[RuleAction] = []
    redacted = text

    for name, pattern in policy.get("pii_patterns", {}).items():
        regex = re.compile(pattern, flags=re.IGNORECASE)
        matches = list(regex.finditer(redacted))
        if not matches:
            continue

        if name == "credit_card":
            for match in matches:
                candidate = re.sub(r"\D", "", match.group(0))
                if luhn_checksum_ok(candidate):
                    redacted = redacted.replace(match.group(0), "[REDACTED_CREDIT_CARD]")
                    actions.append(
                        RuleAction(rule="pii.credit_card", action="redact", detail="Luhn-valid card redacted")
                    )
        else:
            redacted = regex.sub(f"[REDACTED_{name.upper()}]", redacted)
            actions.append(
                RuleAction(rule=f"pii.{name}", action="redact", detail=f"{name} pattern redacted")
            )

    return redacted, actions
