from __future__ import annotations

import re

PHISHING_KEYWORDS: dict[str, int] = {
    "verify your account": 12,
    "login immediately": 12,
    "urgent": 8,
    "account suspended": 15,
    "password reset": 10,
    "click here": 10,
    "update billing": 12,
    "confirm identity": 10,
    "security alert": 8,
    "wire transfer": 15,
    "gift card": 12,
    "confidential": 8,
    "act now": 8,
}


def detect_keywords(email_text: str) -> list[dict[str, int | str]]:
    """Find phishing phrases and return weighted matches."""
    found: list[dict[str, int | str]] = []
    lowered = email_text.lower()

    for phrase, weight in PHISHING_KEYWORDS.items():
        if re.search(re.escape(phrase), lowered):
            found.append({"keyword": phrase, "weight": weight})

    return found
