from __future__ import annotations

import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {".zip", ".xyz", ".top", ".click", ".work", ".country", ".gq", ".tk"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "ow.ly", "rb.gy"}

URL_REGEX = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)


def extract_urls(email_text: str) -> list[str]:
    return URL_REGEX.findall(email_text)


def check_urls(email_text: str) -> list[dict[str, str | int]]:
    """Inspect URLs for common phishing indicators."""
    findings: list[dict[str, str | int]] = []

    for url in extract_urls(email_text):
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if parsed.scheme == "http":
            findings.append({"url": url, "issue": "insecure_http", "weight": 15})

        if domain in URL_SHORTENERS:
            findings.append({"url": url, "issue": "url_shortener", "weight": 20})

        if domain.endswith(tuple(SUSPICIOUS_TLDS)):
            findings.append({"url": url, "issue": "suspicious_tld", "weight": 15})

        if domain.count(".") >= 3:
            findings.append({"url": url, "issue": "excessive_subdomains", "weight": 10})

    return findings
