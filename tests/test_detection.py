from __future__ import annotations

import sys
from pathlib import Path
import unittest

ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from detection.keyword_detector import detect_keywords
from detection.risk_score import calculate_risk
from detection.url_checker import check_urls


class DetectionTests(unittest.TestCase):
    def test_keyword_detector_finds_phishing_phrases(self) -> None:
        text = "Urgent! Verify your account immediately and click here"
        matches = detect_keywords(text)
        self.assertGreaterEqual(len(matches), 2)

    def test_url_checker_flags_shortener(self) -> None:
        text = "Please review: http://bit.ly/reset-now"
        findings = check_urls(text)
        issues = {f["issue"] for f in findings}
        self.assertIn("insecure_http", issues)
        self.assertIn("url_shortener", issues)

    def test_url_checker_flags_brand_impersonation(self) -> None:
        text = "Verify here: https://google-secure-login.com/account"
        findings = check_urls(text)
        issues = {f["issue"] for f in findings}
        self.assertIn("brand_impersonation", issues)

    def test_risk_score_flags_attachment_and_sensitive_request(self) -> None:
        text = (
            "From: billing@paypa1-security.com\n"
            "Subject: Urgent invoice\n"
            "Dear customer, verify immediatly and send your password.\n"
            "Attachment: invoice.docm"
        )
        result = calculate_risk(text, mode="heuristic")
        names = {indicator.name for indicator in result.indicators}
        self.assertIn("brand impersonation", names)
        self.assertIn("risky attachment language", names)
        self.assertIn("sensitive information request", names)
        self.assertIn("Suggested actions:", result.explanation)

    def test_risk_score_higher_for_phishing_than_legit(self) -> None:
        phishing = "From: a@fake.com\nSubject: urgent\nClick here: http://bit.ly/now"
        legit = "From: support@microsoft.com\nSubject: Receipt\nVisit https://microsoft.com"
        phishing_result = calculate_risk(phishing, mode="hybrid")
        legit_result = calculate_risk(legit, mode="hybrid")
        self.assertGreater(phishing_result.score, legit_result.score)


if __name__ == "__main__":
    unittest.main()
