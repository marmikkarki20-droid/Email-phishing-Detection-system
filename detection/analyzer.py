from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable

from .keyword_detector import detect_keywords
from .url_checker import check_urls, extract_urls


@dataclass(frozen=True)
class Indicator:
    name: str
    points: int
    evidence: str


@dataclass(frozen=True)
class MLResult:
    phishing_probability: float
    label: str
    confidence: float


@dataclass(frozen=True)
class AnalysisResult:
    score: int
    risk_level: str
    analysis_mode: str
    indicators: list[Indicator]
    urls: list[str]
    explanation: str
    ml_result: MLResult | None = None


class PhishingAnalyzer:
    _BRAND_DOMAINS = {
        "paypal": "paypal.com",
        "google": "google.com",
        "microsoft": "microsoft.com",
        "apple": "apple.com",
        "amazon": "amazon.com",
        "netflix": "netflix.com",
        "facebook": "facebook.com",
        "instagram": "instagram.com",
        "outlook": "outlook.com",
    }

    _URGENCY_PATTERNS = (
        r"\burgent\b",
        r"\bimmediately\b",
        r"\bact now\b",
        r"\bwithin \d+ (?:hours?|days?)\b",
        r"\bverify your account\b",
        r"\blogin immediately\b",
    )

    _SENDER_PATTERN = re.compile(r"^From:\s*(?P<sender>.+)$", re.IGNORECASE | re.MULTILINE)
    _REPLY_TO_PATTERN = re.compile(r"^Reply-To:\s*(?P<reply_to>.+)$", re.IGNORECASE | re.MULTILINE)
    _SUBJECT_PATTERN = re.compile(r"^Subject:\s*(?P<subject>.+)$", re.IGNORECASE | re.MULTILINE)
    _EMAIL_DOMAIN_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@(?P<domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
    _RISKY_ATTACHMENT_PATTERN = re.compile(
        r"(?:attachment|filename|attached|file).{0,80}\.(?:exe|scr|js|vbs|bat|cmd|ps1|zip|docm|xlsm)|"
        r"\b(?:enable macros|enable content|macro-enabled|invoice attached)\b",
        re.IGNORECASE,
    )
    _GRAMMAR_WARNING_PATTERN = re.compile(
        r"\b(?:kindly|dear customer|click below link|verify immediatly|immediatly|recieve|securty|acount|"
        r"pasword|your account has been suspend|failure to comply)\b|!{3,}|[A-Z]{18,}",
        re.IGNORECASE,
    )
    _SENSITIVE_INFO_PATTERN = re.compile(
        r"\b(?:password|credit card|card number|bank account|social security|ssn|otp|2fa code|security code|"
        r"confirm identity|verify identity|update billing)\b",
        re.IGNORECASE,
    )

    def analyze(self, email_text: str, mode: str = "hybrid") -> AnalysisResult:
        normalized = (mode or "hybrid").strip().lower()
        if normalized not in {"heuristic", "ml", "hybrid"}:
            normalized = "hybrid"
        indicators = self._heuristic_indicators(email_text) if normalized in {"heuristic", "hybrid"} else []
        heuristic_score = min(sum(indicator.points for indicator in indicators), 100)

        ml_result: MLResult | None = None
        ml_score = 0
        if normalized in {"ml", "hybrid"}:
            ml_result = self._predict_ml(email_text, indicators)
            ml_score = int(round(ml_result.phishing_probability * 100))

        if normalized == "ml":
            score = ml_score
        elif normalized == "heuristic":
            score = heuristic_score
        else:
            score = min(int(round(0.65 * heuristic_score + 0.35 * ml_score)), 100)

        risk_level = self._risk_level(score)
        urls = extract_urls(email_text)
        explanation = self._build_explanation(score, risk_level, indicators, urls, ml_result, normalized)

        return AnalysisResult(
            score=score,
            risk_level=risk_level,
            analysis_mode=normalized,
            indicators=indicators,
            urls=urls,
            explanation=explanation,
            ml_result=ml_result,
        )

    def _heuristic_indicators(self, email_text: str) -> list[Indicator]:
        indicators: list[Indicator] = []
        lowered = email_text.lower()

        for match in detect_keywords(email_text):
            indicators.append(
                Indicator(
                    name="keyword",
                    points=int(match["weight"]),
                    evidence=f"Matched phrase '{match['keyword']}'",
                )
            )

        for finding in check_urls(email_text):
            indicators.append(
                Indicator(
                    name=str(finding["issue"]).replace("_", " "),
                    points=int(finding["weight"]),
                    evidence=str(finding["url"]),
                )
            )

        sender = self._extract(self._SENDER_PATTERN, email_text)
        reply_to = self._extract(self._REPLY_TO_PATTERN, email_text)
        subject = self._extract(self._SUBJECT_PATTERN, email_text)

        if sender and reply_to and sender.lower() != reply_to.lower():
            indicators.append(Indicator(name="sender mismatch", points=18, evidence=f"From {sender} vs Reply-To {reply_to}"))

        for header_name, header_value in (("sender", sender), ("reply-to", reply_to)):
            if not header_value:
                continue
            domain = self._extract_domain(header_value)
            brand = self._impersonated_brand(domain)
            if brand:
                indicators.append(
                    Indicator(
                        name="brand impersonation",
                        points=20,
                        evidence=f"{header_name} domain {domain} resembles {brand} but is not {self._BRAND_DOMAINS[brand]}",
                    )
                )

        if subject and any(re.search(pattern, lowered, flags=re.IGNORECASE) for pattern in self._URGENCY_PATTERNS):
            indicators.append(Indicator(name="urgency language", points=12, evidence=subject))

        if self._SENSITIVE_INFO_PATTERN.search(email_text):
            indicators.append(Indicator(name="sensitive information request", points=12, evidence="Requests credentials, identity, payment, or security codes"))

        if self._RISKY_ATTACHMENT_PATTERN.search(email_text):
            indicators.append(Indicator(name="risky attachment language", points=16, evidence="Mentions executable, macro, archive, or script attachment risk"))

        if self._GRAMMAR_WARNING_PATTERN.search(email_text):
            indicators.append(Indicator(name="poor grammar or spelling", points=6, evidence="Common phishing wording, misspelling, or aggressive formatting detected"))

        return indicators

    def _predict_ml(self, email_text: str, indicators: Iterable[Indicator]) -> MLResult:
        text = email_text.lower()
        score = 0.15

        score += min(len(extract_urls(email_text)) * 0.1, 0.2)
        score += min(sum(indicator.points for indicator in indicators) / 200, 0.35)

        if re.search(r"\burgent\b|\bimmediately\b|\bact now\b", text):
            score += 0.1
        if re.search(r"\bverify\b|\bconfirm\b|\blogin\b", text):
            score += 0.08
        if re.search(r"\bfree\b|\breward\b|\bgift card\b", text):
            score += 0.05
        if self._RISKY_ATTACHMENT_PATTERN.search(email_text):
            score += 0.08
        if self._SENSITIVE_INFO_PATTERN.search(email_text):
            score += 0.08

        probability = max(0.0, min(score, 0.99))
        label = "phishing" if probability >= 0.5 else "legitimate"
        confidence = probability if label == "phishing" else 1 - probability
        return MLResult(phishing_probability=probability, label=label, confidence=round(confidence, 2))

    @staticmethod
    def _extract(pattern: re.Pattern[str], email_text: str) -> str | None:
        match = pattern.search(email_text)
        return match.group(1).strip() if match else None

    def _extract_domain(self, header_text: str) -> str:
        match = self._EMAIL_DOMAIN_PATTERN.search(header_text)
        return match.group("domain").lower() if match else ""

    def _impersonated_brand(self, domain: str) -> str | None:
        compact_domain = domain.replace("-", "").replace(".", "").replace("1", "l").replace("0", "o")
        for brand, trusted_domain in self._BRAND_DOMAINS.items():
            if brand in compact_domain and not domain.endswith(trusted_domain):
                return brand
        return None

    @staticmethod
    def _risk_level(score: int) -> str:
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 35:
            return "Medium"
        return "Low"

    def _build_explanation(
        self,
        score: int,
        risk_level: str,
        indicators: list[Indicator],
        urls: list[str],
        ml_result: MLResult | None,
        mode: str,
    ) -> str:
        lines = [f"Risk score: {score}/100 ({risk_level}).", f"Detection mode: {mode.title()}."]
        if indicators:
            lines.append(f"Heuristic indicators found: {len(indicators)}.")
            for indicator in indicators[:6]:
                lines.append(f"- {indicator.name}: {indicator.evidence} (+{indicator.points})")
        if urls:
            lines.append(f"URLs extracted: {len(urls)}.")
        if ml_result:
            lines.append(
                f"ML signal: {ml_result.label} ({ml_result.phishing_probability:.2f} probability, {ml_result.confidence:.2f} confidence)."
            )
        if not indicators and not urls and not ml_result:
            lines.append("No strong phishing indicators were detected.")
        lines.append("Suggested actions:")
        if score >= 60:
            lines.extend(
                [
                    "- Do not click links or open attachments.",
                    "- Verify the sender through a trusted channel.",
                    "- Report the email to IT/security.",
                ]
            )
        elif score >= 35:
            lines.extend(
                [
                    "- Treat the email as suspicious until verified.",
                    "- Check links and sender details before responding.",
                ]
            )
        else:
            lines.append("- Continue normal caution and verify unexpected requests.")
        return "\n".join(lines)
