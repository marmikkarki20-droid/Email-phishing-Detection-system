from __future__ import annotations

from dataclasses import dataclass
import math
import re

from detection.keyword_detector import detect_keywords
from detection.url_checker import check_urls, extract_urls

EMAIL_REGEX = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
HEADER_FROM_REGEX = re.compile(r"^from:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
HEADER_REPLY_TO_REGEX = re.compile(r"^reply-to:\s*(.+)$", re.IGNORECASE | re.MULTILINE)

TRUSTED_BRANDS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
}

TOKEN_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_'-]{2,}")


@dataclass
class Indicator:
    name: str
    points: int
    evidence: str


@dataclass
class MLResult:
    phishing_probability: float
    label: str
    confidence: float


@dataclass
class AnalysisResult:
    score: int
    risk_level: str
    indicators: list[Indicator]
    urls: list[str]
    explanation: str
    analysis_mode: str
    ml_result: MLResult | None


class NaiveBayesPhishingModel:
    def __init__(self) -> None:
        self.class_docs = {"phishing": 0, "legit": 0}
        self.class_tokens = {"phishing": 0, "legit": 0}
        self.word_counts: dict[str, dict[str, int]] = {"phishing": {}, "legit": {}}
        self.vocab: set[str] = set()
        self._train()

    def _train(self) -> None:
        phishing = [
            "urgent verify your account immediately login now click here",
            "final warning account suspended confirm identity",
            "wire transfer confidential payment required",
            "security alert unusual sign in click link",
            "update billing now avoid interruption",
            "open attachment and enable content invoice",
        ]
        legit = [
            "monthly statement attached for your records",
            "team meeting moved to monday",
            "subscription receipt available in dashboard",
            "project update and sprint planning notes",
            "welcome your account setup is complete",
            "support ticket resolved successfully",
        ]
        for text in phishing:
            self._add("phishing", text)
        for text in legit:
            self._add("legit", text)

    def _tokens(self, text: str) -> list[str]:
        return [t.lower() for t in TOKEN_RE.findall(text)]

    def _add(self, klass: str, text: str) -> None:
        tokens = self._tokens(text)
        self.class_docs[klass] += 1
        self.class_tokens[klass] += len(tokens)
        counts = self.word_counts[klass]
        for token in tokens:
            counts[token] = counts.get(token, 0) + 1
            self.vocab.add(token)

    def predict(self, text: str) -> MLResult:
        tokens = self._tokens(text)
        total_docs = self.class_docs["phishing"] + self.class_docs["legit"]
        vocab_size = max(1, len(self.vocab))
        scores: dict[str, float] = {}

        for klass in ("phishing", "legit"):
            prior = self.class_docs[klass] / total_docs
            log_p = math.log(prior)
            token_total = self.class_tokens[klass]
            counts = self.word_counts[klass]
            for token in tokens:
                token_count = counts.get(token, 0)
                like = (token_count + 1) / (token_total + vocab_size)
                log_p += math.log(like)
            scores[klass] = log_p

        delta = max(min(scores["phishing"] - scores["legit"], 50), -50)
        p = 1.0 / (1.0 + math.exp(-delta))
        label = "phishing" if p >= 0.5 else "legit"
        return MLResult(phishing_probability=p, label=label, confidence=abs(p - 0.5) * 2)


_ml_model = NaiveBayesPhishingModel()


def _extract_domain(header_text: str) -> str:
    match = EMAIL_REGEX.search(header_text)
    return match.group(1).lower() if match else ""


def _heuristic_indicators(email_text: str) -> list[Indicator]:
    lowered = email_text.lower()
    out: list[Indicator] = []

    for hit in detect_keywords(email_text):
        out.append(Indicator("Phishing Keyword", int(hit["weight"]), f"Matched phrase: '{hit['keyword']}'"))

    for finding in check_urls(email_text):
        issue = str(finding["issue"]) 
        weight = int(finding["weight"])
        url = str(finding["url"])
        out.append(Indicator(issue.replace("_", " ").title(), weight, f"URL indicator in {url}"))

        domain = url.split("//", 1)[-1].split("/", 1)[0].lower()
        compact = domain.replace("-", "").replace(".", "")
        for brand, legit_domain in TRUSTED_BRANDS.items():
            if brand in compact and legit_domain not in domain:
                out.append(
                    Indicator(
                        "Potential Brand Impersonation",
                        20,
                        f"Domain {domain} differs from expected {legit_domain}",
                    )
                )

    from_line = HEADER_FROM_REGEX.search(email_text)
    reply_line = HEADER_REPLY_TO_REGEX.search(email_text)
    from_domain = _extract_domain(from_line.group(1) if from_line else "")
    reply_domain = _extract_domain(reply_line.group(1) if reply_line else "")

    if from_domain and reply_domain and from_domain != reply_domain:
        out.append(Indicator("Sender Mismatch", 20, f"From {from_domain} differs from Reply-To {reply_domain}"))

    urgent_hits = [t for t in ["immediately", "within 24 hours", "final warning", "urgent action"] if t in lowered]
    if urgent_hits:
        out.append(Indicator("Urgency Language", min(15, 5 * len(urgent_hits)), f"Detected: {', '.join(urgent_hits)}"))

    risky = [t for t in [".exe", ".scr", ".js", ".vbs", "enable content", "macro enabled"] if t in lowered]
    if risky:
        out.append(Indicator("Risky Attachment Language", min(20, len(risky) * 6), f"Detected: {', '.join(risky)}"))

    return out


def _risk_level(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def calculate_risk(email_text: str, mode: str = "hybrid") -> AnalysisResult:
    normalized = mode.strip().lower() if mode else "hybrid"
    if normalized not in {"heuristic", "ml", "hybrid"}:
        normalized = "hybrid"

    indicators: list[Indicator] = []
    heuristic_score = 0
    ml_result: MLResult | None = None

    if normalized in {"heuristic", "hybrid"}:
        indicators.extend(_heuristic_indicators(email_text))
        heuristic_score = min(sum(item.points for item in indicators), 100)

    if normalized in {"ml", "hybrid"}:
        ml_result = _ml_model.predict(email_text)
        ml_score = int(round(ml_result.phishing_probability * 100))
        if normalized == "ml":
            score = ml_score
            indicators.append(
                Indicator(
                    "ML Classifier",
                    ml_score,
                    f"ML predicted {ml_result.label} with confidence {ml_result.confidence:.2f}",
                )
            )
        else:
            score = int(round((heuristic_score * 0.7) + (ml_score * 0.3)))
            indicators.append(
                Indicator(
                    "ML Assist",
                    min(12, int(round(ml_result.confidence * 12))),
                    f"ML probability={ml_result.phishing_probability:.2f}, label={ml_result.label}",
                )
            )
    else:
        score = heuristic_score

    score = min(score, 100)
    risk = _risk_level(score)
    urls = extract_urls(email_text)
    top = sorted(indicators, key=lambda x: x.points, reverse=True)[:4]
    lines = [f"Risk Level: {risk}", f"Analysis Mode: {normalized.title()}", "Top reasons:"]
    for item in top:
        lines.append(f"- {item.name}: {item.evidence} (+{item.points})")
    if ml_result:
        lines.append(
            f"ML signal: {ml_result.label} ({ml_result.phishing_probability:.2f} phishing probability, confidence={ml_result.confidence:.2f})"
        )

    return AnalysisResult(
        score=score,
        risk_level=risk,
        indicators=indicators,
        urls=urls,
        explanation="\n".join(lines),
        analysis_mode=normalized,
        ml_result=ml_result,
    )
