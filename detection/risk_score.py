from __future__ import annotations

from .analyzer import AnalysisResult, PhishingAnalyzer


analyzer = PhishingAnalyzer()


def calculate_risk(email_text: str, mode: str = "hybrid") -> AnalysisResult:
    """Run PhishGuard risk scoring using heuristic, ml, or hybrid mode."""
    return analyzer.analyze(email_text, mode=mode)
