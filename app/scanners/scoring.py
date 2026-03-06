"""Vulnerability severity scoring engine.

Computes a risk score (0–100) and a grade (A–F) based on scan findings.

Score weights per severity:
  critical  = 25 points each (capped at 100)
  high      = 15 points each
  medium    =  7 points each
  low       =  3 points each
  info      =  0 points each
"""

from typing import Any, Dict, List, Tuple

SEVERITY_WEIGHTS: Dict[str, int] = {
    "critical": 25,
    "high": 15,
    "medium": 7,
    "low": 3,
    "info": 0,
}

GRADE_THRESHOLDS: List[Tuple[int, str]] = [
    (0, "A"),
    (10, "B"),
    (25, "C"),
    (45, "D"),
    (65, "F"),
]


def compute_risk_score(findings: List[Dict[str, Any]]) -> Tuple[float, str]:
    """
    Compute the overall risk score and grade from a list of finding dicts.

    Returns a (score, grade) tuple where score is 0–100 (higher = riskier).
    """
    raw_score = 0
    for finding in findings:
        severity = finding.get("severity", "info").lower()
        raw_score += SEVERITY_WEIGHTS.get(severity, 0)

    # Cap at 100
    score = min(raw_score, 100)

    # Determine grade
    grade = "A"
    for threshold, g in GRADE_THRESHOLDS:
        if score >= threshold:
            grade = g

    return round(score, 1), grade


def aggregate_findings(
    ssl_results: Dict[str, Any],
    headers_results: Dict[str, Any],
    ports_results: Dict[str, Any],
    endpoints_results: Dict[str, Any],
    dns_results: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Merge findings from all scanners into a single list."""
    all_findings: List[Dict[str, Any]] = []
    for results in (ssl_results, headers_results, ports_results, endpoints_results, dns_results):
        if results and isinstance(results.get("findings"), list):
            all_findings.extend(results["findings"])
    return all_findings
