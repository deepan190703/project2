"""Tests for the scoring engine."""

import pytest

from app.scanners.scoring import aggregate_findings, compute_risk_score


class TestComputeRiskScore:
    def test_empty_findings_gives_zero_score_and_grade_a(self):
        score, grade = compute_risk_score([])
        assert score == 0.0
        assert grade == "A"

    def test_single_critical_finding(self):
        findings = [{"severity": "critical", "title": "Test", "description": "", "recommendation": "", "category": "ssl"}]
        score, grade = compute_risk_score(findings)
        assert score == 25.0
        assert grade == "C"

    def test_multiple_criticals_capped_at_100(self):
        findings = [{"severity": "critical"}] * 10
        score, grade = compute_risk_score(findings)
        assert score == 100.0
        assert grade == "F"

    def test_high_severity(self):
        findings = [{"severity": "high"}]
        score, grade = compute_risk_score(findings)
        assert score == 15.0
        assert grade == "B"

    def test_medium_severity(self):
        findings = [{"severity": "medium"}]
        score, grade = compute_risk_score(findings)
        assert score == 7.0
        assert grade == "A"  # below 10 threshold

    def test_low_severity(self):
        findings = [{"severity": "low"}]
        score, grade = compute_risk_score(findings)
        assert score == 3.0
        assert grade == "A"

    def test_info_severity_contributes_zero(self):
        findings = [{"severity": "info"}, {"severity": "info"}]
        score, grade = compute_risk_score(findings)
        assert score == 0.0
        assert grade == "A"

    def test_mixed_findings(self):
        findings = [
            {"severity": "critical"},  # 25
            {"severity": "high"},      # 15
            {"severity": "medium"},    # 7
            {"severity": "low"},       # 3
        ]
        score, grade = compute_risk_score(findings)
        assert score == 50.0
        assert grade == "D"

    def test_unknown_severity_treated_as_zero(self):
        findings = [{"severity": "unknown_level"}]
        score, grade = compute_risk_score(findings)
        assert score == 0.0

    def test_grade_boundaries(self):
        # Grade A: 0-9
        assert compute_risk_score([{"severity": "low"}, {"severity": "low"}, {"severity": "low"}])[1] == "A"  # 9
        # Grade B: 10-24
        assert compute_risk_score([{"severity": "high"}])[1] == "B"  # 15
        # Grade C: 25-44
        assert compute_risk_score([{"severity": "critical"}])[1] == "C"  # 25
        # Grade D: 45-64
        assert compute_risk_score([{"severity": "critical"}, {"severity": "high"}, {"severity": "medium"}])[1] == "D"  # 47
        # Grade F: 65+
        assert compute_risk_score([{"severity": "critical"}] * 3)[1] == "F"  # 75


class TestAggregateFindings:
    def test_aggregates_findings_from_all_modules(self):
        ssl    = {"findings": [{"title": "SSL issue", "severity": "critical", "category": "ssl"}]}
        hdrs   = {"findings": [{"title": "Header issue", "severity": "high", "category": "headers"}]}
        ports  = {"findings": []}
        eps    = {"findings": [{"title": "Endpoint issue", "severity": "medium", "category": "endpoints"}]}
        dns    = {"findings": [{"title": "DNS issue", "severity": "low", "category": "dns"}]}

        findings = aggregate_findings(ssl, hdrs, ports, eps, dns)
        assert len(findings) == 4
        titles = {f["title"] for f in findings}
        assert "SSL issue" in titles
        assert "Header issue" in titles
        assert "Endpoint issue" in titles
        assert "DNS issue" in titles

    def test_handles_none_results(self):
        findings = aggregate_findings(None, None, None, None, None)
        assert findings == []

    def test_handles_empty_findings_lists(self):
        empty = {"findings": []}
        findings = aggregate_findings(empty, empty, empty, empty, empty)
        assert findings == []
