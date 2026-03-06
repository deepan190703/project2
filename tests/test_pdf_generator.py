"""Tests for the PDF report generator."""

import pytest

from app.pdf_generator import generate_pdf_report


class TestPdfGenerator:
    """Verify that generate_pdf_report returns valid PDF bytes."""

    def _sample_data(self):
        return dict(
            domain="example.com",
            risk_score=42.0,
            risk_grade="D",
            findings=[
                {
                    "title": "Missing HSTS",
                    "description": "No HSTS header found.",
                    "severity": "high",
                    "category": "headers",
                    "recommendation": "Add HSTS header.",
                },
                {
                    "title": "Risky Port Open",
                    "description": "Port 22 is open.",
                    "severity": "critical",
                    "category": "ports",
                    "recommendation": "Restrict SSH access.",
                },
            ],
            ssl_results={
                "supported": True,
                "valid": True,
                "subject": "example.com",
                "issuer": "Let's Encrypt",
                "not_after": "2025-12-31T00:00:00+00:00",
                "days_until_expiry": 200,
                "protocol_version": "TLSv1.3",
                "cipher_suite": "TLS_AES_256_GCM_SHA384",
                "findings": [],
            },
            headers_results={
                "present_headers": ["X-Frame-Options"],
                "missing_headers": ["Strict-Transport-Security"],
                "info_disclosure": [{"header": "Server", "value": "nginx"}],
                "findings": [],
            },
            ports_results={
                "open_ports": [{"port": 22, "service": "SSH", "severity": "info"}],
                "closed_ports": [],
                "findings": [],
            },
            endpoints_results={
                "discovered": [{"path": "/admin", "description": "Admin panel", "status_code": 200, "severity": "high"}],
                "findings": [],
            },
            dns_results={
                "a_records": ["93.184.216.34"],
                "mx_records": [],
                "spf": None,
                "dmarc": None,
                "has_spf": False,
                "has_dmarc": False,
                "has_caa": False,
                "findings": [],
            },
        )

    def test_returns_bytes(self):
        pdf = generate_pdf_report(**self._sample_data())
        assert isinstance(pdf, bytes)

    def test_starts_with_pdf_magic_bytes(self):
        pdf = generate_pdf_report(**self._sample_data())
        assert pdf[:4] == b"%PDF"

    def test_generates_for_zero_score(self):
        data = self._sample_data()
        data["risk_score"] = 0.0
        data["risk_grade"] = "A"
        data["findings"] = []
        pdf = generate_pdf_report(**data)
        assert pdf[:4] == b"%PDF"

    def test_generates_with_none_results(self):
        data = self._sample_data()
        data["ssl_results"] = None
        data["headers_results"] = None
        data["ports_results"] = None
        data["endpoints_results"] = None
        data["dns_results"] = None
        pdf = generate_pdf_report(**data)
        assert pdf[:4] == b"%PDF"

    def test_generates_with_all_severity_levels(self):
        data = self._sample_data()
        data["findings"] = [
            {"title": "Critical Issue", "description": "Desc", "severity": "critical", "category": "ssl", "recommendation": "Fix it."},
            {"title": "High Issue",     "description": "Desc", "severity": "high",     "category": "headers", "recommendation": "Fix it."},
            {"title": "Medium Issue",   "description": "Desc", "severity": "medium",   "category": "dns",     "recommendation": "Fix it."},
            {"title": "Low Issue",      "description": "Desc", "severity": "low",      "category": "ports",   "recommendation": "Fix it."},
            {"title": "Info",           "description": "Desc", "severity": "info",     "category": "endpoints", "recommendation": "N/A"},
        ]
        pdf = generate_pdf_report(**data)
        assert pdf[:4] == b"%PDF"
        assert len(pdf) > 5000  # Should be a non-trivial PDF
