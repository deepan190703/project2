"""Tests for the DNS configuration scanner."""

import asyncio
from unittest.mock import patch, MagicMock

import pytest

from app.scanners.dns_scanner import scan_dns


def _run(coro):
    """Run an async coroutine in a fresh event loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _patch_resolve(records_map: dict):
    """
    Return a patched version of _resolve that returns records from *records_map*.

    records_map: { ("example.com", "A"): ["93.184.216.34"], ... }
    """

    async def fake_resolve(domain, record_type):
        return records_map.get((domain, record_type), [])

    return patch("app.scanners.dns_scanner._resolve", side_effect=fake_resolve)


class TestDnsScanner:
    def test_all_records_present(self):
        records = {
            ("example.com", "A"): ["93.184.216.34"],
            ("example.com", "AAAA"): ["2606:2800:220:1:248:1893:25c8:1946"],
            ("example.com", "MX"): ["10 mail.example.com."],
            ("example.com", "NS"): ["ns1.example.com."],
            ("example.com", "TXT"): ['"v=spf1 include:_spf.google.com ~all"'],
            ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
            ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=quarantine"'],
        }
        with _patch_resolve(records):
            result = _run(scan_dns("example.com"))

        assert result["a_records"] == ["93.184.216.34"]
        assert result["has_spf"] is True
        assert result["has_dmarc"] is True
        assert result["has_caa"] is True
        # With everything present, only informational findings should exist
        critical = [f for f in result["findings"] if f["severity"] == "critical"]
        assert len(critical) == 0

    def test_no_dns_records_generates_critical_finding(self):
        with _patch_resolve({}):
            result = _run(scan_dns("nonexistent.invalid"))

        assert result["a_records"] == []
        critical = [
            f for f in result["findings"]
            if f["severity"] == "critical" and "a/aaaa" in f["title"].lower()
        ]
        assert len(critical) >= 1

    def test_missing_spf_generates_finding(self):
        records = {
            ("example.com", "A"): ["1.2.3.4"],
            ("example.com", "TXT"): [],  # No SPF
        }
        with _patch_resolve(records):
            result = _run(scan_dns("example.com"))

        assert result["has_spf"] is False
        spf_findings = [
            f for f in result["findings"]
            if "spf" in f["title"].lower()
        ]
        assert len(spf_findings) >= 1
        assert spf_findings[0]["severity"] == "medium"

    def test_missing_dmarc_generates_finding(self):
        records = {
            ("example.com", "A"): ["1.2.3.4"],
            ("_dmarc.example.com", "TXT"): [],  # No DMARC
        }
        with _patch_resolve(records):
            result = _run(scan_dns("example.com"))

        assert result["has_dmarc"] is False
        dmarc_findings = [
            f for f in result["findings"]
            if "dmarc" in f["title"].lower()
        ]
        assert len(dmarc_findings) >= 1
        assert dmarc_findings[0]["severity"] == "medium"

    def test_missing_caa_generates_finding(self):
        records = {
            ("example.com", "A"): ["1.2.3.4"],
            ("example.com", "CAA"): [],  # No CAA
        }
        with _patch_resolve(records):
            result = _run(scan_dns("example.com"))

        assert result["has_caa"] is False
        caa_findings = [
            f for f in result["findings"]
            if "caa" in f["title"].lower()
        ]
        assert len(caa_findings) >= 1
        assert caa_findings[0]["severity"] == "low"

    def test_spf_too_permissive(self):
        records = {
            ("example.com", "A"): ["1.2.3.4"],
            ("example.com", "TXT"): ['"v=spf1 +all"'],
        }
        with _patch_resolve(records):
            result = _run(scan_dns("example.com"))

        assert result["has_spf"] is True
        permissive = [
            f for f in result["findings"]
            if "+all" in f["title"].lower() or "permissive" in f["title"].lower()
        ]
        assert len(permissive) >= 1
        assert permissive[0]["severity"] == "high"

    def test_finding_has_required_fields(self):
        with _patch_resolve({}):
            result = _run(scan_dns("test.invalid"))

        assert len(result["findings"]) > 0
        for finding in result["findings"]:
            assert "title" in finding
            assert "description" in finding
            assert "severity" in finding
            assert "category" in finding
            assert "recommendation" in finding
            assert finding["category"] == "dns"

    def test_mx_records_populated(self):
        records = {
            ("example.com", "A"): ["1.2.3.4"],
            ("example.com", "MX"): ["10 mail.example.com.", "20 mail2.example.com."],
        }
        with _patch_resolve(records):
            result = _run(scan_dns("example.com"))

        assert len(result["mx_records"]) == 2

    def test_ns_records_populated(self):
        records = {
            ("example.com", "A"): ["1.2.3.4"],
            ("example.com", "NS"): ["ns1.example.com.", "ns2.example.com."],
        }
        with _patch_resolve(records):
            result = _run(scan_dns("example.com"))

        assert len(result["ns_records"]) == 2

    def test_spf_record_value_stored(self):
        spf_value = '"v=spf1 include:_spf.google.com ~all"'
        records = {
            ("example.com", "A"): ["1.2.3.4"],
            ("example.com", "TXT"): [spf_value],
        }
        with _patch_resolve(records):
            result = _run(scan_dns("example.com"))

        assert result["spf"] == spf_value
        assert result["has_spf"] is True

    def test_dmarc_record_value_stored(self):
        dmarc_value = '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'
        records = {
            ("example.com", "A"): ["1.2.3.4"],
            ("_dmarc.example.com", "TXT"): [dmarc_value],
        }
        with _patch_resolve(records):
            result = _run(scan_dns("example.com"))

        assert result["dmarc"] == dmarc_value
        assert result["has_dmarc"] is True

    def test_aaaa_records_prevent_no_records_finding(self):
        """If only AAAA records exist (no A records), no critical finding about missing records."""
        records = {
            ("example.com", "AAAA"): ["2606:2800:220:1:248:1893:25c8:1946"],
        }
        with _patch_resolve(records):
            result = _run(scan_dns("example.com"))

        no_records = [
            f for f in result["findings"]
            if "a/aaaa" in f["title"].lower()
        ]
        assert len(no_records) == 0
