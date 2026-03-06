"""Tests for the open port scanner."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from app.scanners.port_scanner import scan_ports, COMMON_PORTS, RISKY_PORTS


def _run(coro):
    """Run an async coroutine in a fresh event loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _mock_scan(open_ports_set: set):
    """Patch asyncio.open_connection to simulate specific ports being open."""

    async def fake_open_connection(host, port):
        if port in open_ports_set:
            writer = AsyncMock()
            writer.close = lambda: None
            writer.wait_closed = AsyncMock()
            return (AsyncMock(), writer)
        raise ConnectionRefusedError("Connection refused")

    with patch("app.scanners.port_scanner.asyncio.open_connection", side_effect=fake_open_connection):
        return await scan_ports("example.com")


class TestPortScanner:
    def test_no_open_ports(self):
        result = _run(_mock_scan(set()))
        assert result["open_ports"] == []
        assert result["findings"] == []
        assert len(result["closed_ports"]) == len(COMMON_PORTS)

    def test_http_and_https_open(self):
        result = _run(_mock_scan({80, 443}))
        open_port_numbers = {p["port"] for p in result["open_ports"]}
        assert 80 in open_port_numbers
        assert 443 in open_port_numbers

    def test_http_port_80_generates_redirect_finding(self):
        result = _run(_mock_scan({80}))
        redirect_findings = [
            f for f in result["findings"]
            if "redirect" in f["title"].lower() and "80" in f["title"]
        ]
        assert len(redirect_findings) >= 1
        assert redirect_findings[0]["severity"] == "low"

    def test_risky_port_mysql_generates_critical_finding(self):
        result = _run(_mock_scan({3306}))
        mysql_findings = [
            f for f in result["findings"]
            if "3306" in f["title"] and f["severity"] == "critical"
        ]
        assert len(mysql_findings) >= 1
        assert "mysql" in mysql_findings[0]["title"].lower()

    def test_risky_port_telnet_generates_critical_finding(self):
        result = _run(_mock_scan({23}))
        telnet_findings = [
            f for f in result["findings"]
            if "23" in f["title"] and f["severity"] == "critical"
        ]
        assert len(telnet_findings) >= 1

    def test_risky_port_rdp_generates_critical_finding(self):
        result = _run(_mock_scan({3389}))
        rdp_findings = [
            f for f in result["findings"]
            if "3389" in f["title"]
        ]
        assert len(rdp_findings) >= 1
        assert rdp_findings[0]["severity"] == "critical"

    def test_risky_port_redis_generates_critical_finding(self):
        result = _run(_mock_scan({6379}))
        redis_findings = [
            f for f in result["findings"]
            if "6379" in f["title"]
        ]
        assert len(redis_findings) >= 1

    def test_risky_port_mongodb_generates_critical_finding(self):
        result = _run(_mock_scan({27017}))
        mongo_findings = [
            f for f in result["findings"]
            if "27017" in f["title"]
        ]
        assert len(mongo_findings) >= 1

    def test_multiple_risky_ports_open(self):
        result = _run(_mock_scan({21, 23, 3306, 5432}))
        assert len(result["open_ports"]) == 4
        # Each risky port should produce a finding
        assert len(result["findings"]) == 4

    def test_safe_ports_no_risky_finding(self):
        """SSH (22) and DNS (53) are info severity, not in RISKY_PORTS with critical findings."""
        result = _run(_mock_scan({443}))
        # HTTPS is info level and not risky
        assert len(result["findings"]) == 0

    def test_open_port_entry_has_expected_fields(self):
        result = _run(_mock_scan({22}))
        assert len(result["open_ports"]) == 1
        port_entry = result["open_ports"][0]
        assert "port" in port_entry
        assert "service" in port_entry
        assert "severity" in port_entry
        assert port_entry["port"] == 22
        assert port_entry["service"] == "SSH"

    def test_finding_has_required_fields(self):
        result = _run(_mock_scan({3306}))
        assert len(result["findings"]) >= 1
        finding = result["findings"][0]
        assert "title" in finding
        assert "description" in finding
        assert "severity" in finding
        assert "category" in finding
        assert "recommendation" in finding
        assert finding["category"] == "ports"

    def test_connection_exception_treated_as_closed(self):
        """If open_connection raises an unexpected exception, port is treated as closed."""

        async def failing_open(host, port):
            raise OSError("Network unreachable")

        with patch("app.scanners.port_scanner.asyncio.open_connection", side_effect=failing_open):
            result = _run(scan_ports("unreachable.invalid"))
        assert result["open_ports"] == []
        assert len(result["closed_ports"]) == len(COMMON_PORTS)
