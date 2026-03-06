"""Tests for the SSL scanner."""

import asyncio
import ssl
import socket
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

from app.scanners.ssl_scanner import scan_ssl


def _make_cert(days_until_expiry: int = 365) -> dict:
    """Return a fake certificate dict similar to ssl.SSLSocket.getpeercert()."""
    now = datetime.now(timezone.utc)
    not_before = (now - timedelta(days=30)).strftime("%b %d %H:%M:%S %Y GMT")
    not_after  = (now + timedelta(days=days_until_expiry)).strftime("%b %d %H:%M:%S %Y GMT")
    return {
        "subject":        ((("commonName", "example.com"),),),
        "issuer":         ((("organizationName", "Test CA"),),),
        "notBefore":      not_before,
        "notAfter":       not_after,
        "serialNumber":   "DEADBEEF",
        "version":        3,
        "subjectAltName": (("DNS", "example.com"),),
    }


def _run(coro):
    """Run an async coroutine in a fresh event loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _scan_with_mock_cert(cert, protocol="TLSv1.3",
                                cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)):
    """Run scan_ssl with a mocked SSL socket that returns *cert*."""
    mock_ssl_sock = MagicMock()
    mock_ssl_sock.__enter__ = MagicMock(return_value=mock_ssl_sock)
    mock_ssl_sock.__exit__ = MagicMock(return_value=False)
    mock_ssl_sock.getpeercert.return_value = cert
    mock_ssl_sock.version.return_value = protocol
    mock_ssl_sock.cipher.return_value = cipher

    mock_plain_sock = MagicMock()
    mock_plain_sock.__enter__ = MagicMock(return_value=mock_plain_sock)
    mock_plain_sock.__exit__ = MagicMock(return_value=False)

    with (
        patch("socket.create_connection", return_value=mock_plain_sock),
        patch("ssl.SSLContext.wrap_socket", return_value=mock_ssl_sock),
    ):
        return await scan_ssl("example.com")


class TestSslScanner:

    def test_valid_certificate_basic_fields(self):
        cert   = _make_cert(days_until_expiry=180)
        result = _run(_scan_with_mock_cert(cert))
        assert result["supported"] is True
        assert result["valid"] is True
        assert result["subject"] == "example.com"
        assert result["issuer"]  == "Test CA"
        assert result["days_until_expiry"] >= 179

    def test_valid_certificate_no_expiry_finding(self):
        cert   = _make_cert(days_until_expiry=180)
        result = _run(_scan_with_mock_cert(cert))
        expiry_findings = [
            f for f in result["findings"]
            if "expir" in f["title"].lower()
        ]
        assert len(expiry_findings) == 0

    def test_certificate_expired(self):
        cert   = _make_cert(days_until_expiry=-5)
        result = _run(_scan_with_mock_cert(cert))
        critical = [
            f for f in result["findings"]
            if f["severity"] == "critical" and "expired" in f["title"].lower()
        ]
        assert len(critical) >= 1

    def test_expiring_within_14_days(self):
        cert   = _make_cert(days_until_expiry=7)
        result = _run(_scan_with_mock_cert(cert))
        high = [f for f in result["findings"] if f["severity"] == "high"]
        assert len(high) >= 1

    def test_expiring_within_30_days(self):
        cert   = _make_cert(days_until_expiry=20)
        result = _run(_scan_with_mock_cert(cert))
        medium = [f for f in result["findings"] if f["severity"] == "medium"]
        assert len(medium) >= 1

    def test_outdated_tls_protocol(self):
        cert   = _make_cert(days_until_expiry=180)
        result = _run(_scan_with_mock_cert(cert, protocol="TLSv1", cipher=("AES128-SHA", "TLSv1", 128)))
        high = [
            f for f in result["findings"]
            if f["severity"] == "high" and "protocol" in f["title"].lower()
        ]
        assert len(high) >= 1

    def test_weak_cipher_suite_rc4(self):
        cert   = _make_cert(days_until_expiry=180)
        result = _run(_scan_with_mock_cert(cert, protocol="TLSv1.2",
                                           cipher=("RC4-SHA", "TLSv1.2", 128)))
        cipher_findings = [f for f in result["findings"] if "cipher" in f["title"].lower()]
        assert len(cipher_findings) >= 1

    def test_https_not_available(self):
        with patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
            result = _run(scan_ssl("unreachable.invalid"))
        assert result["supported"] is False
        critical = [f for f in result["findings"] if f["severity"] == "critical"]
        assert len(critical) >= 1

    def test_ssl_cert_verification_error(self):
        import ssl as ssl_module

        mock_ssl_sock = MagicMock()
        mock_ssl_sock.__enter__ = MagicMock(side_effect=ssl_module.SSLCertVerificationError("bad cert"))
        mock_ssl_sock.__exit__ = MagicMock(return_value=False)
        mock_plain_sock = MagicMock()
        mock_plain_sock.__enter__ = MagicMock(return_value=mock_plain_sock)
        mock_plain_sock.__exit__ = MagicMock(return_value=False)

        with (
            patch("socket.create_connection", return_value=mock_plain_sock),
            patch("ssl.SSLContext.wrap_socket", return_value=mock_ssl_sock),
        ):
            result = _run(scan_ssl("badcert.invalid"))

        assert result["supported"] is True
        assert result["valid"] is False
        critical = [f for f in result["findings"] if f["severity"] == "critical"]
        assert len(critical) >= 1
