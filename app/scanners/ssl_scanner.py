"""SSL/TLS certificate scanner."""

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List


async def scan_ssl(domain: str) -> Dict[str, Any]:
    """
    Validate SSL/TLS configuration for *domain*.

    Returns a dict with certificate info and a list of findings.
    """
    result: Dict[str, Any] = {
        "supported": False,
        "valid": False,
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "serial_number": None,
        "version": None,
        "sans": [],
        "protocol_version": None,
        "cipher_suite": None,
        "findings": [],
    }

    try:
        context = ssl.create_default_context()
        loop = asyncio.get_event_loop()

        def _connect():
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    return cert, protocol, cipher

        cert, protocol, cipher = await loop.run_in_executor(None, _connect)

        result["supported"] = True
        result["valid"] = True
        result["protocol_version"] = protocol
        result["cipher_suite"] = cipher[0] if cipher else None

        # Subject
        subject_dict = dict(x[0] for x in cert.get("subject", []))
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        result["subject"] = subject_dict.get("commonName", "")
        result["issuer"] = issuer_dict.get("organizationName", "")
        result["serial_number"] = cert.get("serialNumber", "")
        result["version"] = cert.get("version", None)

        # SANs
        san_list = []
        for san_type, san_value in cert.get("subjectAltName", []):
            san_list.append(f"{san_type}:{san_value}")
        result["sans"] = san_list

        # Validity dates
        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")

        def parse_cert_date(date_str: str) -> datetime:
            return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )

        if not_before_str:
            not_before = parse_cert_date(not_before_str)
            result["not_before"] = not_before.isoformat()
        if not_after_str:
            not_after = parse_cert_date(not_after_str)
            result["not_after"] = not_after.isoformat()
            now = datetime.now(timezone.utc)
            delta = not_after - now
            result["days_until_expiry"] = delta.days

            if delta.days < 0:
                result["findings"].append(
                    {
                        "title": "SSL Certificate Expired",
                        "description": f"The SSL certificate expired {abs(delta.days)} days ago.",
                        "severity": "critical",
                        "category": "ssl",
                        "recommendation": "Renew the SSL certificate immediately to restore HTTPS trust.",
                    }
                )
            elif delta.days < 14:
                result["findings"].append(
                    {
                        "title": "SSL Certificate Expiring Very Soon",
                        "description": f"The SSL certificate expires in {delta.days} days.",
                        "severity": "high",
                        "category": "ssl",
                        "recommendation": "Renew the SSL certificate as soon as possible.",
                    }
                )
            elif delta.days < 30:
                result["findings"].append(
                    {
                        "title": "SSL Certificate Expiring Soon",
                        "description": f"The SSL certificate expires in {delta.days} days.",
                        "severity": "medium",
                        "category": "ssl",
                        "recommendation": "Plan certificate renewal within the next two weeks.",
                    }
                )

        # Weak protocol checks
        if protocol and protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            result["findings"].append(
                {
                    "title": "Outdated TLS Protocol in Use",
                    "description": f"The server negotiated {protocol}, which is considered insecure.",
                    "severity": "high",
                    "category": "ssl",
                    "recommendation": "Disable TLS 1.0 and TLS 1.1. Enforce TLS 1.2 or TLS 1.3.",
                }
            )

        # Weak cipher checks
        if cipher:
            cipher_name = cipher[0].upper()
            weak_keywords = ("RC4", "DES", "MD5", "NULL", "EXPORT", "anon")
            if any(kw in cipher_name for kw in weak_keywords):
                result["findings"].append(
                    {
                        "title": "Weak Cipher Suite Detected",
                        "description": f"The cipher suite '{cipher[0]}' is considered weak.",
                        "severity": "high",
                        "category": "ssl",
                        "recommendation": "Configure the server to prefer strong cipher suites (AES-GCM, ChaCha20-Poly1305).",
                    }
                )

    except ssl.SSLCertVerificationError as exc:
        result["supported"] = True
        result["valid"] = False
        result["findings"].append(
            {
                "title": "Invalid SSL Certificate",
                "description": f"Certificate verification failed: {exc}",
                "severity": "critical",
                "category": "ssl",
                "recommendation": "Obtain a valid certificate from a trusted Certificate Authority.",
            }
        )
    except (ConnectionRefusedError, socket.timeout, OSError):
        result["findings"].append(
            {
                "title": "HTTPS Not Available",
                "description": "Port 443 is closed or unreachable; the site does not support HTTPS.",
                "severity": "critical",
                "category": "ssl",
                "recommendation": "Enable HTTPS by obtaining an SSL/TLS certificate and configuring your web server.",
            }
        )

    return result
