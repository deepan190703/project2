"""Open port scanner."""

import asyncio
from typing import Any, Dict, List, Tuple

# Common ports to scan with their service descriptions
COMMON_PORTS: List[Tuple[int, str, str]] = [
    (21, "FTP", "high"),
    (22, "SSH", "info"),
    (23, "Telnet", "critical"),
    (25, "SMTP", "medium"),
    (53, "DNS", "info"),
    (80, "HTTP", "info"),
    (110, "POP3", "medium"),
    (143, "IMAP", "medium"),
    (443, "HTTPS", "info"),
    (445, "SMB/CIFS", "critical"),
    (1433, "MSSQL", "critical"),
    (1521, "Oracle DB", "critical"),
    (3306, "MySQL", "critical"),
    (3389, "RDP", "critical"),
    (5432, "PostgreSQL", "critical"),
    (5900, "VNC", "critical"),
    (6379, "Redis", "critical"),
    (8080, "HTTP-Alt", "medium"),
    (8443, "HTTPS-Alt", "low"),
    (9200, "Elasticsearch", "critical"),
    (27017, "MongoDB", "critical"),
]

# Ports that are risky when exposed to the internet
RISKY_PORTS = {
    21: "FTP transmits credentials in plaintext; replace with SFTP/FTPS.",
    23: "Telnet is unencrypted; disable it and use SSH instead.",
    445: "SMB is frequently exploited (e.g., WannaCry); restrict with a firewall.",
    1433: "MSSQL should not be exposed to the internet; use a VPN or firewall.",
    1521: "Oracle DB should not be exposed to the internet.",
    3306: "MySQL should not be exposed to the internet; bind to localhost.",
    3389: "RDP is a common attack vector; restrict with a firewall or VPN.",
    5432: "PostgreSQL should not be exposed to the internet.",
    5900: "VNC is frequently exploited; restrict with a firewall.",
    6379: "Redis has no authentication by default; restrict with a firewall.",
    9200: "Elasticsearch is frequently misconfigured and exposed; restrict access.",
    27017: "MongoDB has had many publicly exposed instances with no auth; restrict access.",
}


async def _check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """Return True if *port* is open on *host*."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def scan_ports(domain: str) -> Dict[str, Any]:
    """Scan common ports on *domain* and report findings."""
    result: Dict[str, Any] = {
        "open_ports": [],
        "closed_ports": [],
        "findings": [],
    }

    tasks = [
        (port, service, severity, _check_port(domain, port))
        for port, service, severity in COMMON_PORTS
    ]

    # Run all checks concurrently
    checks = await asyncio.gather(*[t[3] for t in tasks], return_exceptions=True)

    for (port, service, severity), is_open in zip(
        [(p, s, sev) for p, s, sev in COMMON_PORTS], checks
    ):
        if isinstance(is_open, Exception):
            is_open = False

        if is_open:
            entry = {"port": port, "service": service, "severity": severity}
            result["open_ports"].append(entry)

            if port in RISKY_PORTS:
                result["findings"].append(
                    {
                        "title": f"Risky Port Open: {port}/{service}",
                        "description": f"Port {port} ({service}) is open and publicly accessible.",
                        "severity": severity,
                        "category": "ports",
                        "recommendation": RISKY_PORTS[port],
                    }
                )
            elif port == 80:
                result["findings"].append(
                    {
                        "title": "HTTP (Port 80) Open – Redirect to HTTPS Recommended",
                        "description": "Port 80 is open. Ensure all HTTP traffic is redirected to HTTPS.",
                        "severity": "low",
                        "category": "ports",
                        "recommendation": "Configure your web server to issue a 301 redirect from HTTP to HTTPS.",
                    }
                )
        else:
            result["closed_ports"].append({"port": port, "service": service})

    return result
