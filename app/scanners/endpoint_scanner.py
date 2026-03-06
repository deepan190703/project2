"""Endpoint discovery scanner."""

from typing import Any, Dict, List, Tuple

import httpx

# (path, description, severity_if_found)
SENSITIVE_PATHS: List[Tuple[str, str, str]] = [
    ("/admin", "Admin panel", "high"),
    ("/admin/", "Admin panel", "high"),
    ("/administrator", "Administrator panel", "high"),
    ("/wp-admin/", "WordPress admin panel", "high"),
    ("/wp-login.php", "WordPress login page", "medium"),
    ("/phpmyadmin/", "phpMyAdmin database admin", "critical"),
    ("/phpmyadmin", "phpMyAdmin database admin", "critical"),
    ("/.env", "Environment/configuration file", "critical"),
    ("/.git/config", "Git repository config", "critical"),
    ("/.git/HEAD", "Git repository HEAD", "critical"),
    ("/config.php", "PHP configuration file", "critical"),
    ("/configuration.php", "PHP configuration file", "critical"),
    ("/web.config", "IIS web configuration", "high"),
    ("/server-status", "Apache server status", "high"),
    ("/server-info", "Apache server info", "high"),
    ("/nginx_status", "Nginx status page", "medium"),
    ("/backup", "Backup directory", "high"),
    ("/backup.zip", "Backup archive", "critical"),
    ("/backup.sql", "Database backup", "critical"),
    ("/dump.sql", "Database dump", "critical"),
    ("/db.sql", "Database file", "critical"),
    ("/test", "Test directory", "medium"),
    ("/debug", "Debug endpoint", "high"),
    ("/console", "Console endpoint", "high"),
    ("/api/v1/", "API endpoint", "info"),
    ("/api/", "API endpoint", "info"),
    ("/swagger-ui.html", "Swagger UI (API docs)", "medium"),
    ("/swagger/", "Swagger UI (API docs)", "medium"),
    ("/api-docs", "API documentation", "medium"),
    ("/openapi.json", "OpenAPI specification", "medium"),
    ("/graphql", "GraphQL endpoint", "medium"),
    ("/robots.txt", "Robots.txt file", "info"),
    ("/sitemap.xml", "Sitemap file", "info"),
    ("/security.txt", "Security.txt file", "info"),
    ("/.well-known/security.txt", "Security.txt file (well-known)", "info"),
    ("/crossdomain.xml", "Flash cross-domain policy", "medium"),
    ("/clientaccesspolicy.xml", "Silverlight access policy", "low"),
    ("/xmlrpc.php", "WordPress XML-RPC", "medium"),
    ("/readme.html", "WordPress readme", "low"),
    ("/license.txt", "License file (may reveal CMS)", "low"),
    ("/CHANGELOG.md", "Changelog (version disclosure)", "low"),
    ("/composer.json", "Composer dependency file", "medium"),
    ("/package.json", "Node.js package file", "medium"),
    ("/Gemfile", "Ruby Gemfile", "medium"),
    ("/requirements.txt", "Python requirements", "medium"),
]


async def scan_endpoints(domain: str) -> Dict[str, Any]:
    """Probe common paths on *domain* and report interesting findings."""
    result: Dict[str, Any] = {
        "discovered": [],
        "findings": [],
    }

    base_urls = [f"https://{domain}", f"http://{domain}"]

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=10,
        verify=False,
    ) as client:
        for path, description, severity in SENSITIVE_PATHS:
            status = None
            for base in base_urls:
                try:
                    resp = await client.get(
                        f"{base}{path}",
                        headers={"User-Agent": "SecureScan/1.0"},
                    )
                    if resp.status_code not in (404, 403, 410, 503, 0):
                        status = resp.status_code
                        break
                    elif resp.status_code == 403:
                        # Resource exists but is forbidden – still noteworthy
                        status = resp.status_code
                        break
                except Exception:
                    continue

            if status is not None:
                entry = {
                    "path": path,
                    "description": description,
                    "status_code": status,
                    "severity": severity,
                }
                result["discovered"].append(entry)

                if severity in ("critical", "high", "medium"):
                    status_note = " (access restricted)" if status == 403 else f" (HTTP {status})"
                    result["findings"].append(
                        {
                            "title": f"Sensitive Endpoint Discovered: {path}",
                            "description": (
                                f"The path '{path}' ({description}) was found{status_note}. "
                                "Sensitive resources should not be publicly accessible."
                            ),
                            "severity": severity,
                            "category": "endpoints",
                            "recommendation": (
                                f"Restrict access to '{path}' using authentication, IP whitelisting, or remove it if unused."
                            ),
                        }
                    )

    return result
