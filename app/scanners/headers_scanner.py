"""HTTP security headers scanner."""

from typing import Any, Dict

import httpx

# Map of expected security headers to severity if missing
SECURITY_HEADERS: Dict[str, Dict[str, str]] = {
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "HSTS header is missing. Browsers will not enforce HTTPS connections.",
        "recommendation": "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to all HTTPS responses.",
    },
    "Content-Security-Policy": {
        "severity": "high",
        "description": "Content-Security-Policy header is missing, leaving the site vulnerable to XSS attacks.",
        "recommendation": "Define a strict Content-Security-Policy to restrict resource origins.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options header is missing, allowing the page to be embedded in iframes (clickjacking risk).",
        "recommendation": "Add `X-Frame-Options: DENY` or `SAMEORIGIN`.",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": "X-Content-Type-Options header is missing, allowing MIME-type sniffing.",
        "recommendation": "Add `X-Content-Type-Options: nosniff`.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy header is missing; referrer information may leak to third parties.",
        "recommendation": "Add `Referrer-Policy: strict-origin-when-cross-origin`.",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions-Policy (Feature-Policy) header is missing; browser features are not restricted.",
        "recommendation": "Define a Permissions-Policy to restrict access to sensitive browser APIs.",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "description": "X-XSS-Protection header is missing (legacy XSS filter hint for older browsers).",
        "recommendation": "Add `X-XSS-Protection: 1; mode=block` for legacy browser compatibility.",
    },
}

# Headers that expose server/tech information
INFO_DISCLOSURE_HEADERS = (
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
)


async def scan_headers(domain: str) -> Dict[str, Any]:
    """
    Fetch HTTP headers from *domain* and analyse security posture.
    """
    result: Dict[str, Any] = {
        "url_checked": None,
        "status_code": None,
        "headers": {},
        "missing_headers": [],
        "present_headers": [],
        "info_disclosure": [],
        "findings": [],
    }

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=15,
                verify=False,  # We check certs separately in ssl_scanner
            ) as client:
                response = await client.get(url, headers={"User-Agent": "SecureScan/1.0"})
            result["url_checked"] = str(response.url)
            result["status_code"] = response.status_code
            result["headers"] = dict(response.headers)
            break
        except Exception:
            continue

    if result["url_checked"] is None:
        result["findings"].append(
            {
                "title": "Site Unreachable",
                "description": "Could not connect to the site over HTTP or HTTPS.",
                "severity": "critical",
                "category": "headers",
                "recommendation": "Ensure the web server is running and publicly accessible.",
            }
        )
        return result

    resp_headers_lower = {k.lower(): v for k, v in result["headers"].items()}

    # Check required security headers
    for header, meta in SECURITY_HEADERS.items():
        if header.lower() in resp_headers_lower:
            result["present_headers"].append(header)
        else:
            result["missing_headers"].append(header)
            result["findings"].append(
                {
                    "title": f"Missing Security Header: {header}",
                    "description": meta["description"],
                    "severity": meta["severity"],
                    "category": "headers",
                    "recommendation": meta["recommendation"],
                }
            )

    # Check HSTS value if present
    hsts_value = resp_headers_lower.get("strict-transport-security", "")
    if hsts_value:
        if "max-age=0" in hsts_value:
            result["findings"].append(
                {
                    "title": "HSTS max-age Set to Zero",
                    "description": "The HSTS header is present but max-age=0 effectively disables HSTS.",
                    "severity": "high",
                    "category": "headers",
                    "recommendation": "Set max-age to at least 31536000 (one year).",
                }
            )
        else:
            try:
                parts = {p.strip().split("=")[0].lower(): p.strip().split("=")[1] if "=" in p else None
                         for p in hsts_value.split(";")}
                max_age = int(parts.get("max-age", 0))
                if max_age < 86400:
                    result["findings"].append(
                        {
                            "title": "HSTS max-age Too Short",
                            "description": f"HSTS max-age is {max_age} seconds, which is less than 1 day.",
                            "severity": "medium",
                            "category": "headers",
                            "recommendation": "Increase HSTS max-age to at least 31536000 (one year).",
                        }
                    )
            except (ValueError, IndexError, AttributeError):
                pass

    # Information disclosure
    for header in INFO_DISCLOSURE_HEADERS:
        if header.lower() in resp_headers_lower:
            value = resp_headers_lower[header.lower()]
            result["info_disclosure"].append({"header": header, "value": value})
            result["findings"].append(
                {
                    "title": f"Information Disclosure: {header}",
                    "description": f"The '{header}' header reveals server/technology information: '{value}'.",
                    "severity": "low",
                    "category": "headers",
                    "recommendation": f"Remove or redact the '{header}' response header to minimise information exposure.",
                }
            )

    return result
