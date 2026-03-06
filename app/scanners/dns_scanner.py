"""DNS and configuration analysis scanner."""

import asyncio
import socket
from typing import Any, Dict, List

import dns.resolver
import dns.exception


async def _resolve(domain: str, record_type: str) -> List[str]:
    """Resolve DNS records asynchronously."""
    loop = asyncio.get_event_loop()

    def _query():
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=5)
            return [str(r) for r in answers]
        except (dns.exception.DNSException, Exception):
            return []

    return await loop.run_in_executor(None, _query)


async def scan_dns(domain: str) -> Dict[str, Any]:
    """Analyse DNS configuration of *domain*."""
    result: Dict[str, Any] = {
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "caa_records": [],
        "spf": None,
        "dmarc": None,
        "has_spf": False,
        "has_dmarc": False,
        "has_caa": False,
        "findings": [],
    }

    # Run DNS queries concurrently
    (
        a_records,
        aaaa_records,
        mx_records,
        ns_records,
        txt_records,
        caa_records,
        dmarc_records,
    ) = await asyncio.gather(
        _resolve(domain, "A"),
        _resolve(domain, "AAAA"),
        _resolve(domain, "MX"),
        _resolve(domain, "NS"),
        _resolve(domain, "TXT"),
        _resolve(domain, "CAA"),
        _resolve(f"_dmarc.{domain}", "TXT"),
    )

    result["a_records"] = a_records
    result["aaaa_records"] = aaaa_records
    result["mx_records"] = mx_records
    result["ns_records"] = ns_records
    result["txt_records"] = txt_records
    result["caa_records"] = caa_records

    # Analyse TXT records for SPF
    for txt in txt_records:
        if "v=spf1" in txt.lower():
            result["has_spf"] = True
            result["spf"] = txt

    # DMARC
    for txt in dmarc_records:
        if "v=dmarc1" in txt.lower():
            result["has_dmarc"] = True
            result["dmarc"] = txt

    # CAA
    if caa_records:
        result["has_caa"] = True

    # --- Findings ---

    if not a_records and not aaaa_records:
        result["findings"].append(
            {
                "title": "No DNS A/AAAA Records Found",
                "description": "The domain does not resolve to any IP address.",
                "severity": "critical",
                "category": "dns",
                "recommendation": "Ensure the domain has valid A or AAAA records pointing to your server.",
            }
        )

    if not result["has_spf"]:
        result["findings"].append(
            {
                "title": "Missing SPF Record",
                "description": "No SPF (Sender Policy Framework) TXT record was found. "
                               "This allows anyone to spoof email from this domain.",
                "severity": "medium",
                "category": "dns",
                "recommendation": "Add an SPF TXT record to specify authorised mail senders, "
                                   "e.g. `v=spf1 include:_spf.google.com ~all`.",
            }
        )

    if not result["has_dmarc"]:
        result["findings"].append(
            {
                "title": "Missing DMARC Record",
                "description": "No DMARC record was found at _dmarc." + domain + ". "
                               "Without DMARC, email spoofing attacks are harder to prevent.",
                "severity": "medium",
                "category": "dns",
                "recommendation": "Add a DMARC TXT record at _dmarc." + domain +
                                   ", e.g. `v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain + "`.",
            }
        )

    if not result["has_caa"]:
        result["findings"].append(
            {
                "title": "Missing CAA Record",
                "description": "No Certification Authority Authorization (CAA) record was found. "
                               "Any CA can issue certificates for this domain.",
                "severity": "low",
                "category": "dns",
                "recommendation": "Add a CAA record to restrict which CAs can issue certificates for your domain, "
                                   "e.g. `0 issue \"letsencrypt.org\"`.",
            }
        )

    # Check for SPF too-permissive
    if result["spf"] and "+all" in result["spf"]:
        result["findings"].append(
            {
                "title": "SPF Record Too Permissive (+all)",
                "description": "The SPF record ends with '+all', allowing any server to send mail on behalf of this domain.",
                "severity": "high",
                "category": "dns",
                "recommendation": "Change '+all' to '-all' (hard fail) or '~all' (soft fail) in the SPF record.",
            }
        )

    return result
