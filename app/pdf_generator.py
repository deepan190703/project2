"""PDF report generator for scan results."""

import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Colour palette
COLOR_PRIMARY = colors.HexColor("#1a365d")
COLOR_ACCENT = colors.HexColor("#2b6cb0")
COLOR_CRITICAL = colors.HexColor("#c53030")
COLOR_HIGH = colors.HexColor("#dd6b20")
COLOR_MEDIUM = colors.HexColor("#d69e2e")
COLOR_LOW = colors.HexColor("#276749")
COLOR_INFO = colors.HexColor("#2b6cb0")
COLOR_LIGHT_BG = colors.HexColor("#f7fafc")
COLOR_BORDER = colors.HexColor("#e2e8f0")

SEVERITY_COLORS = {
    "critical": COLOR_CRITICAL,
    "high": COLOR_HIGH,
    "medium": COLOR_MEDIUM,
    "low": COLOR_LOW,
    "info": COLOR_INFO,
}


def _get_styles():
    styles = getSampleStyleSheet()
    custom = {
        "Title": ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=COLOR_PRIMARY,
            alignment=TA_CENTER,
            spaceAfter=6,
        ),
        "Subtitle": ParagraphStyle(
            "Subtitle",
            parent=styles["Normal"],
            fontSize=12,
            textColor=COLOR_ACCENT,
            alignment=TA_CENTER,
            spaceAfter=12,
        ),
        "SectionHeader": ParagraphStyle(
            "SectionHeader",
            parent=styles["Heading2"],
            fontSize=14,
            textColor=COLOR_PRIMARY,
            spaceBefore=16,
            spaceAfter=8,
        ),
        "Body": ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            spaceAfter=6,
        ),
        "FindingTitle": ParagraphStyle(
            "FindingTitle",
            parent=styles["Normal"],
            fontSize=10,
            fontName="Helvetica-Bold",
            spaceAfter=2,
        ),
        "FindingBody": ParagraphStyle(
            "FindingBody",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            spaceAfter=2,
        ),
        "Code": ParagraphStyle(
            "Code",
            parent=styles["Code"],
            fontSize=8,
            leading=12,
        ),
    }
    return custom


def _severity_badge(severity: str) -> str:
    """Return an HTML-like coloured badge string for a severity level."""
    colour_map = {
        "critical": "#c53030",
        "high": "#dd6b20",
        "medium": "#d69e2e",
        "low": "#276749",
        "info": "#2b6cb0",
    }
    colour = colour_map.get(severity.lower(), "#718096")
    label = severity.upper()
    return f'<font color="{colour}"><b>[{label}]</b></font>'


def generate_pdf_report(
    domain: str,
    risk_score: Optional[float],
    risk_grade: Optional[str],
    findings: List[Dict[str, Any]],
    ssl_results: Optional[Dict[str, Any]],
    headers_results: Optional[Dict[str, Any]],
    ports_results: Optional[Dict[str, Any]],
    endpoints_results: Optional[Dict[str, Any]],
    dns_results: Optional[Dict[str, Any]],
) -> bytes:
    """Generate a PDF security report and return it as bytes."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2.5 * cm,
        bottomMargin=2 * cm,
    )

    styles = _get_styles()
    story = []

    # ------------------------------------------------------------------ Cover
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph("SecureScan", styles["Title"]))
    story.append(Paragraph("Website Security Assessment Report", styles["Subtitle"]))
    story.append(HRFlowable(width="100%", thickness=2, color=COLOR_PRIMARY))
    story.append(Spacer(1, 0.5 * cm))

    meta_data = [
        ["Target Domain", domain],
        ["Report Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
        ["Risk Score", f"{risk_score:.1f} / 100" if risk_score is not None else "N/A"],
        ["Risk Grade", risk_grade or "N/A"],
    ]
    meta_table = Table(meta_data, colWidths=[5 * cm, 12 * cm])
    meta_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("TEXTCOLOR", (0, 0), (0, -1), COLOR_PRIMARY),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [COLOR_LIGHT_BG, colors.white]),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, COLOR_BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 0.5 * cm))

    # ---------------------------------------------------------------- Summary
    story.append(Paragraph("Executive Summary", styles["SectionHeader"]))

    # Count findings by severity
    severity_counts: Dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    }
    for f in findings:
        sev = f.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total_findings = len(findings)
    summary_text = (
        f"The security scan of <b>{domain}</b> identified <b>{total_findings}</b> "
        f"finding(s): "
        f"<font color='#c53030'><b>{severity_counts['critical']} Critical</b></font>, "
        f"<font color='#dd6b20'><b>{severity_counts['high']} High</b></font>, "
        f"<font color='#d69e2e'><b>{severity_counts['medium']} Medium</b></font>, "
        f"<font color='#276749'><b>{severity_counts['low']} Low</b></font>, "
        f"<b>{severity_counts['info']} Informational</b>."
    )
    story.append(Paragraph(summary_text, styles["Body"]))
    story.append(Spacer(1, 0.3 * cm))

    # Risk score visual bar
    if risk_score is not None:
        score_label = f"Overall Risk Score: {risk_score:.0f} / 100  (Grade: {risk_grade})"
        story.append(Paragraph(score_label, styles["Body"]))

        bar_width = 15 * cm
        filled = bar_width * (risk_score / 100)
        bar_color = (
            COLOR_CRITICAL if risk_score >= 65
            else COLOR_HIGH if risk_score >= 45
            else COLOR_MEDIUM if risk_score >= 25
            else COLOR_LOW if risk_score >= 10
            else COLOR_INFO
        )
        bar_table = Table(
            [["", ""]],
            colWidths=[filled, bar_width - filled],
            rowHeights=[0.4 * cm],
        )
        bar_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), bar_color),
                    ("BACKGROUND", (1, 0), (1, 0), COLOR_LIGHT_BG),
                    ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        story.append(bar_table)
        story.append(Spacer(1, 0.5 * cm))

    story.append(PageBreak())

    # ----------------------------------------------------------- All Findings
    story.append(Paragraph("Findings", styles["SectionHeader"]))

    if not findings:
        story.append(
            Paragraph("No security issues were detected during this scan.", styles["Body"])
        )
    else:
        # Group by category
        categories = {}
        for f in findings:
            cat = f.get("category", "general").capitalize()
            categories.setdefault(cat, []).append(f)

        for category, cat_findings in categories.items():
            story.append(Paragraph(category, styles["SectionHeader"]))
            for idx, finding in enumerate(cat_findings, 1):
                sev = finding.get("severity", "info")
                badge = _severity_badge(sev)
                story.append(
                    Paragraph(
                        f"{badge}  {finding.get('title', 'Finding')}",
                        styles["FindingTitle"],
                    )
                )
                story.append(
                    Paragraph(
                        f"<b>Description:</b> {finding.get('description', '')}",
                        styles["FindingBody"],
                    )
                )
                story.append(
                    Paragraph(
                        f"<b>Recommendation:</b> {finding.get('recommendation', '')}",
                        styles["FindingBody"],
                    )
                )
                story.append(HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER))
                story.append(Spacer(1, 0.2 * cm))

    story.append(PageBreak())

    # --------------------------------------------------- Detailed Scan Results
    story.append(Paragraph("Detailed Scan Results", styles["SectionHeader"]))

    # SSL
    story.append(Paragraph("SSL/TLS Certificate", styles["SectionHeader"]))
    if ssl_results:
        ssl_rows = [
            ["Property", "Value"],
            ["HTTPS Supported", str(ssl_results.get("supported", "N/A"))],
            ["Certificate Valid", str(ssl_results.get("valid", "N/A"))],
            ["Subject", ssl_results.get("subject") or "N/A"],
            ["Issuer", ssl_results.get("issuer") or "N/A"],
            ["Expiry Date", ssl_results.get("not_after") or "N/A"],
            ["Days Until Expiry", str(ssl_results.get("days_until_expiry", "N/A"))],
            ["Protocol Version", ssl_results.get("protocol_version") or "N/A"],
            ["Cipher Suite", ssl_results.get("cipher_suite") or "N/A"],
        ]
        _append_table(story, ssl_rows)
    else:
        story.append(Paragraph("SSL scan data not available.", styles["Body"]))

    story.append(Spacer(1, 0.5 * cm))

    # Headers
    story.append(Paragraph("HTTP Security Headers", styles["SectionHeader"]))
    if headers_results:
        present = headers_results.get("present_headers", [])
        missing = headers_results.get("missing_headers", [])
        story.append(
            Paragraph(
                f"<b>Present:</b> {', '.join(present) if present else 'None'}",
                styles["Body"],
            )
        )
        story.append(
            Paragraph(
                f"<b>Missing:</b> {', '.join(missing) if missing else 'None'}",
                styles["Body"],
            )
        )
    else:
        story.append(Paragraph("Headers scan data not available.", styles["Body"]))

    story.append(Spacer(1, 0.5 * cm))

    # Open Ports
    story.append(Paragraph("Open Ports", styles["SectionHeader"]))
    if ports_results:
        open_ports = ports_results.get("open_ports", [])
        if open_ports:
            port_rows = [["Port", "Service", "Severity"]] + [
                [str(p["port"]), p["service"], p["severity"].upper()]
                for p in open_ports
            ]
            _append_table(story, port_rows)
        else:
            story.append(Paragraph("No open ports detected.", styles["Body"]))
    else:
        story.append(Paragraph("Port scan data not available.", styles["Body"]))

    story.append(Spacer(1, 0.5 * cm))

    # Endpoints
    story.append(Paragraph("Discovered Endpoints", styles["SectionHeader"]))
    if endpoints_results:
        discovered = endpoints_results.get("discovered", [])
        if discovered:
            ep_rows = [["Path", "Description", "Status", "Severity"]] + [
                [e["path"], e["description"], str(e["status_code"]), e["severity"].upper()]
                for e in discovered
            ]
            _append_table(story, ep_rows)
        else:
            story.append(Paragraph("No sensitive endpoints discovered.", styles["Body"]))
    else:
        story.append(Paragraph("Endpoint scan data not available.", styles["Body"]))

    story.append(Spacer(1, 0.5 * cm))

    # DNS
    story.append(Paragraph("DNS Configuration", styles["SectionHeader"]))
    if dns_results:
        dns_rows = [
            ["Property", "Value"],
            ["A Records", ", ".join(dns_results.get("a_records", [])) or "None"],
            ["MX Records", ", ".join(dns_results.get("mx_records", [])) or "None"],
            ["SPF Record", dns_results.get("spf") or "Not found"],
            ["DMARC Record", dns_results.get("dmarc") or "Not found"],
            ["CAA Records", "Present" if dns_results.get("has_caa") else "Not found"],
        ]
        _append_table(story, dns_rows)
    else:
        story.append(Paragraph("DNS scan data not available.", styles["Body"]))

    # Footer note
    story.append(Spacer(1, 1 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_BORDER))
    story.append(
        Paragraph(
            "This report was generated by SecureScan. Results are indicative and should be "
            "reviewed by a qualified security professional before taking action.",
            ParagraphStyle(
                "Footer",
                parent=_get_styles()["Body"],
                fontSize=8,
                textColor=colors.grey,
                alignment=TA_CENTER,
            ),
        )
    )

    doc.build(story)
    buffer.seek(0)
    return buffer.read()


def _append_table(story, rows):
    """Helper to build and append a simple two-column table."""
    styles = _get_styles()
    col_count = len(rows[0]) if rows else 1
    col_width = 17 * cm / col_count

    table = Table(rows, colWidths=[col_width] * col_count)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_LIGHT_BG, colors.white]),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, COLOR_BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("WORDWRAP", (0, 0), (-1, -1), True),
            ]
        )
    )
    story.append(table)
