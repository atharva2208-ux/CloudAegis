"""PDF security report rendered with ReportLab."""

from __future__ import annotations

import io
import json
from datetime import datetime
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

INK = colors.HexColor("#0F172A")
MUTED = colors.HexColor("#64748B")
LINE = colors.HexColor("#E2E8F0")
ACCENT = colors.HexColor("#2563EB")
PANEL = colors.HexColor("#F8FAFC")
SEV_COLORS = {
    "CRITICAL": colors.HexColor("#B91C1C"),
    "HIGH": colors.HexColor("#EA580C"),
    "MEDIUM": colors.HexColor("#CA8A04"),
    "LOW": colors.HexColor("#2563EB"),
    "INFO": colors.HexColor("#64748B"),
}

_base = getSampleStyleSheet()
S = {
    "title": ParagraphStyle("title", parent=_base["Title"], fontName="Helvetica-Bold", fontSize=22, leading=27,
                            textColor=INK, alignment=TA_LEFT, spaceAfter=4),
    "subtitle": ParagraphStyle("subtitle", fontName="Helvetica", fontSize=10.5, textColor=MUTED, leading=14),
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=14, textColor=INK, spaceBefore=14, spaceAfter=6),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11, textColor=INK, spaceBefore=8, spaceAfter=3),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK, spaceAfter=5),
    "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8, leading=10.5, textColor=MUTED),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=8, leading=10, textColor=INK),
    "cellb": ParagraphStyle("cellb", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=INK),
    "mono": ParagraphStyle("mono", fontName="Courier", fontSize=7.2, leading=9, textColor=INK),
    "metric": ParagraphStyle("metric", fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=INK),
    "metriclabel": ParagraphStyle("metriclabel", fontName="Helvetica", fontSize=8, textColor=MUTED, leading=10),
}


def p(text: Any, style: str = "body") -> Paragraph:
    return Paragraph(escape("" if text is None else str(text)), S[style])


def _fmt_dt(value: str | None) -> str:
    if not value:
        return "—"
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return value


def _table(rows: list[list[Any]], widths: list[float], header: bool = True, zebra: bool = True) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("FONT", (0, 0), (-1, -1), "Helvetica", 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), PANEL), ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8),
                  ("TEXTCOLOR", (0, 0), (-1, 0), MUTED), ("LINEBELOW", (0, 0), (-1, 0), 0.8, LINE)]
    table.setStyle(TableStyle(style))
    return table


def _sev(sev: str) -> Paragraph:
    color = SEV_COLORS.get(sev, MUTED).hexval()[2:]
    return Paragraph(f'<font color="#{color}"><b>{escape(sev)}</b></font>', S["cell"])


def _metrics(data: dict[str, Any]) -> Table:
    score = data["score"] or {}
    counts = data["severity_counts"]
    cells = [
        ("Security score / 100", score.get("score", "—")),
        ("Critical", counts["CRITICAL"]),
        ("High", counts["HIGH"]),
        ("Medium", counts["MEDIUM"]),
        ("Assets", f"{data['assets']['total']:,}"),
        ("Internet-exposed", data["assets"]["public"]),
    ]
    row = [[Paragraph(escape(str(v)), S["metric"]), Paragraph(escape(k), S["metriclabel"])] for k, v in cells]
    table = Table([[Table([[a], [b]]) for a, b in row]], colWidths=[30 * mm] * 6)
    table.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
                               ("BACKGROUND", (0, 0), (-1, -1), PANEL), ("TOPPADDING", (0, 0), (-1, -1), 6),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    return table


def _on_page(canvas, doc, data: dict[str, Any]) -> None:
    canvas.saveState()
    width, height = A4
    canvas.setFillColor(INK)
    canvas.rect(0, height - 9 * mm, width, 9 * mm, stroke=0, fill=1)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 8.5)
    canvas.drawString(18 * mm, height - 6 * mm, "CloudAegis")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(width - 18 * mm, height - 6 * mm, "CONFIDENTIAL — Security Assessment")
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.5)
    footer = f"{data['title']} · Generated {_fmt_dt(data['generated_at'])}"
    if data.get("simulated"):
        footer += " · Contains simulated demo data"
    canvas.drawString(18 * mm, 10 * mm, footer[:140])
    canvas.drawRightString(width - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def to_pdf(data: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm,
                            bottomMargin=18 * mm, title=data["title"], author="CloudAegis")
    content_width = A4[0] - 36 * mm
    story: list[Any] = []

    story += [Spacer(1, 4 * mm), p(data["title"], "title"),
              p(f"{'Executive' if data['report_type'] == 'executive' else 'Technical'} security posture report · "
                f"Scope: {data['scope']} · {_fmt_dt(data['generated_at'])}"
                + (f" · Generated by {data['generated_by']}" if data.get("generated_by") else ""), "subtitle")]
    if data.get("simulated"):
        story.append(Spacer(1, 3 * mm))
        story.append(p("Note: this report includes the CloudAegis demo environment. All demo resources and "
                       "findings are simulated.", "small"))
    story += [Spacer(1, 6 * mm), _metrics(data)]

    story.append(p("1. Executive summary", "h1"))
    for paragraph in data["executive_summary"]:
        story.append(p(paragraph))

    score = data["score"]
    if score:
        story.append(p("How the score is calculated", "h2"))
        story.append(p(
            f"Each resource check is weighted by severity (Critical {score['weights']['CRITICAL']:g}, High "
            f"{score['weights']['HIGH']:g}, Medium {score['weights']['MEDIUM']:g}, Low {score['weights']['LOW']:g}, "
            f"Info {score['weights']['INFO']:g}). The weighted pass rate was "
            f"{score['weighted_pass_rate'] * 100:.1f}% ({score['failed_weight']:g} of {score['total_weight']:g} weight "
            f"failing). A penalty of {score['critical_penalty']} points was applied for {score['critical_findings']} "
            f"open critical finding(s) (3 points each, capped at 25). Suppressed findings are treated as accepted risk."))

    story.append(p("2. Compliance posture", "h1"))
    rows = [["Framework", "Version", "Score", "Controls passed", "Failed", "N/A"]]
    for c in data["compliance"]:
        rows.append([p(c["name"], "cell"), c["version"], f"{c['score']}%", c["passed"], c["failed"], c["not_applicable"]])
    story.append(_table(rows, [70 * mm, 18 * mm, 18 * mm, 25 * mm, 18 * mm, content_width - 149 * mm]))
    story.append(p("Score is the mean share of compliant resources across assessed controls; a control fails if "
                   "any mapped check fails.", "small"))

    story.append(p("3. Priority remediation", "h1"))
    for i, rec in enumerate(data["recommendations"], 1):
        block = [Paragraph(f"{i}. {escape(rec['title'])} — <font color='#{SEV_COLORS[rec['severity']].hexval()[2:]}'>"
                           f"{rec['severity']}</font> · {rec['count']} resource(s) · {rec['rule_id']}", S["h2"]),
                 p(rec["remediation"])]
        for step in rec["steps"][:4]:
            block.append(p(f"• {step}", "small"))
        story.append(KeepTogether(block))

    story.append(p("4. Asset inventory", "h1"))
    rows = [["Service", "Assets", "Internet-exposed", "With open findings"]]
    for s in data["assets"]["by_service"]:
        rows.append([s["service"], f"{s['count']:,}", s["public"], s["with_findings"]])
    story.append(_table(rows, [50 * mm, 30 * mm, 40 * mm, content_width - 120 * mm]))
    enc_total = data["assets"]["encrypted"] + data["assets"]["unencrypted"]
    if enc_total:
        story.append(Spacer(1, 2 * mm))
        story.append(p(f"Encryption at rest: {data['assets']['encrypted']} of {enc_total} encryptable data stores "
                       f"({100 * data['assets']['encrypted'] / enc_total:.1f}%) are encrypted.", "small"))
    if data["top_risky_assets"]:
        story.append(p("Highest-risk assets", "h2"))
        rows = [["Asset", "Service", "Region", "Risk", "Open findings", "Exposed"]]
        for a in data["top_risky_assets"][:10]:
            rows.append([p(a["name"], "cell"), a["service"], a["region"], f"{a['risk_score']} ({a['risk_level']})",
                         a["open_findings"], "Yes" if a["public_exposure"] else "No"])
        story.append(_table(rows, [60 * mm, 22 * mm, 24 * mm, 26 * mm, 22 * mm, content_width - 154 * mm]))

    story.append(PageBreak())
    heading = "5. Critical and high findings" if data["report_type"] == "executive" else "5. Findings"
    story.append(p(heading, "h1"))
    story.append(p(f"{data['findings_included']} of {data['findings_total_open']} open findings are listed.", "small"))
    if data["report_type"] == "executive":
        rows = [["ID", "Severity", "Finding", "Resource", "Region"]]
        for f in data["findings"]:
            rows.append([f["id"], _sev(f["severity"]), p(f["title"], "cell"), p(f["resource_name"], "cell"), f["region"]])
        story.append(_table(rows, [22 * mm, 19 * mm, 62 * mm, 45 * mm, content_width - 148 * mm]))
    else:
        for f in data["findings"][:400]:
            evidence = json.dumps(f["evidence"], default=str)
            if len(evidence) > 600:
                evidence = evidence[:600] + "…"
            block = [
                Paragraph(f"<b>{escape(f['id'])}</b> · <font color='#{SEV_COLORS[f['severity']].hexval()[2:]}'>"
                          f"{f['severity']}</font> · {escape(f['rule_id'])} — {escape(f['title'])}", S["cell"]),
                p(f"{f['resource']} · {f['region']} · {f['account']} · status {f['status']}", "small"),
                Paragraph(escape(evidence), S["mono"]),
                p(f"Remediation: {f['remediation']}", "small"),
                Spacer(1, 3 * mm),
            ]
            story.append(KeepTogether(block))
        if len(data["findings"]) > 400:
            story.append(p("Additional findings are available in the CSV/JSON export.", "small"))

    story.append(p("6. Scan metadata", "h1"))
    rows = [["Scan", "Account", "Completed", "Duration", "Assets", "Checks", "Status"]]
    for s in data["scans"]:
        rows.append([s["display_id"], p(f"{s['account']} ({s['account_identifier']})", "cell"),
                     _fmt_dt(s["finished_at"]), f"{(s['duration_seconds'] or 0):.1f}s", f"{s['assets']:,}",
                     f"{s['checks']:,}", s["status"]])
    story.append(_table(rows, [22 * mm, 48 * mm, 32 * mm, 18 * mm, 16 * mm, 16 * mm, content_width - 152 * mm]))
    for s in data["scans"]:
        if s["service_errors"]:
            story.append(p(f"{s['display_id']} could not read: " + "; ".join(f"{k} ({v})" for k, v in
                                                                             s["service_errors"].items()), "small"))
    story.append(Spacer(1, 4 * mm))
    story.append(p(f"Methodology: CloudAegis evaluated {data['rules_evaluated']} detection rules using read-only API "
                   "access. No changes were made to the assessed environment.", "small"))

    doc.build(story, onFirstPage=lambda c, d: _on_page(c, d, data), onLaterPages=lambda c, d: _on_page(c, d, data))
    return buffer.getvalue()
