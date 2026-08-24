"""
Reporting & Documentation — Group 13.

PDF generation uses reportlab directly (no HTML-to-PDF step) — keeps the
dependency list short and the output deterministic. CSV export is stdlib
`csv` only. Both take already-aggregated data (stats dicts, row lists) as
input rather than querying the database themselves, so they're testable
without a live Postgres connection — the aggregation queries themselves
live in app/api/routes/reports.py, right next to the endpoint that has a
DB session to run them with.
"""

import csv
import io
import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from app.core.config import settings


# ---------------------------------------------------------------------------
# Feature 122: CSV Export
# ---------------------------------------------------------------------------

def generate_csv(rows: list[dict], fieldnames: list[str]) -> str:
    """Returns CSV content as a string — caller decides whether to write
    it to disk (for Report.file_path) or stream it directly as an HTTP
    response."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Features 121, 123-129: PDF report generation (summary / incident / daily
# / weekly / monthly / threat-intel / system-health — all the same
# generator, different title + data)
# ---------------------------------------------------------------------------

def generate_pdf(
    title: str,
    period_label: str,
    stats: dict,
    top_attackers: list[dict],
    alerts: list[dict],
    output_path: str,
) -> str:
    """Writes a PDF to output_path and returns that path. `stats` is a
    flat dict of label->value shown as a summary table; `top_attackers`
    and `alerts` are lists of dicts rendered as their own tables."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("HoneyShield X — Security Report", styles["Title"]))
    story.append(Paragraph(title, styles["Heading2"]))
    story.append(Paragraph(period_label, styles["Normal"]))
    story.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()}Z", styles["Normal"]))
    story.append(Spacer(1, 0.3 * inch))

    story.append(Paragraph("Summary", styles["Heading3"]))
    stats_table_data = [["Metric", "Value"]] + [[str(k), str(v)] for k, v in stats.items()]
    story.append(_styled_table(stats_table_data))
    story.append(Spacer(1, 0.3 * inch))

    if top_attackers:
        story.append(Paragraph("Top Attacking Sources", styles["Heading3"]))
        header = list(top_attackers[0].keys())
        rows = [header] + [[str(row.get(h, "")) for h in header] for row in top_attackers]
        story.append(_styled_table(rows))
        story.append(Spacer(1, 0.3 * inch))

    if alerts:
        story.append(Paragraph("Alerts in Period", styles["Heading3"]))
        header = list(alerts[0].keys())
        rows = [header] + [[str(row.get(h, "")) for h in header] for row in alerts]
        story.append(_styled_table(rows))

    doc.build(story)
    return output_path


def _styled_table(data: list[list[str]]) -> Table:
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2634")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
    ]))
    return table


# ---------------------------------------------------------------------------
# Features 125-127: Daily / Weekly / Monthly report helpers — just decide
# the title/period label; the actual DB aggregation happens in the route.
# ---------------------------------------------------------------------------

def build_report_metadata(report_type: str, period_start: datetime, period_end: datetime) -> dict:
    labels = {
        "daily": "Daily Security Summary",
        "weekly": "Weekly Security Summary",
        "monthly": "Monthly Security Summary",
        "incident": "Incident Report",
        "custom": "Custom Report",
    }
    title = labels.get(report_type, "Security Report")
    period_label = f"{period_start.strftime('%Y-%m-%d')} to {period_end.strftime('%Y-%m-%d')}"
    filename = f"{report_type}_{period_start.strftime('%Y%m%d')}_{period_end.strftime('%Y%m%d')}.pdf"
    return {
        "title": title,
        "period_label": period_label,
        "file_path": os.path.join(settings.REPORTS_DIR, filename),
    }


