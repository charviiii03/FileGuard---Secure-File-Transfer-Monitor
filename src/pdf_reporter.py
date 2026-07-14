"""PDF report generation for FileGuard."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    Preformatted,
)


def _draw_header_footer(canvas, document) -> None:
    """Draw the FileGuard header, footer, and page number."""
    canvas.saveState()

    page_width, page_height = landscape(A4)

    canvas.setStrokeColor(colors.HexColor("#3B82F6"))
    canvas.setLineWidth(1)
    canvas.line(18 * mm, page_height - 16 * mm, page_width - 18 * mm, page_height - 16 * mm)

    canvas.setFillColor(colors.HexColor("#0F172A"))
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(18 * mm, page_height - 12 * mm, "FileGuard Security Report")

    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(
        page_width - 18 * mm,
        page_height - 12 * mm,
        datetime.now().strftime("Generated %Y-%m-%d %H:%M:%S"),
    )

    canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
    canvas.line(18 * mm, 14 * mm, page_width - 18 * mm, 14 * mm)

    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.setFont("Helvetica", 8)
    canvas.drawString(18 * mm, 9 * mm, "Secure File Transfer Monitoring System")
    canvas.drawRightString(
        page_width - 18 * mm,
        9 * mm,
        f"Page {document.page}",
    )

    canvas.restoreState()


def create_pdf_report(report_text: str, output_path: str | Path) -> Path:
    """Create a clean downloadable PDF from the FileGuard text report."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "FileGuardTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0F172A"),
        alignment=TA_CENTER,
        spaceAfter=5 * mm,
    )

    subtitle_style = ParagraphStyle(
        "FileGuardSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
        alignment=TA_CENTER,
        spaceAfter=7 * mm,
    )

    code_style = ParagraphStyle(
        "FileGuardCode",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=7.6,
        leading=10.2,
        textColor=colors.HexColor("#0F172A"),
        leftIndent=4 * mm,
        rightIndent=4 * mm,
        borderColor=colors.HexColor("#CBD5E1"),
        borderWidth=0.6,
        borderPadding=5 * mm,
        backColor=colors.HexColor("#F8FAFC"),
        spaceBefore=2 * mm,
        spaceAfter=4 * mm,
    )

    document = SimpleDocTemplate(
        str(output),
        pagesize=landscape(A4),
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=22 * mm,
        bottomMargin=20 * mm,
        title="FileGuard Security Report",
        author="FileGuard",
        subject="Secure file transfer monitoring audit report",
    )

    generated_at = datetime.now().strftime("%d %B %Y, %H:%M:%S")

    story = [
        Paragraph("FileGuard Security Report", title_style),
        Paragraph(
            f"Secure File Transfer Monitoring System<br/>Generated on {generated_at}",
            subtitle_style,
        ),
        Preformatted(
            report_text or "No report data was available.",
            code_style,
            maxLineLength=115,
        ),
    ]

    document.build(
        story,
        onFirstPage=_draw_header_footer,
        onLaterPages=_draw_header_footer,
    )

    return output