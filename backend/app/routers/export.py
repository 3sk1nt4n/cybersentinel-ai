"""
CyberSentinel v3.0 - Report Export Router (Phase 3)
Export chat conversations as PDF or Markdown reports.
"""
import io
import re
import datetime
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

router = APIRouter(prefix="/export", tags=["export"])


class ExportMessage(BaseModel):
    role: str
    content: str


class ExportRequest(BaseModel):
    messages: list[ExportMessage]
    title: str | None = "CyberSentinel Security Report"
    format: str = "pdf"  # pdf or md


def _strip_markdown(text: str) -> str:
    """Convert markdown to plain-ish text for PDF."""
    # Remove code block markers but keep content
    text = re.sub(r'```\w*\n?', '', text)
    # Bold
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
    # Inline code
    text = re.sub(r'`([^`]+)`', r'\1', text)
    return text


def _generate_pdf(messages: list[ExportMessage], title: str) -> bytes:
    """Generate a professional PDF report from chat messages."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, PageBreak,
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
    except ImportError:
        # Fallback: return a simple text-based PDF-like response
        return _generate_simple_pdf(messages, title)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'CSTitle', parent=styles['Title'],
        fontSize=22, textColor=HexColor('#00f0ff'),
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        'CSSubtitle', parent=styles['Normal'],
        fontSize=10, textColor=HexColor('#9ca3af'),
        spaceAfter=20,
    )
    user_style = ParagraphStyle(
        'CSUser', parent=styles['Normal'],
        fontSize=10, textColor=HexColor('#333333'),
        leftIndent=20, spaceBefore=12, spaceAfter=4,
        backColor=HexColor('#f0f0f0'),
    )
    assistant_style = ParagraphStyle(
        'CSAssistant', parent=styles['Normal'],
        fontSize=10, textColor=HexColor('#1a1a2e'),
        leftIndent=20, spaceBefore=4, spaceAfter=12,
        leading=14,
    )
    code_style = ParagraphStyle(
        'CSCode', parent=styles['Code'],
        fontSize=8, textColor=HexColor('#00f0ff'),
        backColor=HexColor('#1a1d26'),
        leftIndent=20, rightIndent=10,
        spaceBefore=4, spaceAfter=4,
    )
    section_style = ParagraphStyle(
        'CSSection', parent=styles['Heading2'],
        fontSize=12, textColor=HexColor('#ff3355'),
        spaceBefore=16, spaceAfter=8,
    )

    elements = []

    # Header
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    elements.append(Paragraph("🛡️ CYBERSENTINEL AI", title_style))
    elements.append(Paragraph(f"{title}", styles['Heading2']))
    elements.append(Paragraph(
        f"Generated: {now} | Powered by SolventCyber.com | {len(messages)} messages",
        subtitle_style
    ))
    elements.append(HRFlowable(width="100%", thickness=1, color=HexColor('#00f0ff')))
    elements.append(Spacer(1, 12))

    # Messages
    for i, msg in enumerate(messages):
        if msg.role == 'user':
            elements.append(Paragraph(f"<b>👤 USER</b>", section_style))
            # Clean text for PDF
            clean = _strip_markdown(msg.content).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            for line in clean.split('\n'):
                if line.strip():
                    elements.append(Paragraph(line, user_style))
        else:
            elements.append(Paragraph(f"<b>🛡️ CYBERSENTINEL</b>", section_style))
            clean = _strip_markdown(msg.content)
            # Split into code blocks and regular text
            parts = re.split(r'(```[\s\S]*?```)', msg.content)
            for part in parts:
                if part.startswith('```'):
                    code_text = re.sub(r'```\w*\n?', '', part).strip()
                    code_text = code_text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    for code_line in code_text.split('\n'):
                        elements.append(Paragraph(code_line, code_style))
                else:
                    text = _strip_markdown(part).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    for line in text.split('\n'):
                        if line.strip():
                            elements.append(Paragraph(line, assistant_style))

        elements.append(Spacer(1, 8))

    # Footer
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=1, color=HexColor('#333333')))
    elements.append(Paragraph(
        f"CyberSentinel AI v3.0 | SolventCyber.com | Confidential",
        subtitle_style,
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer.read()


def _generate_simple_pdf(messages: list[ExportMessage], title: str) -> bytes:
    """Fallback PDF generator without reportlab - creates a formatted text file."""
    # If reportlab isn't available, return markdown as a downloadable file
    lines = [
        f"# 🛡️ CYBERSENTINEL AI - {title}",
        f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"Messages: {len(messages)}",
        "---",
        "",
    ]
    for msg in messages:
        prefix = "👤 USER" if msg.role == "user" else "🛡️ CYBERSENTINEL"
        lines.append(f"## {prefix}")
        lines.append(msg.content)
        lines.append("")
        lines.append("---")
        lines.append("")
    lines.append("CyberSentinel AI v3.0 | SolventCyber.com")
    return "\n".join(lines).encode("utf-8")


@router.post("/pdf")
async def export_pdf(req: ExportRequest):
    """Export conversation as PDF report."""
    pdf_bytes = _generate_pdf(req.messages, req.title or "Security Report")
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="cybersentinel-report-{datetime.datetime.now().strftime("%Y%m%d-%H%M")}.pdf"'},
    )


@router.post("/markdown")
async def export_markdown(req: ExportRequest):
    """Export conversation as Markdown."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        f"# 🛡️ CyberSentinel AI - {req.title or 'Security Report'}",
        f"> Generated: {now} | Powered by SolventCyber.com",
        "",
        "---",
        "",
    ]
    for msg in req.messages:
        prefix = "👤 You" if msg.role == "user" else "🛡️ CyberSentinel"
        lines.append(f"## {prefix}")
        lines.append("")
        lines.append(msg.content)
        lines.append("")
        lines.append("---")
        lines.append("")
    lines.append(f"*CyberSentinel AI v3.0 | SolventCyber.com*")

    md_bytes = "\n".join(lines).encode("utf-8")
    return StreamingResponse(
        io.BytesIO(md_bytes),
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="cybersentinel-report-{datetime.datetime.now().strftime("%Y%m%d-%H%M")}.md"'},
    )
