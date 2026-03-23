"""Document payload crafting — embed hidden instructions into real files.

Strategies:
  hidden_text  — white text on white background (invisible to humans, visible to extractors)
  metadata     — inject into PDF metadata fields (Author, Subject, Keywords)
  annotation   — inject into PDF annotations/comments

The generated PDF looks completely normal when opened. The payload is only
visible to text extraction pipelines (PyPDF, pdfminer, Unstructured, etc.)
which is exactly what RAG systems use.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class CraftResult:
    output_path: str
    strategy: str
    payload_length: int
    cover_text: str
    file_size_bytes: int


# Default cover text that makes the PDF look like a real business document
DEFAULT_COVER = """\
Meridian Technologies - Internal Policy Update
Document ID: POL-2026-Q1-{doc_id}
Classification: Internal Use Only
Effective Date: March 2026

1. PURPOSE
   This document provides updated procedures for the Q1 operating period.

2. SCOPE
   All customer-facing support agents and automated systems.

3. PROCEDURES
   3.1 All customer inquiries should be handled per the standard operating
       procedure documented in the support handbook.
   3.2 Escalation paths remain unchanged from Q4 2025.
   3.3 Response time SLAs: P1 = 1hr, P2 = 4hr, P3 = 24hr.

4. APPROVAL
   Approved by: Operations Committee
   Date: {date}
"""


def craft_pdf(
    payload: str,
    strategy: str = "hidden_text",
    output: str | None = None,
    cover_text: str | None = None,
    doc_id: str | None = None,
) -> CraftResult:
    """Generate a PDF with an embedded hidden payload.

    Args:
        payload: The injection text to hide in the document
        strategy: Embedding strategy (hidden_text, metadata, annotation)
        output: Output file path (default: ./poison-{strategy}.pdf)
        cover_text: Custom visible content (default: business document template)
        doc_id: Document ID for the cover template

    Returns:
        CraftResult with path and metadata
    """
    from fpdf import FPDF

    if doc_id is None:
        import uuid
        doc_id = str(uuid.uuid4())[:8]

    if cover_text is None:
        from datetime import date
        cover_text = DEFAULT_COVER.format(doc_id=doc_id, date=date.today().isoformat())

    if output is None:
        output = f"poison-{strategy}.pdf"

    # Sanitize text for built-in Helvetica (latin-1 only)
    def _sanitize(text: str) -> str:
        replacements = {"\u2014": "-", "\u2013": "-", "\u2018": "'", "\u2019": "'",
                        "\u201c": '"', "\u201d": '"', "\u2026": "...", "\u00a0": " "}
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text.encode("latin-1", errors="replace").decode("latin-1")

    cover_text = _sanitize(cover_text)
    payload = _sanitize(payload)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    if strategy == "hidden_text":
        _apply_hidden_text(pdf, cover_text, payload)
    elif strategy == "metadata":
        _apply_metadata(pdf, cover_text, payload)
    elif strategy == "annotation":
        _apply_annotation(pdf, cover_text, payload)
    else:
        raise ValueError(f"Unknown strategy: {strategy}. Use: hidden_text, metadata, annotation")

    pdf.output(output)

    return CraftResult(
        output_path=str(Path(output).resolve()),
        strategy=strategy,
        payload_length=len(payload),
        cover_text=cover_text[:100] + "...",
        file_size_bytes=os.path.getsize(output),
    )


def _apply_hidden_text(pdf: Any, cover_text: str, payload: str) -> None:
    """Strategy: white text on white background.

    The payload is rendered in 1pt white font on page 1, then the visible
    cover text is layered on top in normal black font. Text extractors
    (pypdf, pdfminer, Unstructured) extract BOTH — the hidden payload
    and the visible text. Humans see only the cover text.
    """
    pdf.add_page()

    # Write the hidden payload first — white text, tiny font
    pdf.set_font("Helvetica", size=1)
    pdf.set_text_color(255, 255, 255)  # White on white
    pdf.multi_cell(0, 1, payload)

    # Now write the visible cover text on top
    pdf.set_xy(10, 10)  # Reset to top
    pdf.set_font("Helvetica", size=11)
    pdf.set_text_color(0, 0, 0)  # Black
    for line in cover_text.split("\n"):
        pdf.cell(0, 6, line, new_x="LMARGIN", new_y="NEXT")


def _apply_annotation(pdf: Any, cover_text: str, payload: str) -> None:
    """Strategy: inject payload into PDF text annotations.

    Uses fpdf2's text_annotation() to embed the payload as a PDF comment/note
    annotation. Text extractors and some RAG pipelines read annotation contents.
    The annotation is rendered as a tiny invisible marker on the page.
    """
    pdf.add_page()

    # Add a text annotation containing the payload (near top-left, minimal size)
    # fpdf2's text_annotation creates a /Text annotation in the PDF
    pdf.text_annotation(
        x=1, y=1,
        text=payload,
    )

    # Normal visible content on top
    pdf.set_font("Helvetica", size=11)
    pdf.set_text_color(0, 0, 0)
    for line in cover_text.split("\n"):
        pdf.cell(0, 6, line, new_x="LMARGIN", new_y="NEXT")


def _apply_metadata(pdf: Any, cover_text: str, payload: str) -> None:
    """Strategy: inject payload into PDF metadata fields.

    Many RAG pipelines extract metadata (title, author, subject, keywords)
    and include it in the document's text representation. The payload goes
    into these fields. The visible document looks completely normal.
    """
    pdf.set_title(payload[:200])
    pdf.set_author(payload[:200])
    pdf.set_subject(payload[:500])
    pdf.set_keywords(payload)

    # Normal visible content
    pdf.add_page()
    pdf.set_font("Helvetica", size=11)
    pdf.set_text_color(0, 0, 0)
    for line in cover_text.split("\n"):
        pdf.cell(0, 6, line, new_x="LMARGIN", new_y="NEXT")
