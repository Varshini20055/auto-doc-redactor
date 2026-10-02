"""
Post-redaction verification.

A redaction pipeline that only reports "I redacted N things" is trusting
itself. For something a compliance officer signs off on, the tool needs to
independently re-check its own output: re-extract text from the *redacted*
file and re-run the same PII detectors against it. If anything still fires,
that's a signal the redaction missed something — surfaced as a concrete
finding, not buried.

Important: this module never persists or returns the actual matched text of
a residual finding — only its type, location, and confidence — so the
verification step itself can't become a new way to leak PII through logs
or API responses.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import List

from app.services.extractors import extract_pdf_pages, extract_docx_paragraphs
from app.services.pii_detector import detect_all


@dataclass
class ResidualFinding:
    entity_type: str
    location: str      # e.g. "page 2" or "table0:r1c2p0"
    score: float
    page_number: int | None = None
    line_number: int | None = None
    category: str = "actual_unmatched"
    fingerprint: tuple[str, str] | None = None


def _fingerprint(entity_type: str, text: str) -> tuple[str, str]:
    return entity_type, hashlib.sha256(text.encode("utf-8")).hexdigest()


def _line_number(page_text, page_lines, start: int, end: int) -> int | None:
    offset = 0
    for line in page_lines:
        line_start = page_text.find(line["text"], offset)
        if line_start >= 0:
            line_end = line_start + len(line["text"])
            if line_start <= end and start <= line_end:
                return line.get("line_number")
            offset = line_end
    return None


def verify_pdf(redacted_path: Path, entities: List[str] | None = None) -> List[ResidualFinding]:
    residual = []
    pages = extract_pdf_pages(redacted_path)
    for page in pages:
        for f in detect_all(page.text, entities):
            residual.append(ResidualFinding(
                entity_type=f.entity_type,
                location=f"page {page.page_number + 1}",
                score=f.score,
                page_number=page.page_number + 1,
                line_number=_line_number(page.text, page.lines, f.start, f.end),
                fingerprint=_fingerprint(f.entity_type, f.text),
            ))
    return residual


def verify_docx(redacted_path: Path, entities: List[str] | None = None) -> List[ResidualFinding]:
    residual = []
    paragraphs = extract_docx_paragraphs(redacted_path)
    for p in paragraphs:
        for f in detect_all(p.text, entities):
            residual.append(ResidualFinding(
                entity_type=f.entity_type,
                location=p.key,
                score=f.score,
                fingerprint=_fingerprint(f.entity_type, f.text),
            ))
    return residual


def verify_redaction(redacted_path: Path, file_type: str,
                     entities: List[str] | None = None,
                     original_path: Path | None = None) -> dict:
    """Re-check output and classify residuals without returning matched text."""
    original_fingerprints = set()
    if original_path:
        original_pages = extract_pdf_pages(original_path) if file_type == "pdf" else extract_docx_paragraphs(original_path)
        if file_type == "pdf":
            for page in original_pages:
                original_fingerprints.update(
                    _fingerprint(f.entity_type, f.text)
                    for f in detect_all(page.text, entities)
                )
        else:
            for paragraph in original_pages:
                original_fingerprints.update(
                    _fingerprint(f.entity_type, f.text)
                    for f in detect_all(paragraph.text, entities)
                )

    if file_type == "pdf":
        residual = verify_pdf(redacted_path, entities)
    elif file_type == "docx":
        residual = verify_docx(redacted_path, entities)
    else:
        raise ValueError(f"Unsupported file_type: {file_type}")

    entity_counts: dict[str, int] = {}
    context_count = 0
    for r in residual:
        # A residual whose fingerprint was present in the original scan is an
        # actual unmatched finding. Otherwise it was introduced by re-analysis
        # of the altered output and is informational context only.
        if original_fingerprints:
            r.category = "actual_unmatched" if r.fingerprint in original_fingerprints else "post_redaction_context_match"
        if r.category == "actual_unmatched":
            entity_counts[r.entity_type] = entity_counts.get(r.entity_type, 0) + 1
        else:
            context_count += 1

    return {
        "verified": sum(entity_counts.values()) == 0,
        "residual_count": sum(entity_counts.values()),
        "residual_entity_types": entity_counts,
        "post_redaction_context_matches": context_count,
        "verification_findings": [
            {
                "entity_type": r.entity_type,
                "page_number": r.page_number,
                "line_number": r.line_number,
                "location": r.location,
                "score": r.score,
                "category": r.category,
            }
            for r in residual
        ],
    }
