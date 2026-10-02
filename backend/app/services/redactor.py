"""
Applies actual redaction (irreversible black-box + text removal) to PDF and
DOCX files, using the findings produced by pii_detector.

PDF: PyMuPDF's redaction annotations physically strip the underlying text
from the content stream (not just paint a box over it). Matching is tried
verbatim first; if a finding's text isn't found on the page as-is (which can
happen when a match spans a line wrap or has irregular internal spacing),
whitespace-normalized and line-split fallbacks are tried before giving up —
and giving up is recorded, not silently dropped.

DOCX: redaction is applied by character offset within each paragraph's full
text, not by searching for the matched substring inside individual runs.
This matters: Word frequently splits a single word or phrase across several
runs (autocorrect, spell-check, copy/paste, prior edits), so a PII span can
start in one run and end in another. Offset-based redaction blanks exactly
the characters that fall within a match in every run they touch, regardless
of run boundaries — a plain substring search inside each run misses these
cases entirely. Table cells (recursively) and headers/footers are covered
via the same keyed-paragraph structure used for detection.
"""
import re
from pathlib import Path
from typing import Dict, List, Tuple
import fitz  # PyMuPDF
import docx
from docx.enum.text import WD_COLOR_INDEX

from app.services.pii_detector import Finding
from app.services.extractors import extract_pdf_pages, iter_all_docx_paragraphs
from app.utils.metadata import scrub_pdf_metadata, strip_pdf_annotations_and_links, scrub_docx_document


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------
def _ws_normalize(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _search_text_on_page(page: "fitz.Page", text: str) -> list:
    """Verbatim search first; fall back to whitespace-normalized and
    line-split search for matches that span line breaks or irregular
    spacing that a literal substring search won't find."""
    areas = page.search_for(text)
    if areas:
        return areas

    normalized = _ws_normalize(text)
    if normalized and normalized != text:
        areas = page.search_for(normalized)
        if areas:
            return areas

    if "\n" in text:
        areas = []
        for line in text.split("\n"):
            line = line.strip()
            if len(line) >= 3:
                areas.extend(page.search_for(line))
        return areas

    return []


def redact_pdf(src_path: Path, dst_path: Path, findings_by_page: Dict[int, List[Finding]]) -> dict:
    """
    findings_by_page: {page_number: [Finding, ...]}.
    Findings with a non-empty bbox use coordinate-based redaction (for OCR/scanned PDFs).
    Findings without bbox use text-search redaction (for normal text PDFs).
    Returns stats: redacted_boxes, unmatched_findings, plus metadata-scrub stats.
    """
    total_boxes = 0
    unmatched = 0
    doc = fitz.open(src_path)
    try:
        for page_number, findings in findings_by_page.items():
            if page_number >= len(doc):
                continue
            page = doc[page_number]
            for finding in findings:
                # Use bbox coordinates if available (OCR/scanned PDF path)
                bbox = getattr(finding, "bbox", None)
                if bbox and len(bbox) == 4:
                    rect = fitz.Rect(bbox[0], bbox[1], bbox[2], bbox[3])
                    page.add_redact_annot(rect, fill=(0, 0, 0))
                    total_boxes += 1
                    continue

                # Text-search path (normal text PDF)
                text = finding.text.strip()
                if not text:
                    continue
                areas = _search_text_on_page(page, text)
                if not areas:
                    unmatched += 1
                    continue
                for rect in areas:
                    page.add_redact_annot(rect, fill=(0, 0, 0))
                    total_boxes += 1
            page.apply_redactions()

        annot_stats = {"annotations_removed": 0, "links_removed": 0}
        for page in doc:
            page_stats = strip_pdf_annotations_and_links(page)
            for k in annot_stats:
                annot_stats[k] += page_stats[k]
        meta_stats = scrub_pdf_metadata(doc)

        doc.save(dst_path, garbage=4, deflate=True)
    finally:
        doc.close()

    return {
        "redacted_boxes": total_boxes,
        "unmatched_findings": unmatched,
        **annot_stats,
        **meta_stats,
    }


def group_findings_by_page(findings: List[Finding], page_offsets: List[int]) -> Dict[int, List[Finding]]:
    """
    Given global character offsets into the full concatenated PDF text and the
    per-page starting offsets, bucket findings by page number.
    """
    by_page: Dict[int, List[Finding]] = {}
    for finding in findings:
        page_number = 0
        for i, offset in enumerate(page_offsets):
            if finding.start >= offset:
                page_number = i
            else:
                break
        by_page.setdefault(page_number, []).append(finding)
    return by_page


def build_pdf_page_offsets(path: Path) -> List[int]:
    """Character offset at which each page's text begins, matching the
    newline-joined concatenation used for PII detection.
    Uses PyMuPDF directly (no OCR) — this is only needed for text-based PDFs."""
    import fitz as _fitz
    offsets = []
    running = 0
    with _fitz.open(path) as doc:
        for page in doc:
            offsets.append(running)
            running += len(page.get_text("text")) + 1
    return offsets


# ---------------------------------------------------------------------------
# DOCX
# ---------------------------------------------------------------------------
def _merge_spans(spans: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not spans:
        return []
    spans = sorted(spans)
    merged = [spans[0]]
    for s, e in spans[1:]:
        if s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    return merged


def _redact_paragraph_by_offsets(paragraph, spans: List[Tuple[int, int]]) -> int:
    """
    Blank out exactly the characters in `spans` (offsets into the paragraph's
    full concatenated text), wherever they fall across the paragraph's runs.
    This is what makes redaction correct even when a match is split across
    multiple runs — each run only has its overlapping portion blanked, based
    on absolute position, not on whether the matched substring happens to
    sit entirely inside one run's own text.
    """
    merged = _merge_spans(spans)
    if not merged:
        return 0

    touched_runs = 0
    pos = 0
    for run in paragraph.runs:
        run_text = run.text
        run_len = len(run_text)
        run_start, run_end = pos, pos + run_len
        if run_len == 0:
            continue

        chars = list(run_text)
        touched = False
        for s, e in merged:
            ov_start, ov_end = max(s, run_start), min(e, run_end)
            if ov_start < ov_end:
                touched = True
                for i in range(ov_start - run_start, ov_end - run_start):
                    chars[i] = "█"
        if touched:
            run.text = "".join(chars)
            run.font.highlight_color = WD_COLOR_INDEX.BLACK
            touched_runs += 1
        pos = run_end
    return touched_runs


def redact_docx(src_path: Path, dst_path: Path, findings_by_key: Dict[str, List[Finding]]) -> dict:
    """
    findings_by_key: {paragraph_key: [Finding, ...]} where each Finding's
    start/end are offsets into that specific paragraph's text (body
    paragraph, table cell paragraph, or header/footer paragraph — see
    extractors.iter_all_docx_paragraphs for the full coverage).
    """
    document = docx.Document(str(src_path))
    total_runs_touched = 0
    total_spans = sum(len(v) for v in findings_by_key.values())

    for key, paragraph in iter_all_docx_paragraphs(document):
        findings = findings_by_key.get(key)
        if not findings:
            continue
        spans = [(f.start, f.end) for f in findings]
        total_runs_touched += _redact_paragraph_by_offsets(paragraph, spans)

    meta_stats = scrub_docx_document(document)
    document.save(str(dst_path))

    return {
        "redacted_boxes": total_spans,
        "runs_modified": total_runs_touched,
        **meta_stats,
    }
