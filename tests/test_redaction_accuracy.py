"""
Regression tests for the redaction-accuracy fixes.

Each test here reproduces a specific real-world failure mode that a naive
redaction implementation gets wrong, and asserts the fix actually holds —
not just that the code runs, but that the sensitive text is genuinely gone
from the output file afterward.
"""
import tempfile
from pathlib import Path

import docx
import fitz

from app.services.extractors import iter_all_docx_paragraphs, find_table_label_findings, extract_pdf_pages
from app.services.redactor import redact_docx, redact_pdf, group_findings_by_page, build_pdf_page_offsets
from app.services.pii_detector import detect_all
from app.services.verification import verify_docx, verify_pdf


def _tmp_path(suffix: str) -> Path:
    fd = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    fd.close()
    return Path(fd.name)


# ---------------------------------------------------------------------------
# DOCX: PII split across multiple <w:r> runs
# ---------------------------------------------------------------------------
def test_redacts_pii_split_across_runs():
    """A plain substring search inside each run misses PII that starts in
    one run and ends in another — a very common real-world case (Word
    autocorrect, spell-check, or copy/paste routinely splits runs mid-word).
    Offset-based redaction must catch this."""
    src = _tmp_path(".docx")
    dst = _tmp_path(".docx")
    try:
        d = docx.Document()
        p = d.add_paragraph()
        p.add_run("Call the patient at 415-555")
        p.add_run("-2671 to confirm.")
        d.save(src)

        # Confirm the test actually exercises the cross-run case.
        d2 = docx.Document(str(src))
        assert len(d2.paragraphs[0].runs) == 2
        assert "415-555-2671" not in d2.paragraphs[0].runs[0].text  # split, not whole

        findings_by_key = {}
        for key, paragraph in iter_all_docx_paragraphs(d2):
            findings = detect_all(paragraph.text, score_threshold=0.1)
            if findings:
                findings_by_key[key] = findings

        redact_docx(src, dst, findings_by_key)

        result = docx.Document(str(dst))
        full_text = "\n".join(p.text for p in result.paragraphs)
        assert "415-555-2671" not in full_text
        assert "415" not in full_text or "█" in full_text  # digits gone, replaced with block chars
    finally:
        src.unlink(missing_ok=True)
        dst.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# DOCX: PII inside table cells
# ---------------------------------------------------------------------------
def test_detects_and_redacts_pii_in_table_cells():
    """Table cells are a primary location for PII in legal/medical/financial
    documents. They must be scanned and redacted, not just body paragraphs."""
    src = _tmp_path(".docx")
    dst = _tmp_path(".docx")
    try:
        d = docx.Document()
        table = d.add_table(rows=2, cols=2)
        table.rows[0].cells[0].text = "Account Holder"
        table.rows[0].cells[1].text = "Jane Doe"
        table.rows[1].cells[0].text = "SSN"
        table.rows[1].cells[1].text = "294-81-5563"
        d.save(src)

        d2 = docx.Document(str(src))
        findings_by_key = {}
        for key, paragraph in iter_all_docx_paragraphs(d2):
            findings = detect_all(paragraph.text, score_threshold=0.1)
            if findings:
                findings_by_key[key] = findings
        table_findings = find_table_label_findings(d2)
        for key, findings in table_findings.items():
            findings_by_key.setdefault(key, []).extend(findings)

        # The label-aware pass must catch these even if general NER doesn't.
        assert any(f.entity_type == "PERSON" for fs in table_findings.values() for f in fs)
        assert any(f.entity_type == "US_SSN" for fs in table_findings.values() for f in fs)

        redact_docx(src, dst, findings_by_key)

        result = docx.Document(str(dst))
        cell_texts = [c.text for row in result.tables[0].rows for c in row.cells]
        assert "Jane Doe" not in cell_texts
        assert "294-81-5563" not in cell_texts
    finally:
        src.unlink(missing_ok=True)
        dst.unlink(missing_ok=True)


def test_table_header_row_not_misidentified_as_data():
    """Regression test for a bug caught during development: a header row
    like 'Name | Email | Phone' must not have its own 'Email'/'Phone' cells
    tagged PERSON just because column 0 said 'Name'."""
    d = docx.Document()
    table = d.add_table(rows=2, cols=3)
    table.rows[0].cells[0].text = "Name"
    table.rows[0].cells[1].text = "Email"
    table.rows[0].cells[2].text = "Phone"
    table.rows[1].cells[0].text = "Robert Chen"
    table.rows[1].cells[1].text = "r.chen@corpmail.com"
    table.rows[1].cells[2].text = "212-555-8890"

    results = find_table_label_findings(d)
    # Header row (row 0) must not appear as a target of any finding.
    header_keys = {"table0:r0c0p0", "table0:r0c1p0", "table0:r0c2p0"}
    assert not (set(results.keys()) & header_keys)
    # Data row (row 1) must be correctly tagged.
    assert results.get("table0:r1c0p0", [None])[0].entity_type == "PERSON"
    assert results.get("table0:r1c1p0", [None])[0].entity_type == "EMAIL_ADDRESS"
    assert results.get("table0:r1c2p0", [None])[0].entity_type == "PHONE_NUMBER"


# ---------------------------------------------------------------------------
# DOCX: metadata / tracked changes
# ---------------------------------------------------------------------------
def test_core_properties_cleared_after_redaction():
    src = _tmp_path(".docx")
    dst = _tmp_path(".docx")
    try:
        d = docx.Document()
        d.core_properties.author = "Original Author Name"
        d.add_paragraph("No PII here.")
        d.save(src)

        redact_docx(src, dst, {})

        result = docx.Document(str(dst))
        assert result.core_properties.author == ""
    finally:
        src.unlink(missing_ok=True)
        dst.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# PDF: end-to-end redaction + verification
# ---------------------------------------------------------------------------
def test_pdf_redaction_removes_text_from_content_stream():
    src = _tmp_path(".pdf")
    dst = _tmp_path(".pdf")
    try:
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((50, 50), "Contact: john.smith@example.com")
        doc.save(src)
        doc.close()

        pages = extract_pdf_pages(src)
        full_text = "\n".join(p.text for p in pages)
        findings = detect_all(full_text, score_threshold=0.1)
        offsets = build_pdf_page_offsets(src)
        by_page = group_findings_by_page(findings, offsets)

        redact_pdf(src, dst, by_page)

        result_pages = extract_pdf_pages(dst)
        assert "john.smith@example.com" not in result_pages[0].text
    finally:
        src.unlink(missing_ok=True)
        dst.unlink(missing_ok=True)


def test_verification_catches_residual_pii():
    """The verification pass must independently detect PII left in a file —
    proven here by checking a file that was *not* redacted."""
    src = _tmp_path(".pdf")
    try:
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((50, 50), "Contact: john.smith@example.com")
        doc.save(src)
        doc.close()

        residual = verify_pdf(src)
        assert any(r.entity_type == "EMAIL_ADDRESS" for r in residual)
    finally:
        src.unlink(missing_ok=True)


def test_verification_passes_on_clean_file():
    src = _tmp_path(".pdf")
    try:
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((50, 50), "This page has no sensitive information at all.")
        doc.save(src)
        doc.close()

        residual = verify_pdf(src)
        assert residual == []
    finally:
        src.unlink(missing_ok=True)
