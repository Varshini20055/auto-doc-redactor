"""
Generates a one-page "Redaction Certificate" PDF summarizing what happened
to a document: what was found, what was removed, whether independent
verification found anything left over, and what metadata/hidden-data was
stripped. This is the artifact a compliance officer or auditor actually
wants to see — not just the sanitized file, but proof of what was done to
it and confirmation it was checked afterward.

Deliberately contains no matched PII text itself — only entity types,
counts, and pass/fail verification status.
"""
import datetime as dt
from pathlib import Path
from typing import Dict
import fitz  # PyMuPDF


def _draw_kv_table(page, x, y, rows, col1_w=220, row_h=18, font_size=10):
    for label, value in rows:
        page.insert_text((x, y), label, fontsize=font_size, fontname="helv", color=(0.3, 0.3, 0.3))
        page.insert_text((x + col1_w, y), str(value), fontsize=font_size, fontname="helv", color=(0.05, 0.05, 0.05))
        y += row_h
    return y


def generate_certificate(
    output_path: Path,
    document_id: str,
    original_filename: str,
    file_type: str,
    checksum_original: str,
    checksum_redacted: str,
    entity_counts: Dict[str, int],
    redacted_boxes: int,
    unmatched_findings: int,
    verification: dict,
    metadata_stats: dict,
    docx_risk_flags: dict | None = None,
    llm_enabled: bool = False,
) -> Path:
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)  # US Letter

    y = 54
    page.insert_text((54, y), "REDACTION CERTIFICATE", fontsize=20, fontname="helv", color=(0.05, 0.05, 0.05))
    y += 10
    page.draw_line((54, y + 10), (558, y + 10), color=(0.1, 0.1, 0.1), width=1.2)
    y += 34

    page.insert_text((54, y), "Auto-Doc Redactor — automated PII detection & redaction record",
                      fontsize=10, fontname="helv", color=(0.35, 0.35, 0.35))
    y += 30

    def _short_hash(h: str) -> str:
        return h if len(h) <= 24 else f"{h[:16]}…{h[-8:]}"

    generated_at = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    y = _draw_kv_table(page, 54, y, [
        ("Document ID", document_id),
        ("Original filename", original_filename),
        ("File type", file_type.upper()),
        ("Certificate generated", generated_at),
        ("SHA-256 (original, encrypted)", _short_hash(checksum_original)),
        ("SHA-256 (redacted output)", _short_hash(checksum_redacted)),
    ])
    y += 16

    page.insert_text((54, y), "Detection & Redaction Summary", fontsize=13, fontname="helv", color=(0.05, 0.05, 0.05))
    y += 22
    total_entities = sum(entity_counts.values())
    y = _draw_kv_table(page, 54, y, [
        ("Total PII spans detected", total_entities),
        ("Redaction marks applied", redacted_boxes),
        ("Findings not matched on page*", unmatched_findings),
        ("Detection engine", "Presidio + spaCy" + (" + LLM context pass" if llm_enabled else "")),
    ])
    y += 10

    if entity_counts:
        page.insert_text((54, y), "By entity type:", fontsize=10, fontname="helv", color=(0.3, 0.3, 0.3))
        y += 16
        for etype, count in sorted(entity_counts.items(), key=lambda kv: -kv[1]):
            page.insert_text((74, y), f"{etype}", fontsize=9.5, fontname="helv", color=(0.05, 0.05, 0.05))
            page.insert_text((300, y), str(count), fontsize=9.5, fontname="helv", color=(0.05, 0.05, 0.05))
            y += 15
    y += 12

    page.insert_text((54, y), "Independent Verification", fontsize=13, fontname="helv", color=(0.05, 0.05, 0.05))
    y += 22
    verified = verification.get("verified", False)
    status_text = "PASSED — no residual PII detected in output" if verified else "ATTENTION — residual PII detected in output"
    status_color = (0.11, 0.42, 0.14) if verified else (0.58, 0.15, 0.1)
    page.insert_text((54, y), status_text, fontsize=11, fontname="helv", color=status_color)
    y += 20
    y = _draw_kv_table(page, 54, y, [
        ("Residual findings", verification.get("residual_count", 0)),
    ])
    if verification.get("residual_entity_types"):
        for etype, count in verification["residual_entity_types"].items():
            page.insert_text((74, y), f"{etype}: {count}", fontsize=9.5, fontname="helv", color=(0.58, 0.15, 0.1))
            y += 15
    y += 12

    page.insert_text((54, y), "Metadata & Hidden Data Scrubbed", fontsize=13, fontname="helv", color=(0.05, 0.05, 0.05))
    y += 22
    meta_rows = [(k.replace("_", " ").capitalize(), v) for k, v in metadata_stats.items()]
    meta_rows += [("Document metadata (author/title/etc.)", "Cleared")]
    y = _draw_kv_table(page, 54, y, meta_rows)
    y += 12

    if docx_risk_flags:
        has_risk = any(v > 0 for v in docx_risk_flags.values())
        if has_risk:
            page.insert_text((54, y), "Notes", fontsize=13, fontname="helv", color=(0.05, 0.05, 0.05))
            y += 22
            if docx_risk_flags.get("embedded_objects", 0) > 0:
                note_lines = [
                    f"* {docx_risk_flags['embedded_objects']} embedded object(s) detected (e.g. linked",
                    "  spreadsheets/images). Content inside embedded objects is not scanned — review manually.",
                ]
                for line in note_lines:
                    page.insert_text((54, y), line, fontsize=9, fontname="helv", color=(0.58, 0.4, 0.1))
                    y += 14

    y = max(y, 700)
    page.draw_line((54, y), (558, y), color=(0.8, 0.8, 0.8), width=0.8)
    y += 14
    footer_lines = [
        "* A finding not matched on its page can occur if source formatting prevents an exact text",
        "  match; this is surfaced here rather than silently dropped so it can be reviewed manually.",
        "This certificate confirms the automated steps performed above. It is not a substitute for",
        "manual legal/compliance review of the output document.",
    ]
    for line in footer_lines:
        page.insert_text((54, y), line, fontsize=7.5, fontname="helv", color=(0.5, 0.5, 0.5))
        y += 11

    doc.save(output_path)
    doc.close()
    return output_path
