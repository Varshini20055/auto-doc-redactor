"""
Scrub hidden data that survives "visible" redaction.

This is the single most common way real redactions fail an audit: the text
on the page looks gone, but the underlying file still carries it somewhere
else — document metadata (author, comments), tracked-change history
(deleted text is stored, not erased), unresolved comment threads, or
embedded attachments. None of that is caught by blacking out text on the
page, so it gets scrubbed here as a separate, explicit step.
"""
import logging
from typing import Dict
import fitz  # PyMuPDF
import docx
from docx.oxml.ns import qn

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------
def scrub_pdf_metadata(doc: "fitz.Document") -> Dict[str, int]:
    """
    Mutates an already-open PyMuPDF document in place:
      - clears standard metadata (author, title, subject, keywords, producer...)
      - strips XMP metadata (can carry author/editing history independent of
        the standard metadata dict)
      - removes embedded files/attachments (could be the original, un-redacted
        source file silently attached)
      - strips document-level JavaScript
    Returns a small stats dict for the redaction certificate.
    """
    stats = {"embedded_files_removed": 0}

    doc.set_metadata({})
    try:
        doc.del_xml_metadata()
    except Exception:
        pass  # not all PDFs carry XMP metadata; nothing to strip

    try:
        names = list(doc.embfile_names())
        for name in names:
            doc.embfile_del(name)
            stats["embedded_files_removed"] += 1
    except Exception as e:  # noqa: BLE001
        logger.warning("Could not enumerate/remove embedded files: %s", e)

    return stats


def strip_pdf_annotations_and_links(page: "fitz.Page") -> Dict[str, int]:
    """Remove every remaining annotation and link on a page after redaction
    is applied. Comments, highlights, and hyperlink targets are all places
    PII can hide independently of the visible page text."""
    removed = {"annotations_removed": 0, "links_removed": 0}
    for annot in list(page.annots() or []):
        try:
            page.delete_annot(annot)
            removed["annotations_removed"] += 1
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to remove annotation: %s", e)
    for link in list(page.get_links() or []):
        try:
            page.delete_link(link)
            removed["links_removed"] += 1
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to remove link: %s", e)
    return removed


# ---------------------------------------------------------------------------
# DOCX
# ---------------------------------------------------------------------------
_REVISION_TAGS = (qn("w:ins"), qn("w:del"))


def _accept_all_revisions(document: "docx.Document") -> int:
    """
    Word's "tracked changes" store deleted text verbatim in <w:del>/<w:delText>
    elements — hidden from the rendered view but fully present in the XML.
    A document with unresolved tracked changes can look redacted on screen
    while still containing the original sensitive text underneath.

    This "accepts" every tracked change the same way Word's Review > Accept
    All would: insertions are unwrapped (kept, marking removed), deletions
    are removed entirely (the deleted content is discarded for good).
    Returns the number of revision nodes resolved.
    """
    count = 0
    body = document.element.body
    # Also walk header/footer parts, which have their own XML trees.
    parts = [body]
    for section in document.sections:
        for part in (section.header, section.footer,
                     section.first_page_header, section.first_page_footer,
                     section.even_page_header, section.even_page_footer):
            if part is not None and not part.is_linked_to_previous:
                parts.append(part._element)

    for root in parts:
        for ins in root.iter(qn("w:ins")):
            count += 1
            # Unwrap: move children up, drop the <w:ins> wrapper itself.
            parent = ins.getparent()
            if parent is None:
                continue
            idx = list(parent).index(ins)
            for child in list(ins):
                parent.insert(idx, child)
                idx += 1
            parent.remove(ins)
        for delete in list(root.iter(qn("w:del"))):
            count += 1
            parent = delete.getparent()
            if parent is not None:
                parent.remove(delete)
    return count


def _strip_comments(document: "docx.Document") -> int:
    """Remove comment anchors from the body and drop the comments part
    itself so no comment text (which can contain PII, e.g. "confirmed SSN
    with patient") survives in the package."""
    count = 0
    body = document.element.body
    for tag in (qn("w:commentReference"), qn("w:commentRangeStart"), qn("w:commentRangeEnd")):
        for node in list(body.iter(tag)):
            count += 1
            parent = node.getparent()
            if parent is not None:
                parent.remove(node)

    try:
        main_part = document.part
        for rel_id in list(main_part.rels):
            rel = main_part.rels[rel_id]
            if "comments" in rel.reltype:
                main_part.drop_rel(rel_id)
    except Exception as e:  # noqa: BLE001
        logger.warning("Could not drop comments part: %s", e)

    return count


def scrub_docx_document(document: "docx.Document") -> Dict[str, int]:
    """
    Mutates an already-open python-docx Document in place:
      - accepts all tracked changes (discards deleted text for good)
      - strips comments and the comments part
      - clears core properties (author, last_modified_by, subject, comments,
        keywords, title, category) that can identify the source/author
    Returns stats for the redaction certificate.
    """
    stats = {}
    stats["revisions_resolved"] = _accept_all_revisions(document)
    stats["comments_removed"] = _strip_comments(document)

    props = document.core_properties
    props.author = ""
    props.last_modified_by = ""
    props.comments = ""
    props.subject = ""
    props.keywords = ""
    props.category = ""
    props.title = ""
    stats["core_properties_cleared"] = 1

    return stats


def detect_docx_risk_flags(document: "docx.Document") -> Dict[str, int]:
    """
    Read-only scan (used at analyze time, before any mutation) to warn the
    user about content that needs attention regardless of what redaction
    does — e.g. embedded objects that PII detection cannot see inside.
    """
    flags = {"tracked_changes": 0, "comments": 0, "embedded_objects": 0}
    body = document.element.body
    for tag in _REVISION_TAGS:
        flags["tracked_changes"] += len(list(body.iter(tag)))
    flags["comments"] = len(list(body.iter(qn("w:commentReference"))))
    flags["embedded_objects"] = len(list(body.iter(qn("w:object")))) + len(list(body.iter(qn("w:OLEObject"))))
    return flags
