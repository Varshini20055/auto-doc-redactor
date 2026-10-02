"""
OCR service for scanned/image-based PDFs.

Strategy:
  1. Try PaddleOCR (primary).
  2. If PaddleOCR fails or returns no text, fall back to Tesseract.
  3. Each result preserves page number, line number, text, and bounding box.

For normal text PDFs, callers should use PyMuPDF extraction directly
(extract_pdf_pages in extractors.py). This module is only invoked when
the PDF is detected as image/scanned-based.
"""
from __future__ import annotations

import logging
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import fitz  # PyMuPDF — used to render pages as images

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class OcrLine:
    line_number: int
    text: str
    bbox: list = field(default_factory=list)  # [x1, y1, x2, y2]


@dataclass
class OcrPage:
    page: int          # 1-indexed
    lines: List[OcrLine]
    source: str        # "paddleocr" | "tesseract"

    @property
    def full_text(self) -> str:
        return "\n".join(ln.text for ln in self.lines)


# ---------------------------------------------------------------------------
# Scanned-PDF detection
# ---------------------------------------------------------------------------
_TEXT_CHAR_THRESHOLD = 20  # pages with fewer chars than this are treated as image-only


def is_scanned_pdf(path: Path) -> bool:
    """Return True if the PDF appears to be image/scanned-based (no selectable text)."""
    try:
        with fitz.open(path) as doc:
            for page in doc:
                if len(page.get_text("text").strip()) >= _TEXT_CHAR_THRESHOLD:
                    return False
        return True
    except Exception as e:
        logger.warning("Could not determine PDF type, assuming text-based: %s", e)
        return False


# ---------------------------------------------------------------------------
# PaddleOCR
# ---------------------------------------------------------------------------
def _ocr_with_paddle(image_path: str) -> List[OcrLine]:
    from paddleocr import PaddleOCR  # type: ignore
    ocr = PaddleOCR(use_angle_cls=True, lang="en", show_log=False)
    result = ocr.ocr(image_path, cls=True)
    lines: List[OcrLine] = []
    if not result or not result[0]:
        return lines
    for i, item in enumerate(result[0]):
        box, (text, _conf) = item
        # box is [[x1,y1],[x2,y1],[x2,y2],[x1,y2]]
        xs = [pt[0] for pt in box]
        ys = [pt[1] for pt in box]
        bbox = [min(xs), min(ys), max(xs), max(ys)]
        lines.append(OcrLine(line_number=i + 1, text=text, bbox=bbox))
    return lines


# ---------------------------------------------------------------------------
# Tesseract fallback
# ---------------------------------------------------------------------------
def _ocr_with_tesseract(image_path: str) -> List[OcrLine]:
    import pytesseract  # type: ignore
    from PIL import Image  # type: ignore

    img = Image.open(image_path)
    data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
    lines: List[OcrLine] = []
    current_line: int | None = None
    current_words: list[str] = []
    current_bbox: list[int] = []

    for i, word in enumerate(data["text"]):
        if not word.strip():
            continue
        line_num = data["line_num"][i]
        x, y, w, h = data["left"][i], data["top"][i], data["width"][i], data["height"][i]
        if line_num != current_line:
            if current_line is not None and current_words:
                lines.append(OcrLine(
                    line_number=len(lines) + 1,
                    text=" ".join(current_words),
                    bbox=current_bbox,
                ))
            current_line = line_num
            current_words = [word]
            current_bbox = [x, y, x + w, y + h]
        else:
            current_words.append(word)
            current_bbox[2] = max(current_bbox[2], x + w)
            current_bbox[3] = max(current_bbox[3], y + h)

    if current_words:
        lines.append(OcrLine(
            line_number=len(lines) + 1,
            text=" ".join(current_words),
            bbox=current_bbox,
        ))
    return lines


# ---------------------------------------------------------------------------
# Per-page OCR dispatcher
# ---------------------------------------------------------------------------
def _ocr_page_image(image_path: str) -> tuple[List[OcrLine], str]:
    """Try PaddleOCR; fall back to Tesseract. Returns (lines, source_name)."""
    engine = settings.OCR_ENGINE.lower()
    fallback = settings.OCR_FALLBACK.lower()

    def _try_paddle() -> List[OcrLine] | None:
        try:
            lines = _ocr_with_paddle(image_path)
            return lines if lines else None
        except Exception as e:
            logger.warning("PaddleOCR failed: %s", e)
            return None

    def _try_tesseract() -> List[OcrLine] | None:
        try:
            return _ocr_with_tesseract(image_path)
        except Exception as e:
            logger.warning("Tesseract failed: %s", e)
            return None

    if engine == "paddleocr":
        lines = _try_paddle()
        if lines is not None:
            return lines, "paddleocr"
        if fallback == "tesseract":
            lines = _try_tesseract()
            if lines is not None:
                return lines, "tesseract"
    elif engine == "tesseract":
        lines = _try_tesseract()
        if lines is not None:
            return lines, "tesseract"
        if fallback == "paddleocr":
            lines = _try_paddle()
            if lines is not None:
                return lines, "paddleocr"

    return [], "none"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def ocr_pdf(path: Path, dpi: int = 200) -> List[OcrPage]:
    """
    Render each page of a PDF as an image and run OCR.
    Returns a list of OcrPage (one per PDF page, 1-indexed).
    """
    results: List[OcrPage] = []
    with fitz.open(path) as doc:
        for page_idx, page in enumerate(doc):
            mat = fitz.Matrix(dpi / 72, dpi / 72)
            pix = page.get_pixmap(matrix=mat)
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
                tmp_path = tmp.name
            try:
                pix.save(tmp_path)
                pix = None  # release pixmap before OCR to avoid Windows file-lock
                lines, source = _ocr_page_image(tmp_path)
            finally:
                Path(tmp_path).unlink(missing_ok=True)

            results.append(OcrPage(page=page_idx + 1, lines=lines, source=source))
    return results
