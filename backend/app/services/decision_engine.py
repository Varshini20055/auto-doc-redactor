"""
Cross-verification and confidence decision engine.

Combines Presidio/spaCy findings with LLM findings:
  - Overlapping spans from both sources → HIGH confidence, merged finding
  - Presidio-only with score >= HIGH_THRESHOLD → HIGH confidence
  - LLM-only with confidence >= LLM_CONFIDENCE_THRESHOLD → MEDIUM/HIGH
  - Low-confidence single-source → REVIEW or SKIP

Thresholds are configurable via config.py / environment variables.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from app.config import settings
from app.services.pii_detector import Finding


@dataclass
class Decision:
    entity_type: str
    text: str
    start: int
    end: int
    score: float
    sources: List[str]
    decision: str          # "redact" | "review" | "skip"
    reason: str
    page: int | None = None
    line: int | None = None
    bbox: list = field(default_factory=list)


def _spans_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


def _entity_types_agree(a: str, b: str) -> bool:
    """Treat semantically equivalent labels from different engines as matching."""
    _ALIASES: dict[str, set[str]] = {
        "EMAIL_ADDRESS": {"EMAIL", "EMAIL_ADDRESS"},
        "PHONE_NUMBER": {"PHONE", "PHONE_NUMBER"},
        "PERSON": {"PERSON", "NAME"},
        "LOCATION": {"LOCATION", "ADDRESS", "GPE"},
        "DATE_TIME": {"DATE_TIME", "DATE", "TIME"},
        "CREDIT_CARD": {"CREDIT_CARD", "CARD_NUMBER"},
        "US_SSN": {"US_SSN", "SSN"},
        "US_BANK_NUMBER": {"US_BANK_NUMBER", "ACCOUNT_NUMBER"},
    }
    for canonical, aliases in _ALIASES.items():
        if a.upper() in aliases and b.upper() in aliases:
            return True
    return a.upper() == b.upper()


def merge_findings(
    presidio_findings: List[Finding],
    llm_findings: List[Finding],
    page: int | None = None,
    line: int | None = None,
) -> List[Decision]:
    """
    Merge Presidio and LLM findings for a single text segment.
    Returns a deduplicated list of Decision objects.
    bbox and line are assigned by the caller after merge, using OCR line span data.
    """
    high_thresh = settings.PRESIDIO_SCORE_THRESHOLD
    llm_thresh = settings.LLM_CONFIDENCE_THRESHOLD

    decisions: List[Decision] = []
    used_llm: set[int] = set()

    for pf in presidio_findings:
        matched_llm: List[Finding] = []
        for li, lf in enumerate(llm_findings):
            if li in used_llm:
                continue
            if _spans_overlap(pf.start, pf.end, lf.start, lf.end):
                matched_llm.append(lf)
                used_llm.add(li)

        if matched_llm:
            agree = any(_entity_types_agree(pf.entity_type, lf.entity_type) for lf in matched_llm)
            combined_score = min(1.0, pf.score + 0.05) if agree else pf.score
            reasons = [lf.source for lf in matched_llm]
            decisions.append(Decision(
                entity_type=pf.entity_type, text=pf.text, start=pf.start, end=pf.end,
                score=combined_score, sources=["presidio"] + reasons,
                decision="redact", reason="Detected by Presidio and confirmed by LLM.",
                page=page, line=line,
            ))
        else:
            if pf.score >= high_thresh:
                decisions.append(Decision(
                    entity_type=pf.entity_type, text=pf.text, start=pf.start, end=pf.end,
                    score=pf.score, sources=["presidio"],
                    decision="redact", reason=f"Presidio high-confidence detection (score={pf.score:.2f}).",
                    page=page, line=line,
                ))
            else:
                decisions.append(Decision(
                    entity_type=pf.entity_type, text=pf.text, start=pf.start, end=pf.end,
                    score=pf.score, sources=["presidio"],
                    decision="review", reason=f"Presidio low-confidence detection (score={pf.score:.2f}), manual review recommended.",
                    page=page, line=line,
                ))

    for li, lf in enumerate(llm_findings):
        if li in used_llm:
            continue
        if lf.score >= llm_thresh:
            decisions.append(Decision(
                entity_type=lf.entity_type, text=lf.text, start=lf.start, end=lf.end,
                score=lf.score, sources=["llm"],
                decision="redact", reason=f"LLM contextual detection above threshold (score={lf.score:.2f}).",
                page=page, line=line,
            ))
        else:
            decisions.append(Decision(
                entity_type=lf.entity_type, text=lf.text, start=lf.start, end=lf.end,
                score=lf.score, sources=["llm"],
                decision="review", reason=f"LLM detection below confidence threshold (score={lf.score:.2f}).",
                page=page, line=line,
            ))

    seen: set[tuple[int, int]] = set()
    deduped: List[Decision] = []
    for d in sorted(decisions, key=lambda x: (x.start, -x.score)):
        key = (d.start, d.end)
        if key not in seen:
            seen.add(key)
            deduped.append(d)
    return deduped


def decisions_to_findings(decisions: List[Decision]) -> List[Finding]:
    """Convert Decision objects back to Finding objects for the existing redaction pipeline."""
    return [
        Finding(
            entity_type=d.entity_type,
            start=d.start,
            end=d.end,
            score=d.score,
            text=d.text,
            source="+".join(d.sources),
        )
        for d in decisions
        if d.decision == "redact"
    ]
