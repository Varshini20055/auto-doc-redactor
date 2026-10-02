import datetime as dt
from typing import List
from pydantic import BaseModel, ConfigDict


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    entity_type: str
    location: str | None = None
    score: float
    source: str
    page_number: int | None = None
    line_number: int | None = None
    bbox: list | None = None
    decision: str | None = None
    reason: str | None = None


class DocumentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    original_filename: str
    file_type: str
    status: str
    uploaded_at: dt.datetime
    redacted_at: dt.datetime | None = None
    entity_count: int
    verified: bool | None = None
    residual_matches: int = 0


class AnalyzeResponse(BaseModel):
    document_id: str
    entity_count: int
    findings: list[FindingOut]
    docx_risk_flags: dict | None = None
    extraction_method: str | None = None   # "text" | "ocr_paddleocr" | "ocr_tesseract"


class RedactResponse(BaseModel):
    document_id: str
    status: str
    redacted_boxes: int
    unmatched_findings: int
    verified: bool
    residual_matches: int
    residual_entity_types: dict[str, int] = {}
    post_redaction_context_matches: int = 0
    verification_findings: list[dict] = []
    metadata_scrubbed: dict = {}
    warnings: list[str] = []
    download_url: str
    certificate_url: str | None = None


class ChatRequest(BaseModel):
    message: str


class ChatLocation(BaseModel):
    page: int | None = None
    line: int | None = None
    entity_type: str
    source: str | None = None
    decision: str | None = None


class ChatResponse(BaseModel):
    answer: str
    locations: List[ChatLocation] = []
