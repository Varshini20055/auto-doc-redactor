import uuid
import datetime as dt
from sqlalchemy import Column, String, Integer, DateTime, Text, Float, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


class Document(Base):
    """Metadata about every document that passes through the system."""
    __tablename__ = "documents"

    id = Column(String, primary_key=True, default=gen_uuid)
    original_filename = Column(String, nullable=False)
    file_type = Column(String, nullable=False)          # pdf | docx
    status = Column(String, default="uploaded")           # uploaded|processing|redacted|failed
    uploaded_at = Column(DateTime, default=dt.datetime.utcnow)
    redacted_at = Column(DateTime, nullable=True)
    original_path_encrypted = Column(String, nullable=True)   # path to encrypted original
    redacted_path = Column(String, nullable=True)
    entity_count = Column(Integer, default=0)
    owner = Column(String, nullable=True)                # user/account that uploaded it
    checksum_sha256 = Column(String, nullable=True)

    findings = relationship("PIIFinding", back_populates="document", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="document", cascade="all, delete-orphan")

    # --- Compliance / verification (populated after redaction) ---
    verified = Column(Integer, nullable=True)          # 1 = verified clean, 0 = residual found, NULL = not run
    residual_matches = Column(Integer, default=0)
    unmatched_findings = Column(Integer, default=0)    # findings detected but not physically redacted (needs review)
    certificate_path = Column(String, nullable=True)
    checksum_redacted_sha256 = Column(String, nullable=True)
    warnings = Column(JSON, nullable=True)              # e.g. tracked changes / comments / embedded objects detected


class PIIFinding(Base):
    """A single detected PII entity (for reporting / review, not stored with raw text by default)."""
    __tablename__ = "pii_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    document_id = Column(String, ForeignKey("documents.id"), nullable=False)
    entity_type = Column(String, nullable=False)     # PERSON, EMAIL_ADDRESS, etc.
    location = Column(String, nullable=True)          # PDF: "page N" · DOCX: paragraph key
    score = Column(Float, nullable=False)
    source = Column(String, default="presidio")        # presidio | llm | presidio+llm
    start = Column(Integer, nullable=True)
    end = Column(Integer, nullable=True)
    page_number = Column(Integer, nullable=True)       # 1-indexed page number
    line_number = Column(Integer, nullable=True)       # line within page/paragraph
    bbox = Column(JSON, nullable=True)                 # [x1, y1, x2, y2] for OCR findings
    decision = Column(String, nullable=True)           # redact | review | skip
    reason = Column(String, nullable=True)             # human-readable decision reason

    document = relationship("Document", back_populates="findings")


class AuditLog(Base):
    """Immutable trail of every action taken on a document, for compliance (GDPR/HIPAA)."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    document_id = Column(String, ForeignKey("documents.id"), nullable=False)
    action = Column(String, nullable=False)     # upload|analyze|redact|download|delete
    actor = Column(String, nullable=True)
    timestamp = Column(DateTime, default=dt.datetime.utcnow)
    details = Column(JSON, nullable=True)

    document = relationship("Document", back_populates="audit_logs")
