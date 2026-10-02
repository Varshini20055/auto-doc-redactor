from sqlalchemy.orm import Session
from app.models.db_models import AuditLog


def log_action(db: Session, document_id: str, action: str, actor: str | None = None, details: dict | None = None):
    entry = AuditLog(document_id=document_id, action=action, actor=actor, details=details or {})
    db.add(entry)
    db.commit()
    return entry
