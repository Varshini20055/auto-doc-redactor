"""
Lightweight schema migration — adds columns introduced in v2 to existing
databases without requiring Alembic. Safe to run multiple times (no-ops if
columns already exist). Called from main.py before the app starts serving.
"""
import logging
from sqlalchemy import text
from app.database import engine

logger = logging.getLogger(__name__)

_MIGRATIONS = [
    # (table, column, sql_type)
    ("pii_findings", "page_number", "INTEGER"),
    ("pii_findings", "line_number", "INTEGER"),
    ("pii_findings", "bbox",        "TEXT"),
    ("pii_findings", "decision",    "TEXT"),
    ("pii_findings", "reason",      "TEXT"),
]


def run_migrations():
    with engine.connect() as conn:
        for table, column, col_type in _MIGRATIONS:
            try:
                # Check if column exists (works for SQLite and Postgres)
                result = conn.execute(text(f"SELECT {column} FROM {table} LIMIT 0"))
                result.close()
            except Exception:
                # Column missing — add it
                try:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
                    conn.commit()
                    logger.info("Migration: added %s.%s (%s)", table, column, col_type)
                except Exception as e:
                    logger.warning("Migration failed for %s.%s: %s", table, column, e)
