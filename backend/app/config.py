"""
Central configuration for the Auto-Doc Redactor backend.
All values can be overridden via environment variables or a .env file.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path


class Settings(BaseSettings):
    # ---- App ----
    APP_NAME: str = "Auto-Doc Redactor"
    ENV: str = "development"

    # ---- Storage ----
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    UPLOAD_DIR: Path = BASE_DIR / "storage" / "uploads"
    REDACTED_DIR: Path = BASE_DIR / "storage" / "redacted"
    MAX_UPLOAD_MB: int = 25

    # ---- Database ----
    # Defaults to local SQLite so the project runs out of the box.
    # Swap to Postgres/Mongo by setting DATABASE_URL, e.g.
    # postgresql+psycopg2://user:pass@localhost:5432/redactor
    DATABASE_URL: str = "sqlite:///./redactor.db"

    # ---- Security ----
    SECRET_KEY: str = "change-me-in-production"          # used for JWT signing
    ENCRYPTION_KEY: str = ""                              # Fernet key, generated if empty
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ---- PII Detection ----
    SPACY_MODEL: str = "en_core_web_lg"
    PRESIDIO_SCORE_THRESHOLD: float = 0.35
    # Redaction is intentionally biased toward higher recall than the
    # analyze-only preview: a missed finding at redact time leaks PII, while
    # an over-eager one just blacks out a bit more text. Kept lower than
    # PRESIDIO_SCORE_THRESHOLD on purpose.
    PRESIDIO_REDACT_SCORE_THRESHOLD: float = 0.30
    DEFAULT_ENTITIES: list[str] = [
        "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD",
        "US_SSN", "IBAN_CODE", "LOCATION", "DATE_TIME",
        "IP_ADDRESS", "MEDICAL_LICENSE", "US_BANK_NUMBER",
        "CRYPTO", "URL", "NRP",
    ]

    # ---- Compliance / hidden-data scrubbing ----
    STRIP_METADATA: bool = True
    VERIFY_AFTER_REDACT: bool = True
    GENERATE_CERTIFICATE: bool = True

    # ---- LLM — Grok/xAI (context-aware detection + chatbot) ----
    LLM_ENABLED: bool = False
    LLM_PROVIDER: str = "grok"           # only "grok" | "none" are supported
    GROK_API_KEY: str = ""
    GROK_MODEL: str = "grok-3-mini"
    GROK_BASE_URL: str = "https://api.x.ai/v1"
    LLM_CONFIDENCE_THRESHOLD: float = 0.85

    # ---- OCR ----
    OCR_ENGINE: str = "paddleocr"       # "paddleocr" | "tesseract"
    OCR_FALLBACK: str = "tesseract"     # fallback engine if primary fails

    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).resolve().parent.parent / ".env"),
        extra="ignore",
    )


settings = Settings()
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
settings.REDACTED_DIR.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    """Return the live settings object. Import this instead of `settings`
    in any module where the value must reflect the current process state
    rather than the state at first import."""
    return settings
