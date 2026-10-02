from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import Base, engine
from app.routers import documents
from app.migrate import run_migrations

# Create tables on startup, then apply incremental column migrations
Base.metadata.create_all(bind=engine)
run_migrations()

app = FastAPI(
    title=settings.APP_NAME,
    description="Detect and redact PII from PDF/DOCX documents using Presidio, spaCy, "
                "and an optional LLM context-aware pass.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(documents.router)


@app.get("/")
def root():
    return {"app": settings.APP_NAME, "status": "ok"}


@app.get("/health")
def health():
    return {"status": "healthy"}
