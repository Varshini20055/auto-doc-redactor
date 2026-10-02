# 🖍️ Auto-Doc Redactor — Compliance Edition

Automatically detect and redact PII (names, emails, phone numbers, credit
cards, SSNs, etc.) from PDF and DOCX documents — built for legal, medical,
and financial teams that need redaction accurate enough to survive an actual
compliance review, not just look right on screen.

This edition ships with a **React (Vite) frontend** styled as a case-file /
chain-of-custody workbench, and a backend rebuilt around one question:
*if someone in authority checks this output, will it hold up?*

## What changed in this edition

A first pass at this project had the shape of a redaction tool but several
real accuracy gaps that would fail exactly the kind of review this is meant
to pass. Each was found by writing a test that reproduces the real-world
failure case, confirming it actually failed, then fixing it — see
`tests/test_redaction_accuracy.py` for the proof, not just the claim.

| Gap | Why it mattered | Fix |
|---|---|---|
| DOCX redaction matched text inside each run individually | Word routinely splits a phrase across multiple runs (autocorrect, spell-check, edits) — a search that only looks inside one run at a time misses PII that starts in one run and ends in the next | Redaction now works by **character offset across the whole paragraph**, blanking exactly the matched range in every run it touches, regardless of run boundaries |
| Table cells and headers/footers were never scanned | This is where legal/medical/financial PII actually lives — account tables, patient tables, letterhead contacts — and it was completely invisible to both detection and redaction | Extraction now covers **every table cell (recursively, including nested tables) and every header/footer**, using the same detection and redaction path as body text |
| Isolated table cells defeat NER | A bare cell like "Jane Doe" or "294-81-5563" with no sentence around it is exactly where general-purpose NER is weakest | Added a **label-aware table pass**: a "SSN" column header or "Patient Name:" label means the adjacent cell is treated as that type, the same way a human reviewer would read the table — regardless of AI confidence |
| PDF matching failed on line-wrapped text | A literal substring search doesn't match text that was split across a line break in the source | Added whitespace-normalized and line-split fallback matching |
| Redaction never checked its own work | A tool that only reports what it *tried* to redact is trusting itself | Every redacted output is **independently re-scanned** afterward with the same detectors — verified/residual counts are reported, not assumed |
| Metadata and hidden data left untouched | Classic real-world redaction failure: text looks gone, but tracked-change history (Word keeps deleted text in the file, just hidden from view), comments, or document properties still carry it | Redaction now **accepts all tracked changes, strips comments, clears document properties (PDF + DOCX), and removes embedded files/annotations/links** |
| No audit artifact | A sanitized file alone isn't proof of what was done to it | Every redaction now generates a **signed-looking Redaction Certificate PDF**: entity counts, verification result, what metadata was scrubbed |

## Architecture

```
                ┌────────────────────┐
                │   React (Vite)      │
                │   frontend          │
                └─────────┬───────────┘
                          │ REST (multipart upload / JSON)
                ┌─────────▼─────────┐
                │   FastAPI backend  │
                │  /documents/*      │
                └───┬───────────┬────┘
                    │           │
      ┌─────────────▼─┐   ┌─────▼─────────────┐
      │ Extraction     │   │ PII Detection      │
      │ PyMuPDF (pdf)  │   │ Presidio + spaCy   │
      │ python-docx    │   │ + label-aware table │
      │ (body+tables+  │   │ pass + optional LLM │
      │  headers)      │   └─────┬──────────────┘
      └─────────────┬──┘         │
                    │             │
              ┌─────▼─────────────▼─────┐
              │       Redactor            │
              │  PDF: content-stream      │
              │   removal + fallback      │
              │   matching                │
              │  DOCX: offset-based,      │
              │   cross-run safe          │
              └─────────────┬──────────────┘
                            │
              ┌─────────────▼──────────────┐
              │  Metadata Scrub              │
              │  Tracked changes, comments,  │
              │  properties, annotations     │
              └─────────────┬──────────────┘
                            │
              ┌─────────────▼──────────────┐
              │  Verification                │
              │  Re-scan output, confirm     │
              │  no residual PII             │
              └─────────────┬──────────────┘
                            │
              ┌─────────────▼──────────────┐
              │  Certificate + Storage        │
              │  Signed PDF certificate,      │
              │  encrypted originals, DB      │
              └────────────────────────────┘
```

## Tech stack

| Layer | Technology | Purpose |
|---|---|---|
| Frontend | React 18 + Vite | Upload, run the pipeline, review findings and verification status |
| PDF processing | PyMuPDF (`fitz`) | Extract text, apply true redaction annotations, strip metadata/annotations/links |
| DOCX processing | python-docx + lxml | Read/write Word documents, offset-based run redaction, tracked-change/comment removal |
| PII detection | Microsoft Presidio + spaCy + label-aware tables | NER + regex detection, plus structured table-label heuristics |
| LLM (optional) | OpenAI API / Gemini API | Context-aware detection of sensitive info Presidio misses |
| Backend | FastAPI | REST API tying everything together |
| Verification | Same detection pipeline, run again | Independent re-check of redacted output |
| Certificate | PyMuPDF | Generates a one-page audit PDF per redaction |
| Database | SQLite (default) / PostgreSQL | Document metadata, findings, verification results, audit logs |
| Security | Fernet encryption + API-key auth | Originals encrypted at rest, checksum verified, access-controlled |

## Project layout

```
auto-doc-redactor-v2/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py                 # incl. redact-time recall threshold, scrub toggles
│   │   ├── database.py
│   │   ├── models/
│   │   │   ├── db_models.py          # + verified, residual_matches, certificate_path, warnings
│   │   │   └── schemas.py            # + verification/certificate fields
│   │   ├── routers/
│   │   │   └── documents.py          # + /certificate endpoint, verification wired into /redact
│   │   ├── services/
│   │   │   ├── extractors.py         # body + tables (recursive) + headers/footers; table-label heuristic
│   │   │   ├── pii_detector.py       # + configurable threshold, table label keyword map
│   │   │   ├── redactor.py           # offset-based DOCX redaction; PDF fallback matching
│   │   │   ├── verification.py       # NEW — re-scans redacted output
│   │   │   ├── certificate.py        # NEW — generates the audit PDF
│   │   │   └── audit.py
│   │   └── utils/
│   │       ├── security.py
│   │       └── metadata.py           # NEW — tracked changes, comments, properties, PDF metadata/links
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
├── frontend/                          # React (Vite) app
│   └── src/
│       ├── App.jsx                     # + verification panel, certificate download
│       ├── App.css                     # + verify-panel / verify-badge styles
│       └── components/
│           ├── PipelineLedger.jsx      # 5 steps now: Intake → Scan → Redact → Verify → Release
│           ├── FindingsTable.jsx       # location column (page or table/header key)
│           └── HistoryTable.jsx        # + Verified column
├── tests/
│   ├── conftest.py
│   ├── test_pii_detector.py
│   └── test_redaction_accuracy.py     # NEW — regression tests for every fix above
├── storage/
├── docker-compose.yml
├── setup.sh
└── README.md
```

## Quick start (local, no Docker)

```bash
./setup.sh   # sets up the backend virtualenv + spaCy model + frontend deps

# Terminal 1
cd backend && source venv/bin/activate
uvicorn app.main:app --reload

# Terminal 2
cd frontend
npm run dev
```

Open http://localhost:5173. The pipeline now runs Upload → Scan → Redact →
Verify → Release. After redaction you get two downloads: the sanitized file
and a redaction certificate PDF.

## Quick start (Docker)

```bash
docker compose up --build
```

## Running the test suite

```bash
cd auto-doc-redactor-v2
pip install -r backend/requirements.txt
python -m spacy download en_core_web_lg   # or en_core_web_sm for faster local runs
pytest tests/ -v
```

`test_redaction_accuracy.py` specifically proves: PII split across DOCX
runs gets redacted, table cells get detected and redacted, a header row
doesn't get misidentified as data (a real bug caught during development —
kept as a regression test), document metadata gets cleared, PDF redaction
removes text from the actual content stream, and the verification pass
correctly distinguishes a clean file from one with residual PII.

## API overview

| Method | Endpoint | Description |
|---|---|---|
| POST | `/documents/upload` | Upload a PDF/DOCX (encrypted at rest immediately) |
| POST | `/documents/{id}/analyze` | Run PII detection (body + tables + headers/footers), return findings |
| POST | `/documents/{id}/redact` | Redact, scrub metadata, verify, generate certificate |
| GET | `/documents/{id}/download` | Download the redacted file |
| GET | `/documents/{id}/certificate` | Download the redaction certificate PDF |
| GET | `/documents` | List processed documents (includes verification status) |
| DELETE | `/documents/{id}` | Delete a document + its files |

`/redact` response now includes: `verified`, `residual_matches`,
`residual_entity_types`, `unmatched_findings`, `metadata_scrubbed`,
`warnings`, and `certificate_url`.

## Configuration additions

```bash
# backend/.env
PRESIDIO_REDACT_SCORE_THRESHOLD=0.30   # lower than analyze — biased toward recall
STRIP_METADATA=true
VERIFY_AFTER_REDACT=true
GENERATE_CERTIFICATE=true
```

Redaction intentionally uses a **lower confidence threshold** than the
analyze/preview step: a missed finding at redact time leaks PII, while an
over-eager one just blacks out slightly more text. That asymmetry is the
right one for a compliance tool.

## Known limitations (stated honestly, not hidden)

- **Scanned/image-only PDFs**: text-based detection can't see PII inside a
  raster image. No OCR fallback is included in this pass — a document that
  is entirely a scanned image will report zero findings, which is a false
  negative, not a "clean" result. Flag scanned documents for manual review.
- **Embedded objects in DOCX** (linked spreadsheets, OLE objects): detected
  and flagged as a warning, but their content is not scanned — the object
  needs to be reviewed on its own.
- **PDF table structure**: PyMuPDF doesn't expose table structure the way
  python-docx does, so the label-aware heuristic that helps with DOCX tables
  doesn't have a PDF equivalent yet. PDF PII detection still runs on the
  full extracted text, which catches most cases NER can handle with context,
  just not the "bare label + isolated value" table case DOCX now handles.
- **This tool automates detection and redaction; it does not replace legal
  sign-off.** The certificate documents what the automated pipeline did and
  found — a human reviewer should still be the last check before a document
  goes out the door, especially for anything a residual-findings warning
  flags.

## Security & compliance notes

- **Encryption at rest**: Fernet (AES-128), plaintext copy deleted immediately.
- **No raw PII persisted**: findings store type/location/confidence only.
- **True redaction**: PyMuPDF's `apply_redactions()` strips text from the
  PDF content stream; DOCX redaction rewrites run text directly.
- **Hidden-data scrubbing**: tracked changes accepted, comments removed,
  document properties cleared, PDF metadata/XMP/embedded files/annotations/
  links stripped.
- **Independent verification**: redacted output is re-scanned with the same
  detectors before being marked verified.
- **Audit trail**: every action (including certificate downloads) is logged
  with a timestamp.
- **Access control**: API-key header seam included — swap in OAuth2/JWT/SSO
  for production.
