# OfferProof

**Verify Before You Trust.** A student-built recruitment fraud screening prototype using explainable rules.

OfferProof checks offer details and text-based PDF letters for warning indicators, compares identifiers with prior user reports, and records verification history. Scores are heuristic indicators, not probabilities or proof of fraud.

## Implemented features

- Offer form and explainable risk scoring for payment requests, pressure tactics, recruiter domains, shortened URLs, and sensitive-information keywords.
- Text extraction from PDF offer letters; extracted text is analyzed with the submitted message.
- Explicit warnings for unreadable or image-only PDFs, with analysis of any other submitted details continuing.
- Scam reports with HMAC fingerprints and masked email/phone displays.
- Repeat-report counts, self-reported victim counts, and aggregate reported loss.
- SQLite verification history (latest 50 entries) and dashboard totals.
- Five MiB request limit, PDF page/text limits, and debug mode off by default.

## Run locally

Use Python 3.10 or later. From the repository root:

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell instead:
# .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. Starting with `python app.py` creates missing tables without deleting existing records. Before using an existing database, back it up.

For the Flask CLI, initialize tables first:

```bash
python -m flask --app app init-db
python -m flask --app app run
```

## Configuration

Set environment variables before starting the application:

| Variable | Purpose |
| --- | --- |
| `OFFERPROOF_SESSION_SECRET` | Stable random secret for Flask session signing. If omitted, a new secret is generated on startup, invalidating earlier session cookies. |
| `OFFERPROOF_HMAC_SECRET` | Stable private secret for identifier matching. The retained fallback is for local demo compatibility only. Changing it stops matching fingerprints created with the old secret. |
| `OFFERPROOF_DB_PATH` | SQLite database path; defaults to `offerproof.db`. |

Generate independent secrets with `python -c "import secrets; print(secrets.token_hex(32))"`. Keep them outside source control. Do not upload real offer letters, databases, or credentials.

## Project structure

- `app.py`: routes, database initialization, history, and aggregate queries.
- `services/risk_engine.py`: heuristic scoring and explanations.
- `services/pdf_analyzer.py`: bounded PDF text extraction.
- `services/privacy.py`: identifier fingerprints and display masking.
- `templates/`: verification, results, reports, dashboard, and history pages.
- `static/css/style.css`: shared styling.
- `tests/`: route, PDF, history, and risk regression checks.

## Verification

```bash
python -m unittest discover -s tests -v
```

Tests use temporary databases and synthetic documents, not uploaded personal records.

## Limits and next steps

This is a **local demonstration, not a production-ready service**. Authentication, per-user history isolation, report moderation, CSRF protection, rate limiting, and production deployment remain future work. History and dashboard are shared across visitors, so only use synthetic data in a demo.

PDF processing supports text-based documents up to 20 pages and 100,000 extracted characters. Image-only scans need OCR; encrypted and malformed files are not analyzed. Rejected PDFs do not prevent other submitted fields from being checked. A request above five MiB receives HTTP 413.

The engine does not contact employers or independently verify reports. Domain checks are heuristics and do not verify ownership; warnings based on domain endings and keyword presence can cause false positives. PDF email/phone details are not automatically used for identifier matching. ML classification, OCR, external reputation checks, and scam relationship graphs are not implemented.

Masking and HMAC matching reduce identifier exposure but do not make records anonymous. Company names and website values remain stored, and saved rule explanations can contain matched terms. Avoid sensitive input in this shared prototype.

`REVIEW_1_REPORT.md` is historical documentation; this README describes the current implementation.
