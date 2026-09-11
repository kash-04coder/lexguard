# LexGuard

Secure digital document management for legal & investigation records,
built on FastAPI. Originally a zero-dependency stdlib project; migrated
to FastAPI + Jinja2 templates while keeping all business logic modules
unchanged.

## Run it

```bash
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Open http://localhost:8000 — default login is `admin` / `admin123`
(change this before any real deployment).

## What's new vs. the original project

- `app.py` — FastAPI app, replaces webapp.py's raw http.server routing
- `templates/` — Jinja2 templates, replaces hand-built HTML strings
- `static/style.css` — same dark theme, extracted from webapp.py's BASE_CSS
- `documents.py` — legal document management with immutable versioning
- `hash_chain.py` — blockchain-inspired hash-chain integrity ledger
- `database.py` — original schema + `init_document_tables()` (additive only)

## Unchanged

auth.py, case_manager.py, evidence.py, audit.py, encryption.py,
ip_logger.py, metadata.py, tamper.py, verification.py, report_signing.py,
vault_security.py, timeline.py, case_report.py, report_generator.py,
dashboard.py — all reused as-is.

The old `webapp.py` is kept in the repo for reference but is no longer
the entrypoint; `app.py` is.

## Not yet migrated to the new app

These existed as routes in webapp.py and still need FastAPI routes added
(same pattern as documents/cases below — should be quick):
- Evidence upload/search/verify screens
- User management
- Audit log viewer
- Report generation / signature verification
- Secure vault

## Suggested next features (per priority)

1. Digital signatures on document versions (reuse report_signing.py's
   HMAC pattern)
2. Document-level RBAC (document_permissions table already exists)
3. Compliance dashboard summarizing chain health across all documents
