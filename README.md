# LexGuard

Secure digital document management for legal & investigation records,
built on FastAPI.

## Run it

```bash
pip install -r requirements.txt
python -m uvicorn app:app --reload --port 8000
```

(Use `python -m uvicorn ...` rather than a bare `uvicorn` command if
your PATH doesn't have the uvicorn script on it.)

Open http://localhost:8000 — default login is `admin` / `admin123`.
On first login you'll configure the encrypted evidence vault's master
password.

## Structure

- `app.py` — FastAPI app: all routes, session auth, vault gating
- `templates/` — Jinja2 templates (one per page), same dark theme
- `static/style.css` — theme
- `documents.py` / `hash_chain.py` — document management + the
  blockchain-inspired hash-chain integrity ledger (hackathon USP)
- `database.py` — original schema + `init_document_tables()`
- Everything else (auth.py, case_manager.py, evidence.py, audit.py,
  encryption.py, ip_logger.py, metadata.py, tamper.py, verification.py,
  report_signing.py, vault_security.py, timeline.py, case_report.py,
  report_generator.py, dashboard.py) — original business logic, reused.

`webapp.py` is the old raw-http.server entrypoint, kept for reference
only. `app.py` is the real entrypoint.

## Recent changes

- **Evidence pages merged**: `/evidence/search`, `/evidence/details`,
  and `/evidence/timeline` are now one page at `/evidence` — search,
  pick evidence from a dropdown or search result, and see basic info +
  preview + a unified timeline (registration, custody, verification,
  tamper events) all in one place.
- **Audit Logs page removed**: it was a raw duplicate of Activity
  Monitoring (`/activity`), which already covers the same data with
  filtering, metrics, and CSV export. `audit.py`'s logging still runs
  everywhere — only the redundant raw-table page is gone.
- **Generate Report page removed**: it generated a per-evidence report
  with the section 63(4)(c) certificate appended. That certificate is
  now appended to the **signed case report** instead (downloaded from
  Case Management → close & sign a case → "Download Signed Case
  Report"), so there's one authoritative, cryptographically signed
  report per case instead of two separate report flows.

## Suggested next features

1. Digital signatures on document versions (reuse report_signing.py's
   HMAC pattern)
2. Document-level RBAC (document_permissions table already exists)
3. Compliance dashboard summarizing chain health across all documents
