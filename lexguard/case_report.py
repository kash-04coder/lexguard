import sqlite3
import html
from datetime import datetime
from case_manager import build_case_summary

DB = "forensic.db"


def _esc(value):
    return html.escape(str(value)) if value is not None else ""


def _row(*cells):
    tds = "".join(f"<td>{_esc(c)}</td>" for c in cells)
    return f"<tr>{tds}</tr>"


REPORT_CSS = """
<style>
    body { font-family: Georgia, 'Times New Roman', serif; margin: 40px; color: #1a1a1a; }
    h1 { border-bottom: 3px solid #1a3d7c; padding-bottom: 8px; }
    h2 { color: #1a3d7c; margin-top: 32px; border-bottom: 1px solid #ccc; padding-bottom: 4px; }
    table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 13px; }
    th, td { border: 1px solid #999; padding: 6px 10px; text-align: left; }
    th { background: #1a3d7c; color: white; }
    tr:nth-child(even) { background: #f2f2f2; }
    .warning { color: #b00020; font-weight: bold; }
    .signature-block { background: #f7f7f7; border: 1px solid #ccc; padding: 12px;
                        font-family: monospace; word-break: break-all; }
    .meta { color: #555; font-size: 13px; }
</style>
"""


def generate_case_report(case_id, filename):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    build_case_summary(case_id)

    case = conn.execute("""
        SELECT * FROM cases WHERE case_id=?
    """, (case_id,)).fetchone()

    evidence = conn.execute("""
        SELECT id, title, filename, uploaded_by, sha256
        FROM evidence WHERE case_id=?
    """, (case_id,)).fetchall()

    custody = conn.execute("""
        SELECT timestamp, action, person
        FROM custody
        WHERE evidence_id IN (SELECT id FROM evidence WHERE case_id=?)
        ORDER BY timestamp
    """, (case_id,)).fetchall()

    verification = conn.execute("""
        SELECT verification_time, verified_by, status
        FROM verification_logs
        WHERE evidence_id IN (SELECT id FROM evidence WHERE case_id=?)
    """, (case_id,)).fetchall()

    alerts = conn.execute("""
        SELECT detection_time, severity, status
        FROM tamper_alerts
        WHERE evidence_id IN (SELECT id FROM evidence WHERE case_id=?)
    """, (case_id,)).fetchall()

    signed_case = conn.execute("""
        SELECT report_signature, report_signed_at
        FROM cases WHERE case_id=?
    """, (case_id,)).fetchone()

    conn.close()

    evidence_rows = "".join(
        _row(e["id"], e["title"], e["filename"], e["uploaded_by"], e["sha256"][:25] + "...")
        for e in evidence
    ) or "<tr><td colspan='5'>No evidence recorded.</td></tr>"

    custody_rows = "".join(
        _row(c["timestamp"], c["action"], c["person"]) for c in custody
    ) or "<tr><td colspan='3'>No custody records.</td></tr>"

    verification_rows = "".join(
        _row(v["verification_time"], v["verified_by"], v["status"]) for v in verification
    ) or "<tr><td colspan='3'>No verification records.</td></tr>"

    alert_rows = "".join(
        _row(a["detection_time"], a["severity"], a["status"]) for a in alerts
    ) or "<tr><td colspan='3'>No tamper alerts detected.</td></tr>"

    if signed_case and signed_case["report_signature"]:
        signature_block = f"""
        <p><b>Algorithm:</b> HMAC-SHA256</p>
        <p><b>Signed At:</b> {_esc(signed_case["report_signed_at"])}</p>
        <p><b>HMAC Signature:</b></p>
        <div class="signature-block">{_esc(signed_case["report_signature"])}</div>
        <p class="meta">This signature authenticates the canonical case summary
        stored by ForensiVault. Any modification to the authenticated case data
        will cause signature verification to fail.</p>
        """
    else:
        signature_block = (
            '<p class="warning">WARNING: This case has not been '
            'cryptographically signed.</p>'
        )

    case_id_display = _esc(case["case_id"]) if case else _esc(case_id)
    case_name = _esc(case["case_name"]) if case else ""
    investigator = _esc(case["investigator"]) if case else ""
    priority = _esc(case["priority"]) if case else ""
    status = _esc(case["status"]) if case else ""

    html_report = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Case Report - {case_id_display}</title>
{REPORT_CSS}
</head>
<body>
<h1>Digital Forensic Investigation Report</h1>
<p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<p><b>Case ID:</b> {case_id_display}</p>
<p><b>Case Name:</b> {case_name}</p>
<p><b>Investigator:</b> {investigator}</p>
<p><b>Priority:</b> {priority}</p>
<p><b>Status:</b> {status}</p>

<h2>Evidence</h2>
<table>
<tr><th>ID</th><th>Title</th><th>Filename</th><th>Uploaded By</th><th>SHA256</th></tr>
{evidence_rows}
</table>

<h2>Chain of Custody</h2>
<table>
<tr><th>Timestamp</th><th>Action</th><th>Person</th></tr>
{custody_rows}
</table>

<h2>Verification History</h2>
<table>
<tr><th>Time</th><th>Verified By</th><th>Status</th></tr>
{verification_rows}
</table>

<h2>Report Integrity Authentication</h2>
{signature_block}

<h2>Tamper Alerts</h2>
<table>
<tr><th>Detection Time</th><th>Severity</th><th>Status</th></tr>
{alert_rows}
</table>

</body>
</html>
"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_report)

    return filename