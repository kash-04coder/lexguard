import os
import secrets
import html
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse

from database import init_db
from auth import create_default_admin, login, create_user
from vault_security import (
    vault_is_configured,
    setup_master_password,
    verify_master_password
)
from dashboard import get_dashboard_data
from evidence import save_evidence, calculate_hash
from case_report import generate_case_report
from audit import log_action, get_audit_logs
from evidence_details import get_evidence_details
from timeline import get_timeline
from case_manager import (
    create_case, get_cases, get_case, get_case_evidence, get_case_alerts,
    get_case_statistics, update_case, delete_case, close_case, build_case_summary,
)
from auth import get_users, delete_user, update_role
from verification import save_verification
from tamper import create_alert
from report_signing import verify_case_summary
from metadata import extract_image_metadata, extract_pdf_metadata, extract_file_metadata
from encryption import decrypt_file
import report_generator
import csv
import io
import tempfile
from datetime import datetime
import sqlite3

init_db()
create_default_admin()

SESSIONS = {}


def new_session():
    session_id = secrets.token_hex(16)
    SESSIONS[session_id] = {
        "logged_in": False,
        "username": None,
        "role": None,
        "vault_unlocked": False,
    }
    return session_id


def get_session(handler):
    cookie_header = handler.headers.get("Cookie")
    if cookie_header:
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        if "session_id" in cookie:
            session_id = cookie["session_id"].value
            if session_id in SESSIONS:
                return session_id, SESSIONS[session_id]
    session_id = new_session()
    return session_id, SESSIONS[session_id]

ROUTES = [
    ("/dashboard", "Dashboard", []),
    ("/evidence/timeline", "Evidence Timeline", []),
    ("/evidence/search", "Evidence Search", []),
    ("/metadata", "Metadata Analysis", []),
    ("/evidence/details", "Evidence Details", []),
    ("/activity", "Activity Monitoring", []),
    ("/cases", "Case Management", ["Admin", "Investigator"]),
    ("/evidence/verify", "Verify Evidence", ["Admin", "Analyst"]),
    ("/custody", "Chain of Custody", ["Admin", "Investigator"]),
    ("/reports/generate", "Generate Report", ["Admin", "Investigator", "Analyst"]),
    ("/reports/verify-signature", "Verify Report Signature", ["Admin", "Investigator", "Analyst"]),
    ("/vault", "Secure Evidence Vault", ["Admin", "Analyst"]),
    ("/users", "User Management", ["Admin"]),
    ("/audit", "Audit Logs", ["Admin"]),
]


def menu_for_role(role):
    items = [r for r in ROUTES if r[2] == []]
    if role == "Admin":
        extra = ["/cases", "/evidence/verify", "/custody", "/reports/generate",
                 "/reports/verify-signature", "/vault", "/users", "/audit"]
    elif role == "Investigator":
        extra = ["/cases", "/custody", "/reports/generate", "/reports/verify-signature"]
    elif role == "Analyst":
        extra = ["/evidence/verify", "/reports/generate", "/vault", "/reports/verify-signature"]
    else:
        extra = []
    extra_routes = [r for r in ROUTES if r[0] in extra]
    return items + extra_routes


BASE_CSS = """
* { box-sizing: border-box; }
body {
    background: #031f49;
    color: white;
    font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
    margin: 0;
    padding: 0;
}
a { color: #93c5fd; }
.container { max-width: 1100px; margin: 0 auto; padding: 30px 20px; }
.header-box {
    background: #1E293B;
    padding: 25px;
    border-radius: 15px;
    margin-bottom: 20px;
}
.header-box h1 { color: white; margin: 0 0 6px 0; }
.header-box h2 { color: white; margin: 0 0 10px 0; font-weight: 500; }
.header-box p { color: #CBD5E1; margin: 0; }
.layout { display: flex; gap: 40px; align-items: flex-start; }
.layout .left { flex: 1.2; }
.layout .right { flex: 1; }
.card {
    background: #0b2c63;
    border-radius: 15px;
    padding: 20px;
    margin-bottom: 16px;
}
input[type=text], input[type=password], select, textarea {
    width: 100%;
    border-radius: 10px;
    padding: 10px 12px;
    border: 1px solid #334155;
    background: #0f172a;
    color: white;
    margin-bottom: 14px;
    font-size: 14px;
}
label { display: block; margin-bottom: 6px; color: #CBD5E1; font-size: 14px; }
button, input[type=submit] {
    width: 100%;
    border-radius: 12px;
    background: #2563EB;
    color: white;
    border: none;
    height: 45px;
    font-weight: 600;
    font-size: 15px;
    cursor: pointer;
}
button:hover, input[type=submit]:hover { background: #1D4ED8; }
.error { background: #7f1d1d; border: 1px solid #ef4444; padding: 12px 16px;
         border-radius: 10px; margin-bottom: 14px; }
.success { background: #14532d; border: 1px solid #22c55e; padding: 12px 16px;
           border-radius: 10px; margin-bottom: 14px; }
.warning { background: #78350f; border: 1px solid #f59e0b; padding: 12px 16px;
           border-radius: 10px; margin-bottom: 14px; }
.info { background: #1e3a5f; border: 1px solid #3b82f6; padding: 12px 16px;
        border-radius: 10px; margin-bottom: 14px; }
.metric-row { display: flex; gap: 16px; margin: 20px 0; flex-wrap: wrap; }
.metric-card {
    background: #b61f1f;
    padding: 20px;
    border-radius: 15px;
    border: 1px solid #0fdc38;
    flex: 1;
    min-width: 140px;
    text-align: center;
}
.metric-card .label { font-size: 13px; color: #fecaca; }
.metric-card .value { font-size: 28px; font-weight: 700; margin-top: 6px; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; }
thead tr th { background: #1E293B !important; color: white; padding: 10px; text-align: left; }
tbody td { padding: 8px 10px; border-bottom: 1px solid #1e3a5f; }
.sidebar {
    background: #021024;
    width: 230px;
    height: 100vh;
    padding: 20px 16px;
    position: fixed;
    left: 0; top: 0;
    overflow-y: auto;
}
.sidebar a {
    display: block;
    padding: 10px 12px;
    border-radius: 8px;
    color: #CBD5E1;
    text-decoration: none;
    margin-bottom: 4px;
    font-size: 14px;
}
.sidebar a:hover, .sidebar a.active { background: #1E293B; color: white; }
.main-content { margin-left: 260px; padding: 30px; }
.feature-list { line-height: 1.9; }
"""


def render_page(title, body_html, use_sidebar=False, sidebar_html=""):
    if use_sidebar:
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title><style>{BASE_CSS}</style></head>
<body>
<div class="sidebar">{sidebar_html}</div>
<div class="main-content">{body_html}</div>
</body></html>"""
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title><style>{BASE_CSS}</style></head>
<body>
<div class="container">{body_html}</div>
</body></html>"""


def render_login_page(error=None):
    error_html = f'<div class="error">{error}</div>' if error else ""
    body = f"""
    <div class="header-box">
        <h1>&#128274; LexVault </h1>
        <h2>&#128737; Digital Evidence Management System</h2>
        <p>Secure Digital Forensics &bull; Chain of Custody &bull; SHA256 Verification</p>
    </div>
    <div class="layout">
        <div class="left">
            <img src="/assets/forensic.jpg" style="width:100%; max-width:500px; border-radius:12px;">
        </div>
        <div class="right">
            <h3>Login</h3>
            {error_html}
            <form method="POST" action="/login">
                <label>Username</label>
                <input type="text" name="username" required>
                <label>Password</label>
                <input type="password" name="password" required>
                <button type="submit">Login</button>
            </form>
            <p style="margin-top:14px;">Don't have an account?</p>
            <form method="GET" action="/register">
                <button type="submit" style="background:#334155;">Register Here</button>
            </form>
        </div>
    </div>
    <div class="card" style="margin-top:20px;">
        <h3>Why DEMS?</h3>
        <div class="feature-list">
            &#10003; Secure Evidence Storage<br>
            &#10003; SHA-256 Integrity Verification<br>
            &#10003; Chain of Custody<br>
            &#10003; Metadata Analysis<br>
            &#10003; Tamper Detection<br>
            &#10003; Digital Investigation Reports
        </div>
    </div>
    """
    return render_page("LexVault - Login", body)


def render_register_page(error=None, success=None):
    error_html = f'<div class="error">{error}</div>' if error else ""
    success_html = f'<div class="success">{success}</div>' if success else ""
    body = f"""
    <div class="header-box"><h1>&#128274; LexVault </h1></div>
    <div class="card" style="max-width:420px;">
        <h3>Register</h3>
        {error_html}{success_html}
        <form method="POST" action="/register">
            <label>Choose Username</label>
            <input type="text" name="username" required>
            <label>Choose Password</label>
            <input type="password" name="password" required>
            <label>Re-type Password</label>
            <input type="password" name="confirm" required>
            <button type="submit">Register</button>
        </form>
        <p style="margin-top:14px;">Already have an account?</p>
        <form method="GET" action="/">
            <button type="submit" style="background:#334155;">Login Here</button>
        </form>
    </div>
    """
    return render_page("LexVault - Register", body)

def render_vault_setup_page(error=None):
    error_html = f'<div class="error">{error}</div>' if error else ""
    body = f"""
    <div class="header-box">
        <h1>&#128274; Configure Secure Evidence Vault</h1>
    </div>
    <div class="warning">The Secure Evidence Vault has not been configured yet.</div>
    <p>Create a master password to protect access to the encrypted evidence vault.</p>
    <div class="info">LexVault does not store the master password. Only a
    PBKDF2-HMAC-SHA256 derived value and a random salt are stored.</div>
    {error_html}
    <div class="card" style="max-width:420px;">
        <form method="POST" action="/vault/setup">
            <label>Create Master Password</label>
            <input type="password" name="master_password" required>
            <label>Confirm Master Password</label>
            <input type="password" name="confirm_master_password" required>
            <button type="submit">&#128274; Configure Vault</button>
        </form>
    </div>
    """
    return render_page("LexVault - Configure Vault", body)


def render_vault_locked_page(error=None):
    error_html = f'<div class="error">{error}</div>' if error else ""
    body = f"""
    <div class="header-box"><h1>&#128274; Secure Evidence Vault Locked</h1></div>
    <p>Enter the vault master password to continue.</p>
    {error_html}
    <div class="card" style="max-width:420px;">
        <form method="POST" action="/vault/unlock">
            <label>Master Password</label>
            <input type="password" name="master_password" required>
            <button type="submit">&#128275; Unlock Vault</button>
        </form>
    </div>
    """
    return render_page("LexVault - Vault Locked", body)


def render_sidebar(session, active_path):
    role = session["role"]
    username = session["username"]
    items = menu_for_role(role)

    links_html = ""
    for path, label, _ in items:
        active_class = "active" if path == active_path else ""
        links_html += f'<a href="{path}" class="{active_class}">{label}</a>\n'

    return f"""
    <h2 style="margin-top:0;">&#128737; DEMS</h2>
    <p style="color:#94a3b8;">Welcome,<br><b>{username}</b></p>
    <div class="success" style="padding:8px 12px; font-size:13px;">Role: {role}</div>
    <form method="POST" action="/vault/lock" style="margin:12px 0;">
        <button type="submit" style="background:#334155; height:38px;">&#128274; Lock Vault</button>
    </form>
    <hr style="border-color:#1e3a5f; margin:16px 0;">
    {links_html}
    <hr style="border-color:#1e3a5f; margin:16px 0;">
    <form method="POST" action="/logout">
        <button type="submit" style="background:#7f1d1d; height:38px;">Logout</button>
    </form>
    """


def render_authenticated_page(session, active_path, title, body_html):
    sidebar_html = render_sidebar(session, active_path)
    full_body = f'<h1 style="margin-top:0;">{title}</h1>{body_html}'
    return render_page(title, full_body, use_sidebar=True, sidebar_html=sidebar_html)


def render_stub_page(page_label):
    return f'<div class="card">The "{page_label}" page will be built in an upcoming phase.</div>'


def _decrypted_tempfile_for_evidence(filename, encrypted_path):
    """Decrypts an evidence file to a scratch tempfile so metadata/hash
    tools that need a real filepath can operate on it. Caller must
    delete the returned path when done."""
    data = decrypt_file(encrypted_path)
    suffix = ("." + filename.split(".")[-1]) if "." in filename else ""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    tmp.write(data)
    tmp.close()
    return tmp.name


def render_custody_page(session, message=None):
    conn = sqlite3.connect("forensic.db")
    evidence_list = conn.execute("SELECT id, title FROM evidence").fetchall()
    records = conn.execute("""
        SELECT id, evidence_id, action, person, timestamp
        FROM custody ORDER BY timestamp DESC
    """).fetchall()
    conn.close()

    message_html = f'<div class="success">{message}</div>' if message else ""

    if not evidence_list:
        return render_authenticated_page(session, "/custody", "Chain of Custody",
                                          '<div class="info">No evidence has been uploaded yet.</div>')

    picker_options = "".join(f'<option value="{e[0]}">{e[0]} - {_esc(e[1])}</option>' for e in evidence_list)
    action_options = "".join(
        f"<option>{a}</option>" for a in ["Assigned to Analyst", "Transferred", "Analyzed", "Archived"]
    )

    form = f"""
    <div class="card">
        <form method="POST" action="/custody/add">
            <label>Select Evidence</label>
            <select name="evidence_id">{picker_options}</select>
            <label>Action</label>
            <select name="action">{action_options}</select>
            <button type="submit">Add Custody Record</button>
        </form>
    </div>
    """

    rows = "".join(
        f"<tr><td>{_esc(r[1])}</td><td>{_esc(r[2])}</td><td>{_esc(r[3])}</td><td>{_esc(r[4])}</td></tr>"
        for r in records
    ) or "<tr><td colspan='4'>No custody records.</td></tr>"

    table = f"""
    <div class="card">
        <table><thead><tr><th>Evidence ID</th><th>Action</th><th>Person</th><th>Timestamp</th></tr></thead>
        <tbody>{rows}</tbody></table>
    </div>
    """

    body = f"{message_html}{form}{table}"
    return render_authenticated_page(session, "/custody", "Chain of Custody", body)


def render_generate_report_page(session, message=None):
    conn = sqlite3.connect("forensic.db")
    evidence_list = conn.execute("SELECT id, title FROM evidence").fetchall()
    conn.close()

    message_html = f'<div class="success">{message}</div>' if message else ""

    if not evidence_list:
        return render_authenticated_page(session, "/reports/generate", "Forensic Report Generator",
                                          '<div class="info">No evidence is available to report on yet.</div>')

    picker_options = "".join(f'<option value="{e[0]}">{e[0]} - {_esc(e[1])}</option>' for e in evidence_list)

    body = f"""
    {message_html}
    <div class="info">The supplied Schedule certificate under section 63(4)(c) is appended
    verbatim to the report.</div>
    <div class="card">
        <form method="POST" action="/reports/generate/download">
            <label>Select Evidence</label>
            <select name="evidence_id">{picker_options}</select>
            <button type="submit">Generate Report</button>
        </form>
    </div>
    """
    return render_authenticated_page(session, "/reports/generate", "Forensic Report Generator", body)


def render_verify_signature_page(session, selected_case_id=None, result=None):
    conn = sqlite3.connect("forensic.db")
    conn.row_factory = sqlite3.Row
    signed_cases = conn.execute("""
        SELECT case_id, case_name, status, report_signature, report_signed_at
        FROM cases
        WHERE report_signature IS NOT NULL AND report_signature != ''
        ORDER BY report_signed_at DESC
    """).fetchall()
    conn.close()

    if not signed_cases:
        return render_authenticated_page(session, "/reports/verify-signature",
                                          "Case Report Integrity Verification",
                                          '<div class="info">No cryptographically signed cases are available.</div>')

    if selected_case_id is None:
        selected_case_id = signed_cases[0]["case_id"]

    selected = next((c for c in signed_cases if c["case_id"] == selected_case_id), signed_cases[0])

    picker_options = "".join(
        f'<option value="{_esc(c["case_id"])}" {"selected" if c["case_id"]==selected_case_id else ""}>'
        f'{_esc(c["case_id"])} - {_esc(c["case_name"])}</option>'
        for c in signed_cases
    )

    result_html = ""
    if result == "valid":
        result_html = ('<div class="success">&#9989; REPORT INTEGRITY VERIFIED<br>'
                        'The current case data matches the cryptographically authenticated case summary.</div>')
    elif result == "invalid":
        result_html = ('<div class="error">&#128680; REPORT INTEGRITY COMPROMISED<br>'
                        'The current case data no longer matches the stored HMAC signature.</div>')

    body = f"""
    <div class="card">
        <form method="GET" action="/reports/verify-signature">
            <label>Select Signed Case</label>
            <select name="case_id" onchange="this.form.submit()">{picker_options}</select>
        </form>
        <p><b>Case ID:</b> {_esc(selected['case_id'])}</p>
        <p><b>Case Name:</b> {_esc(selected['case_name'])}</p>
        <p><b>Status:</b> {_esc(selected['status'])}</p>
        <p><b>Signed At:</b> {_esc(selected['report_signed_at'])}</p>
        <h3>Stored HMAC-SHA256 Signature</h3>
        <div class="info" style="font-family:monospace; word-break:break-all;">{_esc(selected['report_signature'])}</div>
        <form method="POST" action="/reports/verify-signature/verify" style="margin-top:16px;">
            <input type="hidden" name="case_id" value="{_esc(selected['case_id'])}">
            <button type="submit">&#128269; Verify Report Integrity</button>
        </form>
    </div>
    {result_html}
    """
    return render_authenticated_page(session, "/reports/verify-signature", "Case Report Integrity Verification", body)


def render_verify_evidence_page(session, message=None, message_type="info"):
    conn = sqlite3.connect("forensic.db")
    evidence_list = conn.execute("SELECT id, title, encrypted_path, sha256 FROM evidence").fetchall()
    conn.close()

    message_html = f'<div class="{message_type}">{message}</div>' if message else ""

    if not evidence_list:
        return render_authenticated_page(session, "/evidence/verify", "Evidence Integrity Verification",
                                          '<div class="info">No evidence is available to verify yet.</div>')

    picker_options = "".join(f'<option value="{e[0]}">{e[0]} - {_esc(e[1])}</option>' for e in evidence_list)

    body = f"""
    {message_html}
    <div class="card">
        <form method="POST" action="/evidence/verify/run">
            <label>Select Evidence</label>
            <select name="evidence_id">{picker_options}</select>
            <button type="submit">Verify Evidence</button>
        </form>
    </div>
    """
    return render_authenticated_page(session, "/evidence/verify", "Evidence Integrity Verification", body)


def render_metadata_page(session, evidence_id=None, metadata=None):
    conn = sqlite3.connect("forensic.db")
    evidence_list = conn.execute("""
        SELECT id, title FROM evidence ORDER BY id DESC
    """).fetchall()
    conn.close()

    if not evidence_list:
        return render_authenticated_page(session, "/metadata", "Metadata Analysis",
                                          '<div class="info">No evidence is available for metadata analysis yet.</div>')

    if evidence_id is None:
        evidence_id = evidence_list[0][0]
    else:
        evidence_id = int(evidence_id)

    picker_options = "".join(
        f'<option value="{e[0]}" {"selected" if e[0]==evidence_id else ""}>{e[0]} - {_esc(e[1])}</option>'
        for e in evidence_list
    )

    picker = f"""
    <div class="card">
        <form method="GET" action="/metadata">
            <label>Select Evidence</label>
            <select name="evidence_id" onchange="this.form.submit()">{picker_options}</select>
            <button type="submit">Extract Metadata</button>
        </form>
    </div>
    """

    metadata_html = ""
    if metadata:
        if "Error" in metadata:
            metadata_html = f'<div class="error">Metadata could not be extracted: {_esc(metadata["Error"])}</div>'
        else:
            rows = "".join(
                f"<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>" for k, v in metadata.items()
            )
            metadata_html = f"""
            <div class="success">Extracted {len(metadata)} metadata fields.</div>
            <div class="card">
                <table><thead><tr><th>Property</th><th>Value</th></tr></thead>
                <tbody>{rows}</tbody></table>
                <a href="/metadata/export?evidence_id={evidence_id}"><button type="button"
                   onclick="window.location.href=this.parentElement.href">Download metadata as CSV</button></a>
            </div>
            """

    body = f"{picker}{metadata_html}"
    return render_authenticated_page(session, "/metadata", "Metadata Analysis", body)


def _extract_metadata_for_evidence(evidence_id):
    conn = sqlite3.connect("forensic.db")
    conn.row_factory = sqlite3.Row
    row = conn.execute("""
        SELECT id, title, filename, encrypted_path, sha256, uploaded_by, upload_time
        FROM evidence WHERE id=?
    """, (evidence_id,)).fetchone()
    conn.close()
    if not row:
        return None

    tmp_path = _decrypted_tempfile_for_evidence(row["filename"], row["encrypted_path"])
    try:
        extension = row["filename"].split(".")[-1].lower() if "." in row["filename"] else ""
        if extension in ("jpg", "jpeg", "png", "bmp", "gif"):
            metadata = extract_image_metadata(tmp_path)
        elif extension == "pdf":
            metadata = extract_pdf_metadata(tmp_path)
        else:
            metadata = extract_file_metadata(tmp_path)
            metadata["Analysis | Format-specific metadata"] = (
                "Not available for this file type. File and integrity details are shown below."
            )
    finally:
        os.remove(tmp_path)

    if "Error" not in metadata:
        stored_hash = row["sha256"]
        current_hash = metadata.get("Integrity | SHA-256")
        metadata.update({
            "Evidence record | Evidence ID": row["id"],
            "Evidence record | Title": row["title"],
            "Evidence record | Original filename": row["filename"] or "Not recorded",
            "Evidence record | Uploaded by": row["uploaded_by"] or "Not recorded",
            "Evidence record | Upload time": row["upload_time"] or "Not recorded",
            "Integrity | Stored SHA-256": stored_hash or "Not recorded",
            "Integrity | Verification": (
                "Match — file is consistent with its registered hash"
                if stored_hash and stored_hash == current_hash
                else "Mismatch — current file hash differs from the registered hash"
                if stored_hash else "No registered hash available for comparison"
            ),
        })

    return metadata


ACTIVITY_ICONS = [
    ("Tamper", "&#128680;"), ("Register", "&#128193;"), ("Verify", "&#9989;"),
    ("Metadata", "&#129516;"), ("Report", "&#128196;"), ("Login", "&#128273;"),
]


def _icon_for_action(action):
    for keyword, icon in ACTIVITY_ICONS:
        if keyword in action:
            return icon
    return "&#128204;"


def render_activity_page(session, user_filter="All", action_filter="All", search=""):
    logs = get_audit_logs()
    users = ["All"] + [u[1] for u in get_users()]
    actions = ["All"] + sorted({log["action"] for log in logs})

    today_str = datetime.now().strftime("%Y-%m-%d")
    today_count = sum(1 for log in logs if log["timestamp"].startswith(today_str))
    active_users = len({log["username"] for log in logs})

    metrics = f"""
    <div class="metric-row">
        <div class="metric-card"><div class="label">&#128220; Total Activities</div><div class="value">{len(logs)}</div></div>
        <div class="metric-card"><div class="label">&#128197; Today's Activities</div><div class="value">{today_count}</div></div>
        <div class="metric-card"><div class="label">&#128101; Active Users</div><div class="value">{active_users}</div></div>
    </div>
    """

    filtered = logs
    if user_filter != "All":
        filtered = [log for log in filtered if log["username"] == user_filter]
    if action_filter != "All":
        filtered = [log for log in filtered if log["action"] == action_filter]
    if search:
        filtered = [log for log in filtered if search.lower() in log["action"].lower()]

    user_options = "".join(f'<option {"selected" if user_filter==u else ""}>{_esc(u)}</option>' for u in users)
    action_options = "".join(f'<option {"selected" if action_filter==a else ""}>{_esc(a)}</option>' for a in actions)

    filter_form = f"""
    <div class="card">
        <form method="GET" action="/activity" style="display:flex; gap:10px; flex-wrap:wrap; align-items:flex-end;">
            <div style="flex:1; min-width:150px;"><label>&#128100; User</label>
            <select name="user">{user_options}</select></div>
            <div style="flex:1; min-width:150px;"><label>&#9881; Action</label>
            <select name="action">{action_options}</select></div>
            <div style="flex:2; min-width:200px;"><label>&#128269; Search Activity</label>
            <input type="text" name="search" value="{_esc(search)}"></div>
            <div style="flex:1; min-width:100px;"><button type="submit">Filter</button></div>
        </form>
    </div>
    """

    entries = "".join(
        f"""<div class="info">{_icon_for_action(log['action'])} <b>{_esc(log['timestamp'])}</b><br>
        &#128100; {_esc(log['username'])}<br>{_esc(log['action'])}</div>"""
        for log in filtered
    ) or '<div class="info">No matching activity.</div>'

    export_qs = f"user={user_filter}&action={action_filter}&search={search}"
    export_link = f'<a href="/activity/export.csv?{export_qs}"><button type="button" onclick="window.location.href=this.parentElement.href">&#11015; Export Activity Log</button></a>'

    body = f"{metrics}{filter_form}{entries}<div style='margin-top:16px;'>{export_link}</div>"
    return render_authenticated_page(session, "/activity", "Activity Monitoring", body)


def render_users_page(session, search="", message=None):
    users = get_users()
    admins = sum(1 for u in users if u[2] == "Admin")
    analysts = sum(1 for u in users if u[2] == "Analyst")
    viewers = sum(1 for u in users if u[2] == "Viewer")
    investigators = sum(1 for u in users if u[2] == "Investigator")

    metrics = f"""
    <div class="metric-row">
        <div class="metric-card"><div class="label">&#128081; Admins</div><div class="value">{admins}</div></div>
        <div class="metric-card"><div class="label">&#128737; Analysts</div><div class="value">{analysts}</div></div>
        <div class="metric-card"><div class="label">&#128064; Viewers</div><div class="value">{viewers}</div></div>
        <div class="metric-card"><div class="label">&#128101; Investigators</div><div class="value">{investigators}</div></div>
    </div>
    """

    message_html = f'<div class="success">{message}</div>' if message else ""

    search_form = f"""
    <div class="card">
        <form method="GET" action="/users">
            <label>&#128269; Search User</label>
            <input type="text" name="search" value="{_esc(search)}" placeholder="Enter username...">
            <button type="submit">Search</button>
        </form>
    </div>
    """

    roles = ["Viewer", "Analyst", "Investigator", "Admin"]
    user_cards = ""
    for u in users:
        user_id, username, role = u[0], u[1], u[2]
        if search and search.lower() not in username.lower():
            continue
        current_role = role if role in roles else "Viewer"
        role_options = "".join(f'<option {"selected" if r==current_role else ""}>{r}</option>' for r in roles)
        if username == session["username"]:
            action_html = '<div class="info" style="max-width:150px;">Current User</div>'
        else:
            action_html = f"""
            <form method="POST" action="/users/delete" style="max-width:120px;">
                <input type="hidden" name="user_id" value="{user_id}">
                <button type="submit" style="background:#7f1d1d;">&#128465; Delete</button>
            </form>
            """
        user_cards += f"""
        <div class="card" style="display:flex; gap:16px; align-items:center; flex-wrap:wrap;">
            <div style="flex:2; min-width:150px;"><b>{_esc(username)}</b></div>
            <form method="POST" action="/users/update-role" style="flex:2; min-width:200px; display:flex; gap:8px; align-items:center;">
                <input type="hidden" name="user_id" value="{user_id}">
                <select name="role" style="margin:0;">{role_options}</select>
                <button type="submit" style="width:auto; padding:0 16px;">&#128190; Save</button>
            </form>
            <div style="flex:1; min-width:120px;">{action_html}</div>
        </div>
        """

    create_form = f"""
    <div class="card">
        <h3>&#10133; Create New User</h3>
        <form method="POST" action="/users/create">
            <label>New Username</label>
            <input type="text" name="username" required>
            <label>New Password</label>
            <input type="password" name="password" required>
            <label>Role</label>
            <select name="role">
                <option>Admin</option><option>Investigator</option><option>Analyst</option><option selected>Viewer</option>
            </select>
            <button type="submit">Create User</button>
        </form>
    </div>
    """

    body = f"{message_html}{metrics}{search_form}{user_cards}{create_form}"
    return render_authenticated_page(session, "/users", "User Management", body)


def render_audit_logs_page(session):
    conn = sqlite3.connect("forensic.db")
    logs = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC").fetchall()
    conn.close()

    rows = "".join(
        f"<tr><td>{_esc(l[0])}</td><td>{_esc(l[1])}</td><td>{_esc(l[2])}</td><td>{_esc(l[3])}</td></tr>"
        for l in logs
    ) or "<tr><td colspan='4'>No audit log entries.</td></tr>"

    body = f"""
    <div class="card">
        <table><thead><tr><th>ID</th><th>Username</th><th>Action</th><th>Timestamp</th></tr></thead>
        <tbody>{rows}</tbody></table>
    </div>
    """
    return render_authenticated_page(session, "/audit", "Audit Logs", body)


def render_evidence_search_page(session, search_term=""):
    results_html = ""
    if search_term:
        conn = sqlite3.connect("forensic.db")
        conn.row_factory = sqlite3.Row
        like = f"%{search_term}%"
        results = conn.execute("""
            SELECT id, case_id, title, filename, uploaded_by, upload_time
            FROM evidence
            WHERE case_id LIKE ? OR title LIKE ? OR filename LIKE ?
               OR uploaded_by LIKE ? OR sha256 LIKE ?
        """, (like, like, like, like, like)).fetchall()
        conn.close()

        log_action(session["username"], f"Searched: {search_term}")

        if results:
            rows = "".join(
                f"""<tr><td>{_esc(r['id'])}</td><td>{_esc(r['case_id'])}</td>
                <td>{_esc(r['title'])}</td><td>{_esc(r['filename'])}</td>
                <td>{_esc(r['uploaded_by'])}</td><td>{_esc(r['upload_time'])}</td>
                <td><a href="/evidence/details?evidence_id={r['id']}">View</a></td></tr>"""
                for r in results
            )
            results_html = f"""
            <div class="success">{len(results)} result(s) found</div>
            <table><thead><tr><th>ID</th><th>Case</th><th>Title</th><th>Filename</th>
            <th>Uploaded By</th><th>Upload Time</th><th></th></tr></thead>
            <tbody>{rows}</tbody></table>
            """
        else:
            results_html = '<div class="warning">No matching evidence found</div>'

    body = f"""
    <div class="card">
        <form method="GET" action="/evidence/search">
            <label>Search Evidence</label>
            <input type="text" name="search_term" value="{_esc(search_term)}"
                   placeholder="Case ID, title, filename, uploader, or SHA256">
            <button type="submit">Search</button>
        </form>
    </div>
    {results_html}
    """
    return render_authenticated_page(session, "/evidence/search", "Evidence Search Engine", body)


def render_evidence_details_page(session, evidence_id=None):
    conn = sqlite3.connect("forensic.db")
    evidence_list = conn.execute("SELECT id, title FROM evidence").fetchall()
    conn.close()

    if not evidence_list:
        return render_authenticated_page(session, "/evidence/details", "Evidence Details",
                                          '<div class="info">No evidence has been uploaded yet.</div>')

    if evidence_id is None:
        evidence_id = evidence_list[0][0]
    else:
        evidence_id = int(evidence_id)

    picker_options = "".join(
        f'<option value="{e[0]}" {"selected" if e[0]==evidence_id else ""}>{e[0]} - {_esc(e[1])}</option>'
        for e in evidence_list
    )
    picker = f"""
    <div class="card">
        <form method="GET" action="/evidence/details">
            <label>Select Evidence</label>
            <select name="evidence_id" onchange="this.form.submit()">{picker_options}</select>
        </form>
    </div>
    """

    evidence, custody, verification, alerts, ip_logs = get_evidence_details(evidence_id)
    if not evidence:
        return render_authenticated_page(session, "/evidence/details", "Evidence Details",
                                          picker + '<div class="error">Evidence not found.</div>')

    status = verification[0]["status"] if verification else "Unknown"

    basic_info = f"""
    <div class="card">
        <h3>Basic Information</h3>
        <div style="display:flex; gap:30px; flex-wrap:wrap;">
            <div style="flex:1; min-width:250px;">
                <p><b>Case ID:</b> {_esc(evidence['case_id'])}</p>
                <p><b>Title:</b> {_esc(evidence['title'])}</p>
                <p><b>Uploaded By:</b> {_esc(evidence['uploaded_by'])}</p>
            </div>
            <div style="flex:1; min-width:250px;">
                <p><b>Upload Time:</b> {_esc(evidence['upload_time'])}</p>
                <p><b>Filename:</b> {_esc(evidence['filename'])}</p>
                <p><b>SHA256:</b> <code>{_esc(evidence['sha256'][:32])}...</code></p>
            </div>
        </div>
    </div>
    <div class="metric-row">
        <div class="metric-card"><div class="label">&#128274; Encryption</div><div class="value" style="font-size:16px;">Enabled</div></div>
        <div class="metric-card"><div class="label">&#128269; Status</div><div class="value" style="font-size:16px;">{_esc(status)}</div></div>
        <div class="metric-card"><div class="label">&#128680; Alerts</div><div class="value">{len(alerts)}</div></div>
        <div class="metric-card"><div class="label">&#128220; Custody</div><div class="value">{len(custody)}</div></div>
    </div>
    """

    filename = evidence["filename"]
    extension = filename.split(".")[-1].lower() if "." in filename else ""
    if extension in ("jpg", "jpeg", "png", "bmp", "gif"):
        preview = f'<img src="/evidence/preview?evidence_id={evidence_id}" style="max-width:500px; border-radius:10px;">'
    elif extension in ("txt", "log", "csv"):
        try:
            data = decrypt_file(evidence["encrypted_path"])
            content = data.decode("utf-8", errors="replace")
            preview = f'<pre style="background:#0f172a; padding:16px; border-radius:10px; overflow-x:auto;">{_esc(content)}</pre>'
        except (FileNotFoundError, ValueError) as e:
            preview = f'<div class="warning">Could not decrypt evidence for preview: {_esc(e)}</div>'
    elif extension == "pdf":
        preview = f'<a href="/evidence/preview?evidence_id={evidence_id}"><button type="button" onclick="window.location.href=this.parentElement.href">Download PDF</button></a>'
    else:
        preview = '<div class="warning">Preview not available for this file type.</div>'

    custody_rows = "".join(
        f"<tr><td>{_esc(c['timestamp'])}</td><td>{_esc(c['action'])}</td><td>{_esc(c['person'])}</td></tr>"
        for c in custody
    ) or "<tr><td colspan='3'>No custody records.</td></tr>"

    ip_rows = "".join(
        f"<tr><td>{_esc(i['username'])}</td><td>{_esc(i['action'])}</td><td>{_esc(i['ip_address'])}</td><td>{_esc(i['timestamp'])}</td></tr>"
        for i in ip_logs
    )
    ip_section = (f"<table><thead><tr><th>User</th><th>Action</th><th>IP</th><th>Time</th></tr></thead><tbody>{ip_rows}</tbody></table>"
                  if ip_logs else '<div class="info">No IP activity has been recorded for this evidence yet.</div>')

    alert_rows = "".join(
        f"<tr><td>{_esc(a['detection_time'])}</td><td>{_esc(a['severity'])}</td><td>{_esc(a['status'])}</td></tr>"
        for a in alerts
    ) or "<tr><td colspan='3'>No tamper alerts.</td></tr>"

    body = f"""
    {picker}
    {basic_info}
    <div class="card"><h3>&#128444; Evidence Preview</h3>{preview}</div>
    <div class="card"><h3>&#128209; Chain of Custody</h3>
        <table><thead><tr><th>Timestamp</th><th>Action</th><th>Person</th></tr></thead>
        <tbody>{custody_rows}</tbody></table>
    </div>
    <div class="card"><h3>Evidence Activity IP Logs</h3>{ip_section}</div>
    <div class="card"><h3>&#128680; Tamper Alerts</h3>
        <table><thead><tr><th>Detection Time</th><th>Severity</th><th>Status</th></tr></thead>
        <tbody>{alert_rows}</tbody></table>
    </div>
    """
    return render_authenticated_page(session, "/evidence/details", "Evidence Details", body)



def render_vault_page(session):
    conn = sqlite3.connect("forensic.db")
    conn.row_factory = sqlite3.Row
    files = conn.execute("SELECT id, title, encrypted_path FROM evidence").fetchall()
    conn.close()

    if files:
        rows = "".join(
            f"<tr><td>{_esc(f['id'])}</td><td>{_esc(f['title'])}</td><td>{_esc(f['encrypted_path'])}</td></tr>"
            for f in files
        )
        table = f"""<table><thead><tr><th>ID</th><th>Title</th><th>Encrypted Path</th></tr></thead>
        <tbody>{rows}</tbody></table>"""
    else:
        table = '<div class="info">No encrypted evidence is currently available.</div>'

    body = f"""
    <div class="success">Vault unlocked. Encrypted evidence is accessible.</div>
    {table}
    """
    return render_authenticated_page(session, "/vault", "Encrypted Evidence Vault", body)



TIMELINE_COLORS = {
    "green": "success",
    "red": "error",
    "orange": "warning",
}


def render_timeline_page(session, evidence_id=None):
    conn = sqlite3.connect("forensic.db")
    evidence_list = conn.execute("SELECT id, title FROM evidence").fetchall()
    conn.close()

    if not evidence_list:
        return render_authenticated_page(session, "/evidence/timeline", "Evidence Timeline",
                                          '<div class="info">No evidence has been uploaded yet.</div>')

    if evidence_id is None:
        evidence_id = evidence_list[0][0]
    else:
        evidence_id = int(evidence_id)

    picker_options = "".join(
        f'<option value="{e[0]}" {"selected" if e[0]==evidence_id else ""}>{e[0]} - {_esc(e[1])}</option>'
        for e in evidence_list
    )
    picker = f"""
    <div class="card">
        <form method="GET" action="/evidence/timeline">
            <label>Select Evidence</label>
            <select name="evidence_id" onchange="this.form.submit()">{picker_options}</select>
        </form>
    </div>
    """

    timeline = get_timeline(evidence_id)
    events_html = ""
    for row in timeline:
        ip_address = row.get("ip_address") or "Not recorded"
        css_class = TIMELINE_COLORS.get(row.get("color"), "info")
        events_html += f"""
        <div class="{css_class}">
            <h3 style="margin:0 0 6px 0;">{row.get('icon','')} {_esc(row.get('event',''))}</h3>
            &#128100; <b>{_esc(row.get('user',''))}</b><br>
            &#127760; IP Address: {_esc(ip_address)}<br>
            &#128337; <b>{_esc(row.get('time',''))}</b>
        </div>
        """

    if not events_html:
        events_html = '<div class="info">No timeline events recorded for this evidence yet.</div>'

    body = f"{picker}{events_html}"
    return render_authenticated_page(session, "/evidence/timeline", "Evidence Timeline", body)


CASE_COLUMNS = ["id", "case_id", "case_name", "description", "investigator",
                "priority", "status", "created_at", "report_signature", "report_signed_at"]


def _case_row_dict(row):
    return dict(zip(CASE_COLUMNS, row))


def render_cases_page(session, selected_case_id=None, search="", priority_filter="All",
                       status_filter="All", message=None, error=None):
    message_html = f'<div class="success">{message}</div>' if message else ""
    error_html = f'<div class="error">{error}</div>' if error else ""

    # --- Create case form ---
    create_form = f"""
    <div class="card">
        <h3>Create Investigation</h3>
        <form method="POST" action="/cases/create">
            <label>Case ID</label>
            <input type="text" name="case_id" required>
            <label>Case Name</label>
            <input type="text" name="case_name" required>
            <label>Description</label>
            <textarea name="description" rows="3"></textarea>
            <label>Priority</label>
            <select name="priority">
                <option>Low</option><option>Medium</option><option>High</option><option>Critical</option>
            </select>
            <button type="submit">Create Case</button>
        </form>
    </div>
    """

    all_cases = [_case_row_dict(c) for c in get_cases()]
    filtered = all_cases
    if search:
        s = search.lower()
        filtered = [c for c in filtered if s in c["case_name"].lower() or s in c["case_id"].lower()]
    if priority_filter != "All":
        filtered = [c for c in filtered if c["priority"] == priority_filter]
    if status_filter != "All":
        filtered = [c for c in filtered if c["status"] == status_filter]

    case_rows = "".join(
        f"""<tr>
            <td>{_esc(c['case_id'])}</td><td>{_esc(c['case_name'])}</td>
            <td>{_esc(c['investigator'])}</td><td>{_esc(c['priority'])}</td>
            <td>{_esc(c['status'])}</td><td>{_esc(c['created_at'])}</td>
            <td><a href="/cases?case_id={_esc(c['case_id'])}">Open</a></td>
        </tr>"""
        for c in filtered
    ) or "<tr><td colspan='7'>No cases match.</td></tr>"

    list_section = f"""
    <div class="card">
        <h3>Existing Cases</h3>
        <form method="GET" action="/cases" style="display:flex; gap:10px; align-items:flex-end; flex-wrap:wrap;">
            <div style="flex:2; min-width:200px;">
                <label>&#128269; Search Cases</label>
                <input type="text" name="search" value="{_esc(search)}">
            </div>
            <div style="flex:1; min-width:140px;">
                <label>Priority</label>
                <select name="priority_filter">
                    {''.join(f'<option {"selected" if priority_filter==p else ""}>{p}</option>' for p in ["All","Low","Medium","High","Critical"])}
                </select>
            </div>
            <div style="flex:1; min-width:140px;">
                <label>Status</label>
                <select name="status_filter">
                    {''.join(f'<option {"selected" if status_filter==s else ""}>{s}</option>' for s in ["All","Open","Closed"])}
                </select>
            </div>
            <div style="flex:1; min-width:100px;">
                <button type="submit">Filter</button>
            </div>
        </form>
        <table style="margin-top:16px;">
            <thead><tr><th>Case ID</th><th>Name</th><th>Investigator</th><th>Priority</th>
            <th>Status</th><th>Created</th><th></th></tr></thead>
            <tbody>{case_rows}</tbody>
        </table>
    </div>
    """

    detail_section = ""
    if selected_case_id:
        detail_section = _render_case_detail(session, selected_case_id)

    body = f"{message_html}{error_html}{create_form}{list_section}{detail_section}"
    return render_authenticated_page(session, "/cases", "Case Management", body)


def _render_case_detail(session, case_id):
    case_row = get_case(case_id)
    if not case_row:
        return '<div class="error">Case not found.</div>'
    case = _case_row_dict(case_row)

    alerts = get_case_alerts(case["case_id"])
    evidence = get_case_evidence(case["case_id"])

    status_badge = (f'<div class="success">&#128994; Investigation Status: OPEN</div>'
                     if case["status"] == "Open" else
                     f'<div class="error">&#128308; Investigation Status: CLOSED</div>')

    priority_badges = {
        "Critical": '<div class="error">&#128293; Priority: CRITICAL</div>',
        "High": '<div class="warning">&#9888; Priority: HIGH</div>',
        "Medium": '<div class="info">&#128309; Priority: MEDIUM</div>',
        "Low": '<div class="success">&#128994; Priority: LOW</div>',
    }
    priority_badge = priority_badges.get(case["priority"], "")

    signature_html = ""
    if case["report_signature"]:
        signature_html = f"""
        <div class="card">
            <h3>&#128274; Report Integrity Signature</h3>
            <div class="success">This case has a cryptographically authenticated final report.</div>
            <p><b>Algorithm:</b> HMAC-SHA256</p>
            <div class="info" style="font-family:monospace; word-break:break-all;">{_esc(case['report_signature'])}</div>
            <p><b>Signed At:</b> {_esc(case['report_signed_at'])}</p>
        </div>
        """
    else:
        signature_html = '<div class="info">This case has not yet been cryptographically signed.</div>'

    total, verified, tampered, alert_count = get_case_statistics(case["case_id"])
    progress = 0 if total == 0 else round(((verified + tampered) / total) * 100)

    summary_metrics = f"""
    <div class="metric-row">
        <div class="metric-card"><div class="label">&#128193; Evidence</div><div class="value">{total}</div></div>
        <div class="metric-card"><div class="label">&#9989; Verified</div><div class="value">{verified}</div></div>
        <div class="metric-card"><div class="label">&#128680; Tampered</div><div class="value">{tampered}</div></div>
        <div class="metric-card"><div class="label">&#9888; Alerts</div><div class="value">{alert_count}</div></div>
    </div>
    <div class="card">
        <p>Investigation Progress: <b>{progress}%</b> of evidence has been examined.</p>
        <div style="background:#0f172a; border-radius:8px; overflow:hidden; height:16px;">
            <div style="background:#22c55e; width:{progress}%; height:100%;"></div>
        </div>
    </div>
    """

    edit_form = f"""
    <div class="card">
        <h3>&#9999; Edit Investigation</h3>
        <form method="POST" action="/cases/update">
            <input type="hidden" name="case_id" value="{_esc(case['case_id'])}">
            <label>Case Name</label>
            <input type="text" name="case_name" value="{_esc(case['case_name'])}">
            <label>Description</label>
            <textarea name="description" rows="3">{_esc(case['description'])}</textarea>
            <label>Priority</label>
            <select name="priority">
                {''.join(f'<option {"selected" if case["priority"]==p else ""}>{p}</option>' for p in ["Low","Medium","High","Critical"])}
            </select>
            <label>Status</label>
            <select name="status">
                {''.join(f'<option {"selected" if case["status"]==s else ""}>{s}</option>' for s in ["Open","Closed"])}
            </select>
            <button type="submit">&#128190; Save Changes</button>
        </form>
    </div>
    """

    upload_form = f"""
    <div class="card">
        <h3>&#10133; Add Evidence to this Case</h3>
        <form method="POST" action="/cases/evidence/add" enctype="multipart/form-data">
            <input type="hidden" name="case_id" value="{_esc(case['case_id'])}">
            <label>Evidence Title</label>
            <input type="text" name="title" required>
            <label>Upload Evidence</label>
            <input type="file" name="evidence_file" required>
            <button type="submit">&#128228; Add Evidence</button>
        </form>
    </div>
    """

    evidence_rows = "".join(
        f"""<div class="card">
            <b>&#128196; {_esc(e[1])}</b><br>
            <span style="color:#94a3b8;">Filename: {_esc(e[2])} | Uploaded By: {_esc(e[3])} | On: {_esc(e[4])}</span>
        </div>"""
        for e in evidence
    ) or '<div class="card">No evidence in this case yet.</div>'

    admin_actions = ""
    if session["role"] == "Admin":
        if case["status"] != "Closed":
            report_note = ('<div class="warning">&#128274; The final case report can only be '
                            'generated after the case has been closed and cryptographically signed.</div>')
        else:
            report_note = f'<a href="/cases/report?case_id={_esc(case["case_id"])}"><button type="button" onclick="window.location.href=this.parentElement.href">&#128196; Download Signed Case Report</button></a>'

        admin_actions = f"""
        <div class="card">
            <h3>Admin Actions</h3>
            <div style="display:flex; gap:12px;">
                <form method="POST" action="/cases/close" style="flex:1;">
                    <input type="hidden" name="case_id" value="{_esc(case['case_id'])}">
                    <button type="submit">&#9989; Close &amp; Sign Case</button>
                </form>
                <form method="POST" action="/cases/delete" style="flex:1;">
                    <input type="hidden" name="case_id" value="{_esc(case['case_id'])}">
                    <button type="submit" style="background:#7f1d1d;">&#128465; Delete Case</button>
                </form>
            </div>
            {report_note}
        </div>
        """

    return f"""
    <hr style="border-color:#1e3a5f; margin:24px 0;">
    <h2>Open Investigation: {_esc(case['case_name'])}</h2>
    <div class="metric-row">
        <div class="metric-card"><div class="label">&#128193; Evidence</div><div class="value">{len(evidence)}</div></div>
        <div class="metric-card"><div class="label">&#128680; Alerts</div><div class="value">{alerts}</div></div>
        <div class="metric-card"><div class="label">&#9888; Priority</div><div class="value" style="font-size:16px;">{_esc(case['priority'])}</div></div>
        <div class="metric-card"><div class="label">&#128204; Status</div><div class="value" style="font-size:16px;">{_esc(case['status'])}</div></div>
    </div>
    {status_badge}
    {priority_badge}
    <div class="card">
        <h3>Investigation Information</h3>
        <p><b>Case ID:</b> {_esc(case['case_id'])}</p>
        <p><b>Case Name:</b> {_esc(case['case_name'])}</p>
        <p><b>Lead Investigator:</b> {_esc(case['investigator'])}</p>
        <p><b>Description:</b> {_esc(case['description'])}</p>
        <p><b>Created:</b> {_esc(case['created_at'])}</p>
    </div>
    {signature_html}
    <h3>&#128202; Investigation Summary</h3>
    {summary_metrics}
    {edit_form}
    {upload_form}
    <h3>&#128193; Evidence in this Case</h3>
    {evidence_rows}
    {admin_actions}
    """


def _esc(value):
    return html.escape(str(value)) if value is not None else ""


def render_dashboard_page(session):
    data, uploads, roles, activity = get_dashboard_data()

    metrics_html = f"""
    <div class="metric-row">
        <div class="metric-card"><div class="label">&#128193; Evidence</div><div class="value">{data['evidence']}</div></div>
        <div class="metric-card"><div class="label">&#128101; Users</div><div class="value">{data['users']}</div></div>
        <div class="metric-card"><div class="label">&#128680; Alerts</div><div class="value">{data['alerts']}</div></div>
        <div class="metric-card"><div class="label">&#9989; Verified</div><div class="value">{data['verified']}</div></div>
        <div class="metric-card"><div class="label">&#9888; Tampered</div><div class="value">{data['tampered']}</div></div>
    </div>
    """

    role_rows = "".join(
        f"<tr><td>{_esc(r['role'])}</td><td>{_esc(r['count'])}</td></tr>" for r in roles
    ) or "<tr><td colspan='2'>No users yet.</td></tr>"

    activity_rows = "".join(
        f"<tr><td>{_esc(a['username'])}</td><td>{_esc(a['action'])}</td><td>{_esc(a['timestamp'])}</td></tr>"
        for a in activity
    ) or "<tr><td colspan='3'>No recent activity.</td></tr>"

    body = f"""
    <div class="success">Welcome {_esc(session['username'])}</div>
    {metrics_html}
    <div class="card">
        <h3>Users by Role</h3>
        <table><thead><tr><th>Role</th><th>Count</th></tr></thead>
        <tbody>{role_rows}</tbody></table>
    </div>
    <div class="card">
        <h3>Recent Activity</h3>
        <table><thead><tr><th>User</th><th>Action</th><th>Timestamp</th></tr></thead>
        <tbody>{activity_rows}</tbody></table>
    </div>
    """
    return render_authenticated_page(session, "/dashboard", "Digital Evidence Management System", body)


class ForensiVaultHandler(BaseHTTPRequestHandler):

    def _set_session_cookie(self, session_id):
        cookie = SimpleCookie()
        cookie["session_id"] = session_id
        cookie["session_id"]["httponly"] = True
        cookie["session_id"]["path"] = "/"
        self.send_header("Set-Cookie", cookie.output(header="").strip())

    def _send_server_error(self, exc):
        """
        Last-resort safety net: instead of letting an unhandled exception
        kill the connection (which shows up in the browser as
        ERR_EMPTY_RESPONSE with no explanation), log it to the terminal
        and return a real HTTP 500 page.
        """
        import traceback
        traceback.print_exc()
        try:
            body = (
                "<h1>500 - Internal Server Error</h1>"
                f"<pre>{html.escape(str(exc))}</pre>"
                "<p>Check the server terminal for the full traceback.</p>"
            ).encode("utf-8")
            self.send_response(500)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            # If we can't even send the error page (e.g. connection already broken), there's nothing more we can do -- avoid a second crash.
            pass

    def _send_html(self, html_content, session_id=None, status=200):
        encoded = html_content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        if session_id:
            self._set_session_cookie(session_id)
        self.end_headers()
        self.wfile.write(encoded)

    def _redirect(self, location, session_id=None):
        self.send_response(303)
        self.send_header("Location", location)
        if session_id:
            self._set_session_cookie(session_id)
        self.end_headers()

    def _read_form(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8")
        parsed = parse_qs(raw)
        return {k: v[0] for k, v in parsed.items()}

    def _read_multipart(self):
        """
        Hand-rolled multipart/form-data parser -- replaces what
        Streamlit's file_uploader (or a package like python-multipart)
        handled for us. The body is split on the boundary string taken
        from the Content-Type header; each part's headers are parsed
        for name= / filename=, and the remainder is the raw value.

        Returns (fields, files) where fields is {name: value} for plain
        text inputs and files is {name: (filename, bytes)} for uploads.
        """
        content_type = self.headers.get("Content-Type", "")
        if "boundary=" not in content_type:
            return {}, {}

        boundary = content_type.split("boundary=")[1].strip()
        if boundary.startswith('"') and boundary.endswith('"'):
            boundary = boundary[1:-1]
        boundary_bytes = ("--" + boundary).encode("utf-8")

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        fields = {}
        files = {}

        parts = body.split(boundary_bytes)
        for part in parts:
            part = part.strip(b"\r\n")
            if not part or part == b"--":
                continue

            if b"\r\n\r\n" not in part:
                continue
            header_block, value = part.split(b"\r\n\r\n", 1)
            value = value.rstrip(b"\r\n")

            headers_text = header_block.decode("utf-8", errors="replace")
            disposition_line = next(
                (line for line in headers_text.split("\r\n")
                 if line.lower().startswith("content-disposition")),
                ""
            )

            name = None
            filename = None
            for piece in disposition_line.split(";"):
                piece = piece.strip()
                if piece.startswith("name="):
                    name = piece.split("=", 1)[1].strip('"')
                elif piece.startswith("filename="):
                    filename = piece.split("=", 1)[1].strip('"')

            if name is None:
                continue

            if filename is not None:
                files[name] = (filename, value)
            else:
                fields[name] = value.decode("utf-8", errors="replace")

        return fields, files

    def do_GET(self):
        try:
            self._do_GET_impl()
        except Exception as e:
            self._send_server_error(e)

    def _do_GET_impl(self):
        path = urlparse(self.path).path
        session_id, session = get_session(self)

        if path == "/assets/forensic.jpg":
            self._serve_static_image("assets/forensic.jpg")
            return

        if not session["logged_in"]:
            if path == "/register":
                self._send_html(render_register_page(), session_id)
            else:
                self._send_html(render_login_page(), session_id)
            return

        if not vault_is_configured():
            self._send_html(render_vault_setup_page(), session_id)
            return

        if not session["vault_unlocked"]:
            self._send_html(render_vault_locked_page(), session_id)
            return

        if path == "/" or path == "/dashboard":
            self._send_html(render_dashboard_page(session), session_id)
            return

        if path == "/cases":
            query = parse_qs(urlparse(self.path).query)
            case_id = query.get("case_id", [None])[0]
            search = query.get("search", [""])[0]
            priority_filter = query.get("priority_filter", ["All"])[0]
            status_filter = query.get("status_filter", ["All"])[0]
            message = query.get("message", [None])[0]
            error = query.get("error", [None])[0]
            self._send_html(render_cases_page(
                session, case_id, search, priority_filter, status_filter, message, error
            ), session_id)
            return

        if path == "/cases/report":
            query = parse_qs(urlparse(self.path).query)
            case_id = query.get("case_id", [None])[0]
            case_row = get_case(case_id) if case_id else None
            if not case_row or session["role"] != "Admin":
                self.send_response(403)
                self.end_headers()
                return
            filename = f"{case_id}_Report.html"
            generate_case_report(case_id, filename)
            with open(filename, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(data)))
            self._set_session_cookie(session_id)
            self.end_headers()
            self.wfile.write(data)
            os.remove(filename)
            return

        if path == "/evidence/search":
            query = parse_qs(urlparse(self.path).query)
            search_term = query.get("search_term", [""])[0]
            self._send_html(render_evidence_search_page(session, search_term), session_id)
            return

        if path == "/evidence/details":
            query = parse_qs(urlparse(self.path).query)
            evidence_id = query.get("evidence_id", [None])[0]
            self._send_html(render_evidence_details_page(session, evidence_id), session_id)
            return

        if path == "/evidence/preview":
            query = parse_qs(urlparse(self.path).query)
            evidence_id = query.get("evidence_id", [None])[0]
            self._serve_evidence_preview(evidence_id)
            return

        if path == "/vault":
            self._send_html(render_vault_page(session), session_id)
            return

        if path == "/evidence/timeline":
            query = parse_qs(urlparse(self.path).query)
            evidence_id = query.get("evidence_id", [None])[0]
            self._send_html(render_timeline_page(session, evidence_id), session_id)
            return

        if path == "/custody":
            self._send_html(render_custody_page(session), session_id)
            return

        if path == "/reports/generate":
            self._send_html(render_generate_report_page(session), session_id)
            return

        if path == "/reports/verify-signature":
            query = parse_qs(urlparse(self.path).query)
            case_id = query.get("case_id", [None])[0]
            result = query.get("result", [None])[0]
            self._send_html(render_verify_signature_page(session, case_id, result), session_id)
            return

        if path == "/evidence/verify":
            query = parse_qs(urlparse(self.path).query)
            message = query.get("message", [None])[0]
            message_type = query.get("type", ["info"])[0]
            self._send_html(render_verify_evidence_page(session, message, message_type), session_id)
            return

        if path == "/metadata":
            query = parse_qs(urlparse(self.path).query)
            evidence_id = query.get("evidence_id", [None])[0]
            metadata = _extract_metadata_for_evidence(evidence_id) if evidence_id else None
            self._send_html(render_metadata_page(session, evidence_id, metadata), session_id)
            return

        if path == "/metadata/export":
            query = parse_qs(urlparse(self.path).query)
            evidence_id = query.get("evidence_id", [None])[0]
            metadata = _extract_metadata_for_evidence(evidence_id) if evidence_id else {}
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(["Property", "Value"])
            for k, v in (metadata or {}).items():
                writer.writerow([k, v])
            data = buffer.getvalue().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv")
            self.send_header("Content-Disposition", f'attachment; filename="evidence_{evidence_id}_metadata.csv"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/activity":
            query = parse_qs(urlparse(self.path).query)
            user_filter = query.get("user", ["All"])[0]
            action_filter = query.get("action", ["All"])[0]
            search = query.get("search", [""])[0]
            self._send_html(render_activity_page(session, user_filter, action_filter, search), session_id)
            return

        if path == "/activity/export.csv":
            query = parse_qs(urlparse(self.path).query)
            user_filter = query.get("user", ["All"])[0]
            action_filter = query.get("action", ["All"])[0]
            search = query.get("search", [""])[0]
            logs = get_audit_logs()
            if user_filter != "All":
                logs = [log for log in logs if log["username"] == user_filter]
            if action_filter != "All":
                logs = [log for log in logs if log["action"] == action_filter]
            if search:
                logs = [log for log in logs if search.lower() in log["action"].lower()]
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(["username", "action", "timestamp"])
            for log in logs:
                writer.writerow([log["username"], log["action"], log["timestamp"]])
            data = buffer.getvalue().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv")
            self.send_header("Content-Disposition", 'attachment; filename="activity_logs.csv"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/users":
            query = parse_qs(urlparse(self.path).query)
            search = query.get("search", [""])[0]
            message = query.get("message", [None])[0]
            self._send_html(render_users_page(session, search, message), session_id)
            return

        if path == "/audit":
            self._send_html(render_audit_logs_page(session), session_id)
            return

        route = next((r for r in ROUTES if r[0] == path), None)
        if route:
            _, label, allowed_roles = route
            if allowed_roles and session["role"] not in allowed_roles:
                self._send_html(render_authenticated_page(
                    session, path, "Access Denied",
                    '<div class="error">You do not have permission to view this page.</div>'
                ), session_id, status=403)
                return
            self._send_html(render_authenticated_page(
                session, path, label, render_stub_page(label)
            ), session_id)
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        try:
            self._do_POST_impl()
        except Exception as e:
            self._send_server_error(e)

    def _do_POST_impl(self):
        path = urlparse(self.path).path
        session_id, session = get_session(self)

        content_type = self.headers.get("Content-Type", "")
        if content_type.startswith("multipart/form-data"):
            if path == "/cases/evidence/add":
                fields, files = self._read_multipart()
                case_id = fields.get("case_id", "")
                title = fields.get("title", "")
                uploaded = files.get("evidence_file")
                if not uploaded or not title:
                    self._redirect(f"/cases?case_id={case_id}&error=Title+and+file+required", session_id)
                    return
                filename, file_bytes = uploaded
                client_ip = self.client_address[0]
                save_evidence(case_id, title, filename, file_bytes, session["username"], client_ip)
                self._redirect(f"/cases?case_id={case_id}&message=Evidence+Added", session_id)
                return
            self.send_response(404)
            self.end_headers()
            return

        form = self._read_form()

        if path == "/login":
            role = login(form.get("username", ""), form.get("password", ""))
            if role:
                session["logged_in"] = True
                session["username"] = form.get("username")
                session["role"] = role
                self._redirect("/", session_id)
            else:
                self._send_html(render_login_page(error="Invalid Credentials"), session_id)
            return

        if path == "/register":
            username = form.get("username", "")
            password = form.get("password", "")
            confirm = form.get("confirm", "")
            if password != confirm:
                self._send_html(render_register_page(error="Passwords do not match."), session_id)
                return
            success = create_user(username, password, "Viewer")
            if success:
                self._send_html(render_register_page(success="Account Created Successfully"), session_id)
            else:
                self._send_html(render_register_page(error="Username Already Exists"), session_id)
            return

        if path == "/vault/setup":
            master_password = form.get("master_password", "")
            confirm = form.get("confirm_master_password", "")
            if master_password != confirm:
                self._send_html(render_vault_setup_page(error="Passwords do not match."), session_id)
                return
            success, message = setup_master_password(master_password)
            if success:
                session["vault_unlocked"] = True
                self._redirect("/", session_id)
            else:
                self._send_html(render_vault_setup_page(error=message), session_id)
            return

        if path == "/vault/unlock":
            master_password = form.get("master_password", "")
            if verify_master_password(master_password):
                session["vault_unlocked"] = True
                self._redirect("/", session_id)
            else:
                self._send_html(render_vault_locked_page(error="Invalid master password."), session_id)
            return

        if path == "/vault/lock":
            session["vault_unlocked"] = False
            self._redirect("/", session_id)
            return

        if path == "/logout":
            session["logged_in"] = False
            session["username"] = None
            session["role"] = None
            self._redirect("/", session_id)
            return

        if path == "/cases/create":
            case_id = form.get("case_id", "").strip()
            if not case_id:
                self._redirect("/cases?error=Case+ID+is+required", session_id)
                return
            try:
                create_case(
                    case_id,
                    form.get("case_name", ""),
                    form.get("description", ""),
                    session["username"],
                    form.get("priority", "Low"),
                )
            except sqlite3.IntegrityError:
                self._redirect(
                    f"/cases?error=Case+ID+%27{case_id}%27+already+exists",
                    session_id
                )
                return
            self._redirect("/cases?message=Case+Created", session_id)
            return

        if path == "/cases/update":
            case_id = form.get("case_id", "")
            case_row = get_case(case_id)
            if case_row:
                update_case(
                    case_id,
                    form.get("case_name", ""),
                    form.get("description", ""),
                    case_row[4],  # investigator unchanged, matches original behavior
                    form.get("priority", "Low"),
                    form.get("status", "Open"),
                )
            self._redirect(f"/cases?case_id={case_id}&message=Case+Updated", session_id)
            return

        if path == "/cases/close":
            case_id = form.get("case_id", "")
            if session["role"] != "Admin":
                self._redirect(f"/cases?case_id={case_id}&error=Admins+only", session_id)
                return
            success, result = close_case(case_id)
            if success:
                self._redirect(f"/cases?case_id={case_id}&message=Case+closed+and+signed", session_id)
            else:
                self._redirect(f"/cases?case_id={case_id}&error={result}", session_id)
            return

        if path == "/cases/delete":
            case_id = form.get("case_id", "")
            if session["role"] != "Admin":
                self._redirect(f"/cases?error=Admins+only", session_id)
                return
            delete_case(case_id)
            self._redirect("/cases?message=Case+Deleted", session_id)
            return

        if path == "/custody/add":
            evidence_id = form.get("evidence_id", "")
            action = form.get("action", "")
            conn = sqlite3.connect("forensic.db")
            conn.execute("""
                INSERT INTO custody(evidence_id, action, person, timestamp)
                VALUES(?,?,?,?)
            """, (evidence_id, action, session["username"],
                  datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            conn.close()
            from ip_logger import log_ip_activity
            log_ip_activity(evidence_id, session["username"], action, self.client_address[0])
            self._redirect("/custody", session_id)
            return

        if path == "/reports/generate/download":
            evidence_id = form.get("evidence_id", "")
            conn = sqlite3.connect("forensic.db")
            evidence_row = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
            custody_records = conn.execute(
                "SELECT * FROM custody WHERE evidence_id=?", (evidence_id,)
            ).fetchall()
            conn.close()
            if not evidence_row:
                self._redirect("/reports/generate", session_id)
                return
            os.makedirs("reports", exist_ok=True)
            report_path = f"reports/report_{evidence_id}.html"
            report_generator.generate_report(report_path, evidence_row, custody_records)
            with open(report_path, "rb") as f:
                data = f.read()
            log_action(session["username"], f"Generated Report {evidence_id}")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Disposition", f'attachment; filename="report_{evidence_id}.html"')
            self.send_header("Content-Length", str(len(data)))
            self._set_session_cookie(session_id)
            self.end_headers()
            self.wfile.write(data)
            os.remove(report_path)
            return

        if path == "/reports/verify-signature/verify":
            case_id = form.get("case_id", "")
            conn = sqlite3.connect("forensic.db")
            row = conn.execute(
                "SELECT report_signature FROM cases WHERE case_id=?", (case_id,)
            ).fetchone()
            conn.close()
            current_summary = build_case_summary(case_id)
            valid = verify_case_summary(current_summary, row[0] if row else None)
            result = "valid" if valid else "invalid"
            self._redirect(f"/reports/verify-signature?case_id={case_id}&result={result}", session_id)
            return

        if path == "/evidence/verify/run":
            evidence_id = form.get("evidence_id", "")
            conn = sqlite3.connect("forensic.db")
            row = conn.execute(
                "SELECT title, encrypted_path, sha256 FROM evidence WHERE id=?", (evidence_id,)
            ).fetchone()
            conn.close()
            if not row:
                self._redirect("/evidence/verify", session_id)
                return
            title, encrypted_path, stored_hash = row
            client_ip = self.client_address[0]
            try:
                data = decrypt_file(encrypted_path)
            except (FileNotFoundError, ValueError):
                self._redirect(
                    f"/evidence/verify?message=Could+not+decrypt+evidence+for+verification&type=error",
                    session_id
                )
                return
            import hashlib as _hashlib
            current_hash = _hashlib.sha256(data).hexdigest()
            if current_hash == stored_hash:
                save_verification(evidence_id, session["username"], "Verified")
                from ip_logger import log_ip_activity
                log_ip_activity(evidence_id, session["username"], "Verified", client_ip)
                self._redirect("/evidence/verify?message=Integrity+Verified&type=success", session_id)
            else:
                create_alert(evidence_id, title, session["username"], stored_hash, current_hash)
                save_verification(evidence_id, session["username"], "Tampered")
                log_action(session["username"], f"Tamper detected: {title}")
                from ip_logger import log_ip_activity
                log_ip_activity(evidence_id, session["username"], "Tampered", client_ip)
                self._redirect("/evidence/verify?message=Evidence+Tampered&type=error", session_id)
            return

        if path == "/users/update-role":
            if session["role"] != "Admin":
                self._redirect("/users?message=Admins+only", session_id)
                return
            update_role(form.get("user_id", ""), form.get("role", "Viewer"))
            self._redirect("/users?message=Role+Updated", session_id)
            return

        if path == "/users/delete":
            if session["role"] != "Admin":
                self._redirect("/users?message=Admins+only", session_id)
                return
            delete_user(form.get("user_id", ""))
            self._redirect("/users?message=User+Deleted", session_id)
            return

        if path == "/users/create":
            if session["role"] != "Admin":
                self._redirect("/users?message=Admins+only", session_id)
                return
            success = create_user(
                form.get("username", ""), form.get("password", ""), form.get("role", "Viewer")
            )
            if success:
                log_action(session["username"], f"Created User: {form.get('username', '')}")
                self._redirect("/users?message=User+Created+Successfully", session_id)
            else:
                self._redirect("/users?message=Username+already+exists", session_id)
            return

        self.send_response(404)
        self.end_headers()

    def _serve_evidence_preview(self, evidence_id):
        if not evidence_id:
            self.send_response(404)
            self.end_headers()
            return
        conn = sqlite3.connect("forensic.db")
        row = conn.execute(
            "SELECT filename, encrypted_path FROM evidence WHERE id=?", (evidence_id,)
        ).fetchone()
        conn.close()
        if not row:
            self.send_response(404)
            self.end_headers()
            return
        filename, encrypted_path = row
        try:
            data = decrypt_file(encrypted_path)
        except (FileNotFoundError, ValueError):
            self.send_response(404)
            self.end_headers()
            return
        extension = filename.split(".")[-1].lower() if "." in filename else ""
        content_types = {
            "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
            "bmp": "image/bmp", "gif": "image/gif", "pdf": "application/pdf",
        }
        content_type = content_types.get(extension, "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        if extension == "pdf":
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _serve_static_image(self, filepath):
        if not os.path.exists(filepath):
            self.send_response(404)
            self.end_headers()
            return
        with open(filepath, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "image/jpeg")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass


def run(port=8000):
    server = ThreadingHTTPServer(("0.0.0.0", port), ForensiVaultHandler)
    print(f"LexVault running at http://localhost:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()