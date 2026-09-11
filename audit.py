
import sqlite3
from datetime import datetime

def log_action(username,action):
    conn = sqlite3.connect(
        "forensic.db",
        timeout=10
    )
    c = conn.cursor()
    c.execute(
        "INSERT INTO audit_logs(username,action,timestamp) VALUES(?,?,?)",
        (
            username,
            action,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )
    conn.commit()
    conn.close()


def get_audit_logs():
    conn = sqlite3.connect("forensic.db")
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
    SELECT
        username,
        action,
        timestamp
    FROM audit_logs
    ORDER BY timestamp DESC
    """).fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_audit_users():
    conn = sqlite3.connect("forensic.db")
    users = conn.execute("""
    SELECT DISTINCT username
    FROM audit_logs
    ORDER BY username
    """).fetchall()
    conn.close()
    return [u[0] for u in users]

