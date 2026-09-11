import sqlite3


DB = "forensic.db"


def get_dashboard_data():

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    data = {}

    data["evidence"] = conn.execute(
        "SELECT COUNT(*) FROM evidence"
    ).fetchone()[0]

    data["users"] = conn.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]

    data["alerts"] = conn.execute(
        """
        SELECT COUNT(*)
        FROM tamper_alerts
        WHERE status='Active'
        """
    ).fetchone()[0]

    data["verified"] = conn.execute(
        """
        SELECT COUNT(*)
        FROM verification_logs
        WHERE status='Verified'
        """
    ).fetchone()[0]

    data["tampered"] = conn.execute(
        """
        SELECT COUNT(*)
        FROM verification_logs
        WHERE status='Tampered'
        """
    ).fetchone()[0]
    uploads = [dict(row) for row in conn.execute("""
        SELECT upload_time
        FROM evidence
    """).fetchall()]

    roles = [dict(row) for row in conn.execute("""
        SELECT role, COUNT(*) AS count
        FROM users
        GROUP BY role
    """).fetchall()]

    activity = [dict(row) for row in conn.execute("""
        SELECT username,
               action,
               timestamp
        FROM audit_logs
        ORDER BY timestamp DESC
        LIMIT 10
    """).fetchall()]

    conn.close()

    return data, uploads, roles, activity