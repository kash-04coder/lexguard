import sqlite3


DB = "forensic.db"

def get_evidence_details(evidence_id):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    evidence = conn.execute("""
        SELECT *
        FROM evidence
        WHERE id=?
    """, (evidence_id,)).fetchone()
    custody = [dict(row) for row in conn.execute("""
        SELECT *
        FROM custody
        WHERE evidence_id=?
        ORDER BY timestamp
    """, (evidence_id,)).fetchall()]

    verification = [dict(row) for row in conn.execute("""
        SELECT *
        FROM verification_logs
        WHERE evidence_id=?
        ORDER BY verification_time DESC
    """, (evidence_id,)).fetchall()]

    ip_logs = [dict(row) for row in conn.execute("""
        SELECT
        username,
        action,
        ip_address,
        timestamp
        FROM evidence_ip_logs
        WHERE evidence_id=?
        ORDER BY timestamp DESC
    """, (evidence_id,)).fetchall()]

    alerts = [dict(row) for row in conn.execute("""
        SELECT *
        FROM tamper_alerts
        WHERE evidence_id=?
        ORDER BY detection_time DESC
    """, (evidence_id,)).fetchall()]

    conn.close()

    return evidence, custody, verification, alerts, ip_logs