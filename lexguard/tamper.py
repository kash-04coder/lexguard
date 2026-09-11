import sqlite3
from datetime import datetime

DB = "forensic.db"
def create_alert(evidence_id, title, username, original_hash, current_hash):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
    INSERT INTO tamper_alerts(
        evidence_id,
        evidence_title,
        detected_by,
        detection_time,
        original_hash,
        current_hash,
        severity,
        status
    )
    VALUES(?,?,?,?,?,?,?,?)
    """,
    (
        evidence_id,
        title,
        username,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        original_hash,
        current_hash,
        "HIGH",
        "Active"
    ))

    conn.commit()
    conn.close()