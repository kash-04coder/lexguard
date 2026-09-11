import sqlite3
from datetime import datetime

def save_verification(
        evidence_id,
        username,
        status):
    conn = sqlite3.connect("forensic.db")
    c = conn.cursor()
    c.execute("""
    INSERT INTO verification_logs(
        evidence_id,
        verified_by,
        verification_time,
        status
    )
    VALUES(?,?,?,?)
    """,
    (
        evidence_id,
        username,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        status
    ))

    conn.commit()
    conn.close()