import sqlite3
from datetime import datetime

DB = "forensic.db"

def log_ip_activity(evidence_id, username, action, ip):
    conn = sqlite3.connect(DB)
    conn.execute("""
    INSERT INTO evidence_ip_logs(
        evidence_id,
        username,
        action,
        ip_address,
        timestamp
    )
    VALUES(?,?,?,?,?)
    """,(
        evidence_id,
        username,
        action,
        ip,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()