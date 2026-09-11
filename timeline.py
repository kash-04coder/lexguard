import sqlite3
from datetime import datetime

DB = "forensic.db"

def get_timeline(evidence_id):

    conn = sqlite3.connect(DB)

    events = []

    ip_logs = conn.execute("""
        SELECT action, username, ip_address
        FROM evidence_ip_logs
        WHERE evidence_id=?
        ORDER BY timestamp
    """, (evidence_id,)).fetchall()
    ip_by_activity = {
        (action, username): ip_address
        for action, username, ip_address in ip_logs
    }

    def activity_ip(action, username):
        return ip_by_activity.get((action, username), "Not recorded")

    # Evidence Registration
    evidence = conn.execute("""
        SELECT
            uploaded_by,
            upload_time,
            title
        FROM evidence
        WHERE id=?
    """, (evidence_id,)).fetchone()

    if evidence:
        events.append({
            "time": evidence[1],
            "user": evidence[0],
            "event": "Evidence Registered",
            "ip_address": activity_ip("Evidence Registered", evidence[0]),
            "icon": "📁",
            "color": "green"
        })

    # Chain of Custody
    custody = conn.execute("""
        SELECT
            action,
            person,
            timestamp
        FROM custody
        WHERE evidence_id=?
    """, (evidence_id,)).fetchall()

    for row in custody:
        if row[0] == "Evidence Registered":
            continue

        events.append({
            "time": row[2],
            "user": row[1],
            "event": row[0],
            "ip_address": activity_ip(row[0], row[1]),
            "icon": "📜",
            "color": "blue"
        })

    # Verification Logs
    verification = conn.execute("""
        SELECT
            status,
            verified_by,
            verification_time
        FROM verification_logs
        WHERE evidence_id=?
    """, (evidence_id,)).fetchall()

    for row in verification:

        if row[0] == "Verified":

            icon = "✅"
            color = "green"

        else:

            icon = "🚨"
            color = "red"

        events.append({
            "time": row[2],
            "user": row[1],
            "event": row[0],
            "ip_address": activity_ip(row[0], row[1]),
            "icon": icon,
            "color": color
        })

    # Tamper Alerts
    alerts = conn.execute("""
        SELECT
            detected_by,
            detection_time
        FROM tamper_alerts
        WHERE evidence_id=?
    """, (evidence_id,)).fetchall()

    for row in alerts:

        events.append({
            "time": row[1],
            "user": row[0],
            "event": "Tamper Alert Created",
            "ip_address": "Not recorded",
            "icon": "⚠",
            "color": "orange"
        })

    conn.close()

    if not events:
        return events

    events.sort(key=lambda e: datetime.strptime(e["time"], "%Y-%m-%d %H:%M:%S"))

    return events   
