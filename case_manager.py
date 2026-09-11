import sqlite3
from datetime import datetime

DB = "forensic.db"

def create_case(case_id,
                case_name,
                description,
                investigator,
                priority):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
    INSERT INTO cases(
        case_id,
        case_name,
        description,
        investigator,
        priority,
        status,
        created_at
    )
    VALUES(?,?,?,?,?,?,?)
    """,
    (
        case_id,
        case_name,
        description,
        investigator,
        priority,
        "Open",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()

def get_cases():
    conn = sqlite3.connect(DB)
    cases = conn.execute("""
    SELECT *
    FROM cases
    ORDER BY created_at DESC
    """).fetchall()
    conn.close()
    return cases

def build_case_summary(case_id):
    conn = sqlite3.connect(DB)
    case = conn.execute("""
        SELECT
            case_id,
            case_name,
            description,
            investigator,
            priority,
            status,
            created_at
        FROM cases
        WHERE case_id=?
    """, (case_id,)).fetchone()

    if not case:
        conn.close()
        return None

    evidence = conn.execute("""
        SELECT
            id,
            title,
            filename,
            uploaded_by,
            upload_time,
            sha256
        FROM evidence
        WHERE case_id=?
        ORDER BY id
    """, (case_id,)).fetchall()

    custody = conn.execute("""
        SELECT
            evidence_id,
            timestamp,
            action,
            person
        FROM custody
        WHERE evidence_id IN (
            SELECT id
            FROM evidence
            WHERE case_id=?
        )
        ORDER BY timestamp, evidence_id
    """, (case_id,)).fetchall()
    verification = conn.execute("""
        SELECT
            evidence_id,
            verification_time,
            verified_by,
            status
        FROM verification_logs
        WHERE evidence_id IN (
            SELECT id
            FROM evidence
            WHERE case_id=?
        )
        ORDER BY verification_time, evidence_id
    """, (case_id,)).fetchall()
    alerts = conn.execute("""
        SELECT
            evidence_id,
            detection_time,
            severity,
            status,
            original_hash,
            current_hash
        FROM tamper_alerts
        WHERE evidence_id IN (
            SELECT id
            FROM evidence
            WHERE case_id=?
        )
        ORDER BY detection_time, evidence_id
    """, (case_id,)).fetchall()
    conn.close()
    lines = []
    lines.append("FORENSIVAULT CASE REPORT")
    lines.append("========================")
    lines.append("")
    lines.append("CASE")
    lines.append(f"Case ID: {case[0]}")
    lines.append(f"Case Name: {case[1]}")
    lines.append(f"Description: {case[2]}")
    lines.append(f"Investigator: {case[3]}")
    lines.append(f"Priority: {case[4]}")
    lines.append(f"Status: {case[5]}")
    lines.append(f"Created At: {case[6]}")
    lines.append("")
    lines.append("EVIDENCE")
    lines.append("--------")
    for item in evidence:
        lines.append(
            f"ID={item[0]} | "
            f"Title={item[1]} | "
            f"Filename={item[2]} | "
            f"Uploaded By={item[3]} | "
            f"Upload Time={item[4]} | "
            f"SHA256={item[5]}"
        )
    if not evidence:
        lines.append("No evidence.")
    lines.append("")
    lines.append("CHAIN OF CUSTODY")
    lines.append("-----------------")
    for item in custody:
        lines.append(
            f"Evidence ID={item[0]} | "
            f"Timestamp={item[1]} | "
            f"Action={item[2]} | "
            f"Person={item[3]}"
        )
    if not custody:
        lines.append("No custody records.")
    lines.append("")
    lines.append("VERIFICATION HISTORY")
    lines.append("--------------------")
    for item in verification:
        lines.append(
            f"Evidence ID={item[0]} | "
            f"Time={item[1]} | "
            f"Verified By={item[2]} | "
            f"Status={item[3]}"
        )
    if not verification:
        lines.append("No verification records.")
    lines.append("")
    lines.append("TAMPER ALERTS")
    lines.append("-------------")
    for item in alerts:
        lines.append(
            f"Evidence ID={item[0]} | "
            f"Detection Time={item[1]} | "
            f"Severity={item[2]} | "
            f"Status={item[3]} | "
            f"Original Hash={item[4]} | "
            f"Current Hash={item[5]}"
        )
    if not alerts:
        lines.append("No tamper alerts.")
    lines.append("")
    return "\n".join(lines)

def close_case(case_id):
    from report_signing import sign_case_summary
    summary = build_case_summary(case_id)
    if summary is None:
        return False, "Case not found."
    conn = sqlite3.connect(DB)
    conn.execute("""
        UPDATE cases
        SET status='Closed'
        WHERE case_id=?
    """, (case_id,))
    conn.commit()
    conn.close()
    summary = build_case_summary(case_id)
    signature = sign_case_summary(summary)
    signed_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    conn = sqlite3.connect(DB)
    conn.execute("""
        UPDATE cases
        SET
            report_signature=?,
            report_signed_at=?
        WHERE case_id=?
    """, (
        signature,
        signed_at,
        case_id
    ))
    conn.commit()
    conn.close()
    return True, signature

def get_case(case_id):
    conn = sqlite3.connect(DB)
    case = conn.execute("""
    SELECT *
    FROM cases
    WHERE case_id=?
    """, (case_id,)).fetchone()
    conn.close()
    return case

def get_case_evidence(case_id):
    conn = sqlite3.connect(DB)
    evidence = conn.execute("""
    SELECT
        id,
        title,
        filename,
        uploaded_by,
        upload_time
    FROM evidence
    WHERE case_id=?
    ORDER BY upload_time DESC
    """, (case_id,)).fetchall()
    conn.close()
    return evidence

def get_case_alerts(case_id):
    conn = sqlite3.connect(DB)
    count = conn.execute("""
    SELECT COUNT(*)
    FROM tamper_alerts
    WHERE evidence_id IN (
        SELECT id
        FROM evidence
        WHERE case_id=?
    )
    """, (case_id,)).fetchone()[0]
    conn.close()
    return count

def get_case_statistics(case_id):
    conn = sqlite3.connect(DB)
    stats = {}
    stats["evidence"] = conn.execute("""
    SELECT COUNT(*)
    FROM evidence
    WHERE case_id=?
    """, (case_id,)).fetchone()[0]

    stats["verified"] = conn.execute("""
    SELECT COUNT(*)
    FROM verification_logs
    WHERE evidence_id IN (
        SELECT id
        FROM evidence
        WHERE case_id=?
    )
    AND status='Verified'
    """, (case_id,)).fetchone()[0]

    stats["tampered"] = conn.execute("""
    SELECT COUNT(*)
    FROM verification_logs
    WHERE evidence_id IN (
        SELECT id
        FROM evidence
        WHERE case_id=?
    )
    AND status='Tampered'
    """, (case_id,)).fetchone()[0]

    conn.close()
    return stats


def update_case(
    case_id,
    case_name,
    description,
    investigator,
    priority,
    status
):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
    UPDATE cases
    SET
        case_name=?,
        description=?,
        investigator=?,
        priority=?,
        status=?
    WHERE case_id=?
    """,
    (
        case_name,
        description,
        investigator,
        priority,
        status,
        case_id
    ))

    conn.commit()
    conn.close()

def delete_case(case_id):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute(
        "DELETE FROM cases WHERE case_id=?",
        (case_id,)
    )
    conn.commit()
    conn.close()

def get_case_statistics(case_id):

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    total = c.execute("""
    SELECT COUNT(*)
    FROM evidence
    WHERE case_id=?
    """,(case_id,)).fetchone()[0]

    verified = c.execute("""
    SELECT COUNT(*)
    FROM verification_logs
    WHERE status='Verified'
    AND evidence_id IN (
        SELECT id FROM evidence
        WHERE case_id=?
    )
    """,(case_id,)).fetchone()[0]

    tampered = c.execute("""
    SELECT COUNT(*)
    FROM verification_logs
    WHERE status='Tampered'
    AND evidence_id IN (
        SELECT id FROM evidence
        WHERE case_id=?
    )
    """,(case_id,)).fetchone()[0]

    alerts = c.execute("""
    SELECT COUNT(*)
    FROM tamper_alerts
    WHERE evidence_id IN(
        SELECT id
        FROM evidence
        WHERE case_id=?
    )
    """,(case_id,)).fetchone()[0]

    conn.close()

    return total, verified, tampered, alerts