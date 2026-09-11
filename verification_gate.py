"""
Single entry point for LexGuard forensic verification.
"""

import hashlib
import os
import tempfile
from pathlib import Path

from encryption import decrypt_file

from forensics.ai_detection import detect_ai_generated
from forensics.tamper_detection import detect_tampering
from forensics.metadata_forensics import analyze_metadata
from forensics.ocr_extract import extract_document_content
from forensics.reconciliation import analyze_financial_document
from forensics.report_narration import narrate_report


IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".bmp",
    ".tiff",
}


def _risk_from_results(
    metadata,
    ai,
    tamper,
    financial,
):
    scores = []

    metadata_score = (
        metadata.get("content", {})
        .get("risk_score", 0)
    )

    ai_score = ai.get("score", 0)
    tamper_score = tamper.get("score", 0)

    scores.extend([
        metadata_score,
        ai_score,
        tamper_score,
    ])

    benford = financial.get("benford", {})

    if benford.get("available"):
        mad = benford.get("mad", 0)

        if mad >= 0.012:
            scores.append(60)
        elif mad >= 0.006:
            scores.append(30)

    if not scores:
        return 0

    return min(int(max(scores)), 100)


def run_verification(filepath, heatmap_path=None):
    extension = Path(filepath).suffix.lower()

    metadata = analyze_metadata(filepath)

    if extension in IMAGE_EXTENSIONS:
        ai = detect_ai_generated(filepath)

        if heatmap_path is None:
            heatmap_path = os.path.join(
                os.path.dirname(filepath),
                f"{Path(filepath).stem}_heatmap.png",
            )

        tamper = detect_tampering(
            filepath,
            heatmap_path=heatmap_path,
        )

    else:
        ai = {
            "supported": False,
            "verdict": "NOT_APPLICABLE",
            "score": 0,
        }

        tamper = {
            "supported": False,
            "verdict": "NOT_APPLICABLE",
            "score": 0,
        }

    ocr = extract_document_content(filepath)

    financial = analyze_financial_document(
        ocr.get("text", "")
    )

    results = {
        "metadata": metadata,
        "ai_detection": ai,
        "tamper_detection": tamper,
        "ocr": ocr,
        "financial": financial,
    }

    risk_score = _risk_from_results(
        metadata,
        ai,
        tamper,
        financial,
    )

    results["risk_score"] = risk_score

    if risk_score >= 70:
        results["risk_level"] = "HIGH"
        results["status"] = "PENDING_REVIEW"

    elif risk_score >= 40:
        results["risk_level"] = "MEDIUM"
        results["status"] = "PENDING_REVIEW"

    else:
        results["risk_level"] = "LOW"
        results["status"] = "SCREENED"

    results["narrative"] = narrate_report(
        results
    )

    return results


def verify_encrypted_version(
    encrypted_path,
    filename,
):
    """
    Decrypt one immutable LexGuard document version into a temporary file,
    run forensic verification, then remove the temporary plaintext file.
    """

    data = decrypt_file(encrypted_path)

    suffix = Path(filename).suffix

    temp = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=suffix,
    )

    try:
        temp.write(data)
        temp.close()

        heatmap_path = os.path.join(
            os.path.dirname(encrypted_path),
            f"{Path(encrypted_path).stem}_heatmap.png",
        )

        result = run_verification(
            temp.name,
            heatmap_path=heatmap_path,
        )

        result["sha256"] = hashlib.sha256(
            data
        ).hexdigest()

        return result

    finally:
        try:
            os.remove(temp.name)
        except FileNotFoundError:
            pass