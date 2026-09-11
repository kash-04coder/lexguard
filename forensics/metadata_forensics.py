"""
Deep metadata forensic analysis.

Supports:
- image EXIF
- PDF metadata
- filesystem timestamps
- editing-software indicators
- timestamp inconsistencies
"""

import os
from datetime import datetime
from pathlib import Path

from PIL import Image
from PIL.ExifTags import TAGS


EDITING_SOFTWARE = {
    "photoshop",
    "adobe photoshop",
    "gimp",
    "lightroom",
    "illustrator",
    "paint.net",
    "affinity",
    "canva",
    "pixlr",
    "snapseed",
}

IMAGE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".webp",
    ".bmp", ".tiff", ".tif"
}


def _normalise(value):
    if value is None:
        return ""

    if isinstance(value, bytes):
        try:
            return value.decode(errors="replace")
        except Exception:
            return str(value)

    return str(value)


def _timestamp(value):
    if not value:
        return None

    text = _normalise(value).strip()

    formats = [
        "%Y:%m:%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue

    return None


def analyze_image_metadata(filepath):
    result = {
        "available": True,
        "format": None,
        "width": None,
        "height": None,
        "exif": {},
        "editing_software": [],
        "anomalies": [],
        "risk_score": 0,
    }

    try:
        with Image.open(filepath) as image:
            result["format"] = image.format
            result["width"], result["height"] = image.size

            exif = image.getexif()

            for tag_id, value in exif.items():
                tag_name = TAGS.get(tag_id, str(tag_id))
                result["exif"][tag_name] = _normalise(value)

    except Exception as exc:
        result["available"] = False
        result["error"] = str(exc)
        return result

    software_values = []

    for key, value in result["exif"].items():
        value_lower = str(value).lower()

        if key.lower() in {
            "software",
            "processingsoftware",
            "hostcomputer",
        }:
            software_values.append(value_lower)

    for value in software_values:
        for software in EDITING_SOFTWARE:
            if software in value:
                result["editing_software"].append(value)
                result["anomalies"].append(
                    f"Editing software signature found: {value}"
                )
                result["risk_score"] += 25

    date_original = None
    date_digitized = None
    date_modified = None

    for key, value in result["exif"].items():
        key_lower = key.lower()

        if key_lower in {"datetimeoriginal", "datetimeoriginal"}:
            date_original = _timestamp(value)

        elif key_lower == "datetimedigitized":
            date_digitized = _timestamp(value)

        elif key_lower == "datetime":
            date_modified = _timestamp(value)

    if date_original and date_modified:
        if date_modified < date_original:
            result["anomalies"].append(
                "EXIF modification time predates original capture time."
            )
            result["risk_score"] += 35

    result["risk_score"] = min(result["risk_score"], 100)

    return result


def analyze_pdf_metadata(filepath):
    result = {
        "available": True,
        "metadata": {},
        "anomalies": [],
        "editing_software": [],
        "risk_score": 0,
    }

    try:
        import fitz

        document = fitz.open(filepath)

        metadata = document.metadata or {}

        for key, value in metadata.items():
            result["metadata"][key] = _normalise(value)

        document.close()

    except Exception as exc:
        result["available"] = False
        result["error"] = str(exc)
        return result

    software_text = " ".join(
        str(v).lower()
        for v in result["metadata"].values()
        if v
    )

    for software in EDITING_SOFTWARE:
        if software in software_text:
            result["editing_software"].append(software)
            result["anomalies"].append(
                f"PDF metadata contains editing-software signature: {software}"
            )
            result["risk_score"] += 25

    created = result["metadata"].get("creationDate")
    modified = result["metadata"].get("modDate")

    if created and modified:
        if str(modified) < str(created):
            result["anomalies"].append(
                "PDF modification date appears earlier than creation date."
            )
            result["risk_score"] += 35

    result["risk_score"] = min(result["risk_score"], 100)

    return result


def analyze_metadata(filepath):
    extension = Path(filepath).suffix.lower()

    filesystem = os.stat(filepath)

    result = {
        "filesystem": {
            "size": filesystem.st_size,
            "created": datetime.fromtimestamp(
                filesystem.st_ctime
            ).isoformat(),
            "modified": datetime.fromtimestamp(
                filesystem.st_mtime
            ).isoformat(),
        },
        "type": extension,
    }

    if extension in IMAGE_EXTENSIONS:
        result["content"] = analyze_image_metadata(filepath)

    elif extension == ".pdf":
        result["content"] = analyze_pdf_metadata(filepath)

    else:
        result["content"] = {
            "available": False,
            "anomalies": [],
            "risk_score": 0,
            "message": "Format-specific metadata analysis not available.",
        }

    return result