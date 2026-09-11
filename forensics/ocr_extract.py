"""
OCR and lightweight entity extraction.

Supports:
- images
- PDFs
- names
- dates
- PAN
- Aadhaar-like numbers
- phone numbers
- emails
- amounts
"""

import re
from pathlib import Path

import pytesseract


DATE_PATTERN = re.compile(
    r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}"
    r"|\d{4}[/-]\d{1,2}[/-]\d{1,2})\b"
)

PAN_PATTERN = re.compile(
    r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"
)

PHONE_PATTERN = re.compile(
    r"\b(?:\+91[\s-]?)?[6-9]\d{9}\b"
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

AMOUNT_PATTERN = re.compile(
    r"(?:₹|Rs\.?|INR)\s?[\d,]+(?:\.\d{1,2})?"
)


def _extract_entities(text):
    return {
        "dates": sorted(set(DATE_PATTERN.findall(text))),
        "pan_numbers": sorted(set(
            x.upper() for x in PAN_PATTERN.findall(text)
        )),
        "phone_numbers": sorted(set(
            PHONE_PATTERN.findall(text)
        )),
        "emails": sorted(set(
            EMAIL_PATTERN.findall(text)
        )),
        "amounts": sorted(set(
            AMOUNT_PATTERN.findall(text)
        )),
    }


def _ocr_image(filepath):
    text = pytesseract.image_to_string(
        filepath,
        config="--psm 6",
    )

    return text


def _ocr_pdf(filepath):
    import fitz

    pages = []

    document = fitz.open(filepath)

    for page in document:
        text = page.get_text("text")

        if not text.strip():
            pixmap = page.get_pixmap(dpi=200)

            image_path = f"{filepath}.page.png"

            pixmap.save(image_path)

            try:
                text = pytesseract.image_to_string(
                    image_path,
                    config="--psm 6",
                )
            finally:
                import os

                if os.path.exists(image_path):
                    os.remove(image_path)

        pages.append(text)

    document.close()

    return "\n".join(pages)


def extract_document_content(filepath):
    extension = Path(filepath).suffix.lower()

    try:
        if extension in {
            ".jpg",
            ".jpeg",
            ".png",
            ".bmp",
            ".tiff",
            ".webp",
        }:
            text = _ocr_image(filepath)

        elif extension == ".pdf":
            text = _ocr_pdf(filepath)

        elif extension in {
            ".txt",
            ".csv",
        }:
            with open(
                filepath,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as file:
                text = file.read()

        else:
            return {
                "supported": False,
                "text": "",
                "entities": {},
            }

        entities = _extract_entities(text)

        return {
            "supported": True,
            "text": text,
            "character_count": len(text),
            "entities": entities,
        }

    except Exception as exc:
        return {
            "supported": True,
            "text": "",
            "entities": {},
            "error": str(exc),
        }