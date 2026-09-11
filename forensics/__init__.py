"""
LexGuard forensic analysis package.

All forensic modules are designed to be:
- local-first
- deterministic where possible
- independently testable
- safe to fail without breaking document ingestion
"""

from .metadata_forensics import analyze_metadata
from .ai_detection import detect_ai_generated
from .tamper_detection import detect_tampering
from .ocr_extract import extract_document_content
from .reconciliation import analyze_financial_document
from .report_narration import narrate_report

__all__ = [
    "analyze_metadata",
    "detect_ai_generated",
    "detect_tampering",
    "extract_document_content",
    "analyze_financial_document",
    "narrate_report",
]