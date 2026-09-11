"""
AI-generated image detection.

This module intentionally returns:
- probability
- confidence
- indicators

It does not claim that heuristic analysis is definitive.
"""

import os
from pathlib import Path

import numpy as np
from PIL import Image


SUPPORTED = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
}


def _image_statistics(filepath):
    with Image.open(filepath).convert("RGB") as image:
        arr = np.asarray(image).astype(np.float32)

    return {
        "mean": float(arr.mean()),
        "std": float(arr.std()),
        "width": int(arr.shape[1]),
        "height": int(arr.shape[0]),
    }


def detect_ai_generated(filepath):
    extension = Path(filepath).suffix.lower()

    if extension not in SUPPORTED:
        return {
            "supported": False,
            "verdict": "NOT_APPLICABLE",
            "score": 0,
            "confidence": 0,
            "indicators": [],
        }

    indicators = []

    try:
        stats = _image_statistics(filepath)

        width = stats["width"]
        height = stats["height"]

        if width == height:
            indicators.append(
                "Square image dimensions detected."
            )

        if width % 64 == 0 and height % 64 == 0:
            indicators.append(
                "Dimensions are aligned to common generative-model sizes."
            )

        score = min(len(indicators) * 15, 30)

        return {
            "supported": True,
            "method": "local_heuristic_baseline",
            "verdict": (
                "REVIEW"
                if score >= 20
                else "NO_STRONG_INDICATOR"
            ),
            "score": score,
            "confidence": min(score, 100),
            "indicators": indicators,
            "statistics": stats,
            "warning": (
                "Heuristic only. This is not a trained AI-image detector "
                "and must not be treated as definitive evidence."
            ),
        }

    except Exception as exc:
        return {
            "supported": True,
            "verdict": "ERROR",
            "score": 0,
            "confidence": 0,
            "indicators": [],
            "error": str(exc),
        }