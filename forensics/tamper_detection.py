"""
Local image tamper screening.

Provides a lightweight fallback when a TruFor model is not installed.

This detects suspicious pixel/compression inconsistencies.
It is NOT equivalent to a trained TruFor model.
"""

import os
from pathlib import Path

import cv2
import numpy as np


IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
}


def _error_level_analysis(image, quality=90):
    encode_params = [
        int(cv2.IMWRITE_JPEG_QUALITY),
        quality,
    ]

    success, encoded = cv2.imencode(
        ".jpg",
        image,
        encode_params,
    )

    if not success:
        raise RuntimeError("Could not encode image for ELA.")

    recompressed = cv2.imdecode(
        encoded,
        cv2.IMREAD_COLOR,
    )

    difference = cv2.absdiff(
        image,
        recompressed,
    )

    gray = cv2.cvtColor(
        difference,
        cv2.COLOR_BGR2GRAY,
    )

    return gray


def detect_tampering(filepath, heatmap_path=None):
    extension = Path(filepath).suffix.lower()

    if extension not in IMAGE_EXTENSIONS:
        return {
            "supported": False,
            "verdict": "NOT_APPLICABLE",
            "score": 0,
            "heatmap": None,
        }

    image = cv2.imread(filepath)

    if image is None:
        return {
            "supported": False,
            "verdict": "ERROR",
            "score": 0,
            "heatmap": None,
            "error": "Unable to read image.",
        }

    ela = _error_level_analysis(image)

    mean_value = float(np.mean(ela))
    std_value = float(np.std(ela))

    threshold = mean_value + (2.0 * std_value)

    mask = (ela > threshold).astype(np.uint8) * 255

    kernel = np.ones((5, 5), np.uint8)

    mask = cv2.morphologyEx(
        mask,
        cv2.MORPH_OPEN,
        kernel,
    )

    mask = cv2.morphologyEx(
        mask,
        cv2.MORPH_CLOSE,
        kernel,
    )

    suspicious_ratio = float(
        np.count_nonzero(mask) / mask.size
    )

    score = min(
        int(suspicious_ratio * 500),
        100,
    )

    if score >= 60:
        verdict = "HIGH_SUSPICION"
    elif score >= 30:
        verdict = "REVIEW"
    else:
        verdict = "LOW_SUSPICION"

    saved_heatmap = None

    if heatmap_path:
        heatmap = cv2.applyColorMap(
            ela,
            cv2.COLORMAP_JET,
        )

        overlay = cv2.addWeighted(
            image,
            0.65,
            heatmap,
            0.35,
            0,
        )

        os.makedirs(
            os.path.dirname(heatmap_path) or ".",
            exist_ok=True,
        )

        cv2.imwrite(
            heatmap_path,
            overlay,
        )

        saved_heatmap = heatmap_path

    return {
        "supported": True,
        "method": "ELA_fallback",
        "verdict": verdict,
        "score": score,
        "suspicious_ratio": suspicious_ratio,
        "heatmap": saved_heatmap,
        "statistics": {
            "mean_ela": mean_value,
            "std_ela": std_value,
        },
        "warning": (
            "ELA is a screening technique. Replace with a trained "
            "TruFor model for production-grade pixel-level localization."
        ),
    }