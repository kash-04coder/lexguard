"""
Financial document reconciliation and Benford's Law screening.
"""

import math
import re
from collections import Counter


AMOUNT_PATTERN = re.compile(
    r"(?:₹|Rs\.?|INR)?\s*"
    r"(\d[\d,]*(?:\.\d{1,2})?)"
)


def extract_numbers(text):
    values = []

    for match in AMOUNT_PATTERN.findall(text):
        try:
            value = float(
                match.replace(",", "")
            )

            if value > 0:
                values.append(value)

        except ValueError:
            continue

    return values


def benford_analysis(numbers):
    first_digits = []

    for value in numbers:
        text = str(abs(value)).replace(".", "").lstrip("0")

        if text:
            first_digits.append(int(text[0]))

    if not first_digits:
        return {
            "available": False,
            "reason": "Not enough numeric data.",
        }

    counts = Counter(first_digits)

    expected = {
        digit: math.log10(1 + 1 / digit)
        for digit in range(1, 10)
    }

    observed = {
        digit: counts[digit] / len(first_digits)
        for digit in range(1, 10)
    }

    mad = sum(
        abs(observed[d] - expected[d])
        for d in range(1, 10)
    ) / 9

    if mad < 0.006:
        interpretation = "Close to Benford expectation"
    elif mad < 0.012:
        interpretation = "Acceptable deviation"
    else:
        interpretation = "Potential anomaly"

    return {
        "available": True,
        "sample_size": len(first_digits),
        "observed": observed,
        "expected": expected,
        "mad": mad,
        "interpretation": interpretation,
    }


def reconciliation_check(numbers):
    if len(numbers) < 2:
        return {
            "available": False,
            "issues": [],
        }

    issues = []

    total = sum(numbers)

    if total <= 0:
        issues.append(
            "Extracted financial values produce a non-positive total."
        )

    return {
        "available": True,
        "number_count": len(numbers),
        "sum_of_extracted_values": round(total, 2),
        "issues": issues,
    }


def analyze_financial_document(text):
    numbers = extract_numbers(text)

    return {
        "numbers": numbers,
        "reconciliation": reconciliation_check(numbers),
        "benford": benford_analysis(numbers),
    }