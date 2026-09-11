"""
Local Ollama report narration.

No case information is sent to a cloud API.
"""

import json
import os

import requests


OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://127.0.0.1:11434/api/generate",
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "llama3.2:1b",
)


def _fallback_report(results):
    risk = results.get("risk_score", 0)

    if risk >= 70:
        level = "HIGH"
    elif risk >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return (
        f"LexGuard forensic screening indicates a {level} risk level "
        f"with an aggregate screening score of {risk}/100. "
        "The result should be reviewed together with the individual "
        "forensic indicators rather than treated as conclusive proof."
    )


def narrate_report(results):
    prompt = f"""
You are a forensic document analysis assistant.

Summarize the following machine-generated findings in plain English.

Rules:
- Do not invent facts.
- Do not say fraud is proven.
- Distinguish indicators from conclusions.
- Mention important uncertainty.
- Keep the report under 250 words.

Findings:

{json.dumps(results, indent=2, default=str)}
"""

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=5,
        )

        response.raise_for_status()

        data = response.json()

        text = data.get("response", "").strip()

        if text:
            return {
                "available": True,
                "model": OLLAMA_MODEL,
                "text": text,
                "local": True,
            }

    except Exception as exc:
        return {
            "available": False,
            "model": OLLAMA_MODEL,
            "text": _fallback_report(results),
            "local": True,
            "error": str(exc),
        }

    return {
        "available": False,
        "model": OLLAMA_MODEL,
        "text": _fallback_report(results),
        "local": True,
    }