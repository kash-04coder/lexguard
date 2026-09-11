import os
import hmac
import hashlib

REPORT_KEY_FILE = "report_signing.key"
KEY_SIZE = 32

def generate_report_signing_key():
    """
    Generate a random 256-bit HMAC signing key.
    """
    if not os.path.exists(REPORT_KEY_FILE):
        key = os.urandom(KEY_SIZE)
        with open(
            REPORT_KEY_FILE,
            "wb"
        ) as f:
            f.write(key)


def load_report_signing_key():
    """
    Load the HMAC signing key.
    """
    generate_report_signing_key()
    with open(
        REPORT_KEY_FILE,
        "rb"
    ) as f:
        return f.read()


def sign_case_summary(case_summary):
    """
    Generate HMAC-SHA256 for a canonical case summary.
    """
    key = load_report_signing_key()
    signature = hmac.new(
        key,
        case_summary.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return signature


def verify_case_summary(
    case_summary,
    stored_signature
):
    """
    Verify the HMAC signature of a case summary.
    """
    if not stored_signature:
        return False
    key = load_report_signing_key()
    expected_signature = hmac.new(
        key,
        case_summary.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(
        expected_signature,
        stored_signature
    )