import sqlite3
import hashlib
import hmac
import secrets
from datetime import datetime

DB = "forensic.db"

PBKDF2_ITERATIONS = 600_000

SALT_SIZE = 32
KEY_LENGTH = 32


def derive_master_key(password, salt, iterations=PBKDF2_ITERATIONS):
    """
    Derive a cryptographic value from the master password.

    The plaintext password is never stored.
    """

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=KEY_LENGTH
    )


def vault_is_configured():
    """
    Returns True if a master password has already been configured.
    """

    conn = sqlite3.connect(DB)

    result = conn.execute("""
        SELECT id
        FROM vault_security
        WHERE id=1
    """).fetchone()

    conn.close()

    return result is not None


def setup_master_password(password):
    """
    Create the vault master password verifier.
    Only the salt and PBKDF2-derived value are stored.
    """

    if not password:
        return False, "Master password cannot be empty."

    if len(password) < 8:
        return False, "Master password must contain at least 8 characters."

    if vault_is_configured():
        return False, "A master password is already configured."

    salt = secrets.token_bytes(SALT_SIZE)

    derived_key = derive_master_key(
        password,
        salt,
        PBKDF2_ITERATIONS
    )

    conn = sqlite3.connect(DB)

    conn.execute("""
        INSERT INTO vault_security(
            id,
            salt,
            password_hash,
            iterations,
            created_at
        )
        VALUES(1, ?, ?, ?, ?)
    """, (
        salt,
        derived_key,
        PBKDF2_ITERATIONS,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()

    return True, "Master password configured successfully."


def verify_master_password(password):
    """
    Verify a supplied master password.

    hmac.compare_digest() is used for constant-time comparison.
    """

    if not password:
        return False

    conn = sqlite3.connect(DB)

    record = conn.execute("""
        SELECT salt, password_hash, iterations
        FROM vault_security
        WHERE id=1
    """).fetchone()

    conn.close()

    if not record:
        return False

    salt, stored_hash, iterations = record

    derived_key = derive_master_key(
        password,
        salt,
        iterations
    )

    return hmac.compare_digest(
        derived_key,
        stored_hash
    )


def delete_master_password():
    """
    Remove the vault master-password verifier.

    This is intentionally provided as a controlled administrative
    operation rather than being exposed directly in the normal UI.
    """

    conn = sqlite3.connect(DB)

    conn.execute("""
        DELETE FROM vault_security
        WHERE id=1
    """)

    conn.commit()
    conn.close()