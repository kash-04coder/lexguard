

import hashlib
import hmac
import os
import secrets

KEY_FILE = "secret.key"
NONCE_SIZE = 16
BLOCK_SIZE = 32  # size of one SHA-256 HMAC output


def generate_key():
    if not os.path.exists(KEY_FILE):
        key = secrets.token_bytes(32)
        with open(KEY_FILE, "wb") as f:
            f.write(key)


def load_key():
    with open(KEY_FILE, "rb") as f:
        return f.read()


def _derive_subkey(master_key, label):
    """Domain-separate the encryption key from the MAC key."""
    return hmac.new(master_key, label, hashlib.sha256).digest()


def _keystream(key, nonce, length):
    """Generate `length` bytes of keystream via HMAC-SHA256 in counter mode."""
    output = bytearray()
    counter = 0
    while len(output) < length:
        block = hmac.new(
            key,
            nonce + counter.to_bytes(8, "big"),
            hashlib.sha256
        ).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:length])


def _xor(data, keystream):
    return bytes(a ^ b for a, b in zip(data, keystream))


generate_key()
_MASTER_KEY = load_key()
_ENC_KEY = _derive_subkey(_MASTER_KEY, b"forensivault-encryption")
_MAC_KEY = _derive_subkey(_MASTER_KEY, b"forensivault-authentication")


def encrypt_file(filepath):
    with open(filepath, "rb") as f:
        data = f.read()

    nonce = secrets.token_bytes(NONCE_SIZE)
    keystream = _keystream(_ENC_KEY, nonce, len(data))
    ciphertext = _xor(data, keystream)
    tag = hmac.new(_MAC_KEY, nonce + ciphertext, hashlib.sha256).digest()

    encrypted_path = filepath + ".enc"
    with open(encrypted_path, "wb") as f:
        f.write(nonce + tag + ciphertext)

    return encrypted_path


def decrypt_file(filepath):
    with open(filepath, "rb") as f:
        blob = f.read()

    nonce = blob[:NONCE_SIZE]
    tag = blob[NONCE_SIZE:NONCE_SIZE + BLOCK_SIZE]
    ciphertext = blob[NONCE_SIZE + BLOCK_SIZE:]

    expected_tag = hmac.new(_MAC_KEY, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError(
            "Evidence file failed integrity verification during decryption "
            "-- the encrypted file may be corrupted or tampered with."
        )

    keystream = _keystream(_ENC_KEY, nonce, len(ciphertext))
    return _xor(ciphertext, keystream)