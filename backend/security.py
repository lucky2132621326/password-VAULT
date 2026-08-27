from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import time
from datetime import datetime, timedelta, timezone

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import Settings


PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def encrypt_totp_secret(secret: str, key: bytes) -> str:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, secret.encode("ascii"), b"aegis:totp-secret:v1")
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii").rstrip("=")


def decrypt_totp_secret(value: str, key: bytes) -> str:
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) < 29:
        raise ValueError("invalid encrypted TOTP secret")
    plaintext = AESGCM(key).decrypt(raw[:12], raw[12:], b"aegis:totp-secret:v1")
    return plaintext.decode("ascii")


def make_token(settings: Settings, *, subject: str, purpose: str, minutes: int, jti: str | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "purpose": purpose,
        "iat": now,
        "exp": now + timedelta(minutes=minutes),
        "jti": jti or secrets.token_urlsafe(18),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_token(settings: Settings, token: str, purpose: str) -> dict:
    payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    if payload.get("purpose") != purpose:
        raise jwt.InvalidTokenError("wrong token purpose")
    return payload


def matching_totp_step(secret: str, code: str, now: float | None = None) -> int | None:
    now = time.time() if now is None else now
    totp = pyotp.TOTP(secret, digits=6, interval=30, digest=hashlib.sha1)
    current = int(now // totp.interval)
    for offset in (-2, -1, 0, 1, 2):
        step = current + offset
        if hmac.compare_digest(totp.at(step * totp.interval), code):
            return step
    return None


def make_recovery_codes(count: int = 8) -> list[str]:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(alphabet) for _ in range(20))
        codes.append("-".join(raw[i:i + 5] for i in range(0, 20, 5)))
    return codes


def normalize_recovery_code(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch.isalnum())


def recovery_digest(code: str, key: bytes) -> str:
    return hmac.new(key, normalize_recovery_code(code).encode("ascii"), hashlib.sha256).hexdigest()


def vault_sync_digest(secret: str, key: bytes) -> str:
    message = b"aegis:vault-sync-authorization:v1\x00" + secret.encode("ascii")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def valid_vault_sync_secret(secret: str) -> bool:
    if not re.fullmatch(r"AEGIS-SYNC-[A-Za-z0-9_-]{43}", secret):
        return False
    try:
        raw = base64.urlsafe_b64decode(secret[11:] + "=")
    except (ValueError, binascii.Error):
        return False
    return len(raw) == 32


def verify_vault_sync_secret(secret: str, stored_hash: str, key: bytes) -> bool:
    return valid_vault_sync_secret(secret) and hmac.compare_digest(
        vault_sync_digest(secret, key), stored_hash
    )


def encode_recovery_hashes(codes: list[str], key: bytes) -> str:
    return json.dumps([recovery_digest(code, key) for code in codes])


def consume_recovery_code(stored: str, candidate: str, key: bytes) -> tuple[bool, str]:
    try:
        hashes = json.loads(stored)
    except (TypeError, json.JSONDecodeError):
        hashes = []
    candidate_hash = recovery_digest(candidate, key)
    for index, value in enumerate(hashes):
        if hmac.compare_digest(value, candidate_hash):
            del hashes[index]
            return True, json.dumps(hashes)
    return False, stored


def provisioning_uri(secret: str, username: str, issuer: str) -> str:
    return pyotp.TOTP(secret, interval=30, digits=6).provisioning_uri(name=username, issuer_name=issuer)
