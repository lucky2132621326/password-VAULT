from __future__ import annotations

import base64
import os
from dataclasses import dataclass


def _decode_key(value: str, name: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:  # pragma: no cover - defensive startup validation
        raise RuntimeError(f"{name} must be URL-safe base64") from exc
    if len(raw) != 32:
        raise RuntimeError(f"{name} must decode to exactly 32 bytes")
    return raw


@dataclass(frozen=True)
class Settings:
    database_url: str
    jwt_secret: bytes
    mfa_encryption_key: bytes
    cookie_secure: bool = True
    session_minutes: int = 15
    challenge_minutes: int = 5
    totp_issuer: str = "AEGIS Password Vault"
    allowed_origins: tuple[str, ...] = ("http://localhost:5173", "http://127.0.0.1:5173")

    @classmethod
    def from_env(cls) -> "Settings":
        jwt = os.environ.get("AEGIS_JWT_SECRET", "")
        mfa = os.environ.get("AEGIS_MFA_ENCRYPTION_KEY", "")
        # In production both values must be supplied. For local demos you may
        # set AEGIS_ALLOW_DEV_KEYS=true to auto-generate ephemeral keys so the
        # server starts without manual env setup. NEVER enable this in prod.
        allow_dev = os.environ.get("AEGIS_ALLOW_DEV_KEYS", "false").lower() in ("1", "true", "yes")
        if not jwt or not mfa:
            if not allow_dev:
                raise RuntimeError(
                    "AEGIS_JWT_SECRET and AEGIS_MFA_ENCRYPTION_KEY are required; "
                    "generate independent 32-byte URL-safe base64 values"
                )
            # Auto-generate URL-safe base64 values that decode to 32 bytes.
            import secrets, base64
            if not jwt:
                jwt = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('ascii').rstrip('=')
                print("[WARN] AEGIS_JWT_SECRET not set — using ephemeral dev key (AEGIS_ALLOW_DEV_KEYS=true)")
            if not mfa:
                mfa = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('ascii').rstrip('=')
                print("[WARN] AEGIS_MFA_ENCRYPTION_KEY not set — using ephemeral dev key (AEGIS_ALLOW_DEV_KEYS=true)")
        origins = tuple(
            x.strip() for x in os.environ.get(
                "AEGIS_ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
            ).split(",") if x.strip()
        )
        return cls(
            database_url=os.environ.get("AEGIS_DATABASE_URL", "sqlite:///./aegis.db"),
            jwt_secret=_decode_key(jwt, "AEGIS_JWT_SECRET"),
            mfa_encryption_key=_decode_key(mfa, "AEGIS_MFA_ENCRYPTION_KEY"),
            cookie_secure=os.environ.get("AEGIS_COOKIE_SECURE", "true").lower() != "false",
            session_minutes=int(os.environ.get("AEGIS_SESSION_MINUTES", "15")),
            challenge_minutes=int(os.environ.get("AEGIS_CHALLENGE_MINUTES", "5")),
            allowed_origins=origins,
        )
