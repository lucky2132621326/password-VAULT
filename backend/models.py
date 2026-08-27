from __future__ import annotations

from datetime import datetime, timezone

from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(SQLModel, table=True):
    id: str = Field(primary_key=True)
    username: str = Field(unique=True, index=True, max_length=80)
    name: str = Field(max_length=120)
    account_password_hash: str
    role: str = Field(default="user", max_length=16)
    status: str = Field(default="pending_mfa", max_length=24)
    totp_secret_encrypted: str
    totp_confirmed: bool = False
    last_totp_step: int | None = None
    recovery_code_hashes: str = "[]"
    created_at: datetime = Field(default_factory=utcnow)
    last_seen: datetime | None = None


class AuthChallenge(SQLModel, table=True):
    id: str = Field(primary_key=True)
    user_id: str = Field(foreign_key="user.id", index=True)
    purpose: str = Field(max_length=24)
    expires_at: datetime
    used_at: datetime | None = None


class VaultProfileRecord(SQLModel, table=True):
    """Password-wrapped vault key material. No recovery key or plaintext key."""

    user_id: str = Field(primary_key=True, foreign_key="user.id")
    profile_json: str
    sync_secret_hash: str
    revision: int = 1
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class VaultItemRecord(SQLModel, table=True):
    """One client-encrypted credential plus a retained deletion tombstone."""

    user_id: str = Field(primary_key=True, foreign_key="user.id")
    item_id: str = Field(primary_key=True, max_length=128)
    payload_json: str = "{}"
    revision: int = 1
    deleted: bool = False
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
