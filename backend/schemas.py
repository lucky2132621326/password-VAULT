from __future__ import annotations

import base64
import binascii
import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,79}$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RegisterRequest(StrictModel):
    username: str
    name: str = Field(min_length=1, max_length=120)
    accountPassword: str = Field(min_length=12, max_length=256)

    @field_validator("username")
    @classmethod
    def valid_username(cls, value: str) -> str:
        value = value.lower()
        if not USERNAME_RE.fullmatch(value):
            raise ValueError("use 3-80 lowercase letters, numbers, dots, underscores, or hyphens")
        return value


class LoginRequest(StrictModel):
    username: str = Field(min_length=1, max_length=80)
    accountPassword: str = Field(min_length=1, max_length=256)


class ChallengeCodeRequest(StrictModel):
    challengeToken: str = Field(min_length=20, max_length=4096)
    code: str = Field(pattern=r"^\d{6}$")


class RecoveryCodeRequest(StrictModel):
    challengeToken: str = Field(min_length=20, max_length=4096)
    recoveryCode: str = Field(min_length=12, max_length=64)


class PublicUser(BaseModel):
    id: str
    username: str
    name: str
    role: str
    mfa: bool


def public_user(user) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "name": user.name,
        "role": user.role,
        "mfa": bool(user.totp_confirmed),
    }


class EncryptedBlob(StrictModel):
    v: int = Field(ge=2, le=2)
    alg: str = Field(pattern=r"^AES-256-GCM$")
    iv: str = Field(min_length=16, max_length=24)
    ct: str = Field(min_length=24, max_length=262_144)

    @field_validator("iv")
    @classmethod
    def valid_iv(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("must be canonical base64") from exc
        if len(raw) != 12:
            raise ValueError("AES-GCM IV must be 96 bits")
        return value

    @field_validator("ct")
    @classmethod
    def valid_ciphertext(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("must be canonical base64") from exc
        if len(raw) < 17:
            raise ValueError("ciphertext must include data and a GCM tag")
        return value


class VaultKdf(StrictModel):
    name: str = Field(pattern=r"^PBKDF2-HMAC-SHA256$")
    iterations: int = Field(ge=600_000, le=10_000_000)
    hash: str = Field(pattern=r"^SHA-256$")


class VaultProfileData(StrictModel):
    version: int = Field(ge=2, le=2)
    kdf: VaultKdf
    salt: str = Field(min_length=20, max_length=64)
    wrappedVaultKey: EncryptedBlob
    recoveryWrappedVaultKey: EncryptedBlob
    wrappedSyncSecret: EncryptedBlob

    @field_validator("salt")
    @classmethod
    def valid_salt(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("must be canonical base64") from exc
        if len(raw) < 16:
            raise ValueError("salt must be at least 128 bits")
        return value


class VaultProfilePutRequest(StrictModel):
    profile: VaultProfileData
    expectedRevision: int = Field(ge=0)


class VaultItemData(StrictModel):
    app: str = Field(min_length=1, max_length=200)
    username: str = Field(default="", max_length=500)
    url: str = Field(default="", max_length=2048)
    category: str = Field(default="Other", min_length=1, max_length=80)
    password: EncryptedBlob
    strength: str = Field(pattern=r"^(critical|weak|fair|strong|elite)$")
    entropy: int = Field(ge=0, le=10_000)
    createdAt: datetime
    updatedAt: datetime
    favorite: bool = False
    locked: bool = False
    compromisedAt: datetime | None = None
    compromiseReason: str | None = Field(default=None, max_length=80)
    breachNotifiedAt: datetime | None = None


class VaultItemPutRequest(StrictModel):
    item: VaultItemData
    expectedRevision: int = Field(ge=0)
