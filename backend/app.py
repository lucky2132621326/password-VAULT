from __future__ import annotations

import json
import re
import secrets
from datetime import datetime, timedelta, timezone

import jwt
import pyotp
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from .config import Settings
from .models import AuthChallenge, User, VaultItemRecord, VaultProfileRecord, utcnow
from .rate_limit import RateLimiter
from .schemas import (
    ChallengeCodeRequest,
    LoginRequest,
    RecoveryCodeRequest,
    RegisterRequest,
    VaultItemPutRequest,
    VaultProfilePutRequest,
    public_user,
)
from .security import (
    consume_recovery_code,
    decode_token,
    decrypt_totp_secret,
    encode_recovery_hashes,
    encrypt_totp_secret,
    hash_password,
    make_recovery_codes,
    make_token,
    matching_totp_step,
    provisioning_uri,
    valid_vault_sync_secret,
    verify_password,
    vault_sync_digest,
    verify_vault_sync_secret,
)


COOKIE_NAME = "aegis_session"


def create_app(settings: Settings) -> FastAPI:
    connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
    engine_kwargs = {"connect_args": connect_args}
    if settings.database_url in {"sqlite://", "sqlite:///:memory:"}:
        engine_kwargs["poolclass"] = StaticPool
    engine = create_engine(settings.database_url, **engine_kwargs)
    SQLModel.metadata.create_all(engine)

    app = FastAPI(title="AEGIS Zero-Knowledge Vault API", version="0.3.0")
    app.state.settings = settings
    app.state.engine = engine
    app.state.rate_limiter = RateLimiter()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Content-Type", "X-Aegis-Vault-Authorization"],
    )

    def get_session():
        with Session(engine) as session:
            yield session

    def remote_key(request: Request, scope: str, identity: str) -> str:
        ip = request.client.host if request.client else "unknown"
        return f"{scope}:{identity.lower()}:{ip}"

    def require_rate(request: Request, scope: str, identity: str, limit: int = 5) -> str:
        key = remote_key(request, scope, identity)
        if not app.state.rate_limiter.allow(key, limit, 60):
            raise HTTPException(status_code=429, detail="Too many attempts; try again later")
        return key

    def create_challenge(session: Session, user: User, purpose: str) -> str:
        challenge_id = secrets.token_urlsafe(18)
        expires = datetime.now(timezone.utc) + timedelta(minutes=settings.challenge_minutes)
        session.add(AuthChallenge(id=challenge_id, user_id=user.id, purpose=purpose, expires_at=expires))
        session.commit()
        return make_token(
            settings, subject=user.id, purpose=purpose,
            minutes=settings.challenge_minutes, jti=challenge_id,
        )

    def use_challenge(session: Session, token: str, purpose: str) -> tuple[User, AuthChallenge]:
        try:
            payload = decode_token(settings, token, purpose)
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=401, detail="Invalid or expired challenge") from exc
        challenge = session.get(AuthChallenge, payload.get("jti"))
        user = session.get(User, payload.get("sub"))
        now = datetime.now(timezone.utc)
        if not challenge or not user or challenge.user_id != user.id or challenge.purpose != purpose:
            raise HTTPException(status_code=401, detail="Invalid or expired challenge")
        expires_at = challenge.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if challenge.used_at is not None or expires_at <= now:
            raise HTTPException(status_code=401, detail="Invalid or expired challenge")
        return user, challenge

    def set_session(response: Response, user: User) -> None:
        token = make_token(settings, subject=user.id, purpose="session", minutes=settings.session_minutes)
        response.set_cookie(
            COOKIE_NAME, token, max_age=settings.session_minutes * 60,
            httponly=True, secure=settings.cookie_secure, samesite="strict", path="/",
        )

    def current_user(
        session: Session = Depends(get_session),
        token: str | None = Cookie(default=None, alias=COOKIE_NAME),
    ) -> User:
        if not token:
            raise HTTPException(status_code=401, detail="Authentication required")
        try:
            payload = decode_token(settings, token, "session")
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=401, detail="Authentication required") from exc
        user = session.get(User, payload.get("sub"))
        if not user or user.status != "active" or not user.totp_confirmed:
            raise HTTPException(status_code=401, detail="Authentication required")
        return user

    @app.get("/api/health")
    def health():
        return {"ok": True}

    @app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
    def register(body: RegisterRequest, request: Request, session: Session = Depends(get_session)):
        require_rate(request, "register", body.username, limit=3)
        if session.exec(select(User).where(User.username == body.username)).first():
            raise HTTPException(status_code=409, detail="Account already exists")
        secret = pyotp.random_base32(length=32)
        user = User(
            id=secrets.token_urlsafe(12), username=body.username, name=body.name,
            account_password_hash=hash_password(body.accountPassword),
            totp_secret_encrypted=encrypt_totp_secret(secret, settings.mfa_encryption_key),
        )
        session.add(user)
        session.commit()
        challenge_token = create_challenge(session, user, "enroll")
        return {
            "ok": True,
            "challengeToken": challenge_token,
            "totp": {
                "secret": secret,
                "uri": provisioning_uri(secret, user.username, settings.totp_issuer),
                "period": 30,
                "digits": 6,
            },
        }

    @app.post("/api/auth/enroll/confirm")
    def confirm_enrollment(
        body: ChallengeCodeRequest, request: Request, response: Response,
        session: Session = Depends(get_session),
    ):
        user, challenge = use_challenge(session, body.challengeToken, "enroll")
        require_rate(request, "enroll", user.username)
        secret = decrypt_totp_secret(user.totp_secret_encrypted, settings.mfa_encryption_key)
        step = matching_totp_step(secret, body.code)
        if step is None:
            raise HTTPException(status_code=401, detail="Invalid authenticator code")
        codes = make_recovery_codes()
        user.totp_confirmed = True
        user.status = "active"
        user.last_totp_step = step
        user.recovery_code_hashes = encode_recovery_hashes(codes, settings.mfa_encryption_key)
        user.last_seen = utcnow()
        challenge.used_at = utcnow()
        session.add(user)
        session.add(challenge)
        session.commit()
        set_session(response, user)
        return {"ok": True, "user": public_user(user), "recoveryCodes": codes}

    @app.post("/api/auth/login")
    def login(body: LoginRequest, request: Request, session: Session = Depends(get_session)):
        username = body.username.strip().lower()
        rate_key = require_rate(request, "login", username)
        user = session.exec(select(User).where(User.username == username)).first()
        if not user or not verify_password(user.account_password_hash, body.accountPassword):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if user.status != "active" or not user.totp_confirmed:
            raise HTTPException(status_code=403, detail="Account is not active")
        app.state.rate_limiter.clear(rate_key)
        return {"ok": True, "challengeToken": create_challenge(session, user, "login"), "mfaRequired": True}

    @app.post("/api/auth/totp")
    def verify_totp(
        body: ChallengeCodeRequest, request: Request, response: Response,
        session: Session = Depends(get_session),
    ):
        user, challenge = use_challenge(session, body.challengeToken, "login")
        require_rate(request, "totp", user.username)
        secret = decrypt_totp_secret(user.totp_secret_encrypted, settings.mfa_encryption_key)
        step = matching_totp_step(secret, body.code)
        if step is None or (user.last_totp_step is not None and step <= user.last_totp_step):
            raise HTTPException(status_code=401, detail="Invalid or already-used authenticator code")
        user.last_totp_step = step
        user.last_seen = utcnow()
        challenge.used_at = utcnow()
        session.add(user)
        session.add(challenge)
        session.commit()
        set_session(response, user)
        return {"ok": True, "user": public_user(user)}

    @app.post("/api/auth/recovery")
    def verify_recovery(
        body: RecoveryCodeRequest, request: Request, response: Response,
        session: Session = Depends(get_session),
    ):
        user, challenge = use_challenge(session, body.challengeToken, "login")
        require_rate(request, "recovery", user.username, limit=5)
        ok, remaining = consume_recovery_code(
            user.recovery_code_hashes, body.recoveryCode, settings.mfa_encryption_key
        )
        if not ok:
            raise HTTPException(status_code=401, detail="Invalid recovery code")
        user.recovery_code_hashes = remaining
        user.last_seen = utcnow()
        challenge.used_at = utcnow()
        session.add(user)
        session.add(challenge)
        session.commit()
        set_session(response, user)
        return {"ok": True, "user": public_user(user), "recoveryCodeConsumed": True}

    @app.get("/api/auth/me")
    def me(user: User = Depends(current_user)):
        return {"ok": True, "user": public_user(user)}

    @app.post("/api/auth/logout")
    def logout(response: Response):
        response.delete_cookie(COOKIE_NAME, path="/", secure=settings.cookie_secure, samesite="strict")
        return {"ok": True}

    def profile_response(record: VaultProfileRecord | None):
        if record is None:
            return None
        return {
            "revision": record.revision,
            "profile": json.loads(record.profile_json),
            "updatedAt": record.updated_at,
        }

    def item_response(record: VaultItemRecord):
        def _is_encrypted_blob(obj: any) -> bool:
            try:
                return isinstance(obj, dict) and int(obj.get('v', 0)) >= 2 and isinstance(obj.get('alg'), str) and isinstance(obj.get('iv'), str) and isinstance(obj.get('ct'), str)
            except Exception:
                return False

        payload = None
        if not record.deleted:
            try:
                payload = json.loads(record.payload_json)
            except Exception:
                payload = None
            # Defensive: if a payload contains a non-encrypted password (eg. plain string), redact it
            if payload and not _is_encrypted_blob(payload.get('password')):
                payload = { **payload }
                payload['password'] = { 'v': 2, 'alg': 'AES-256-GCM', 'iv': '', 'ct': '' }
                payload['_plaintextDetected'] = True

        return {
            "id": record.item_id,
            "revision": record.revision,
            "deleted": record.deleted,
            "item": None if record.deleted else payload,
            "updatedAt": record.updated_at,
        }

    def require_vault_write(
        profile: VaultProfileRecord | None,
        authorization: str | None,
    ) -> None:
        if not profile or not authorization or not verify_vault_sync_secret(
            authorization, profile.sync_secret_hash, settings.mfa_encryption_key
        ):
            raise HTTPException(status_code=403, detail="Vault unlock authorization required")

    @app.get("/api/vault")
    def get_vault(
        user: User = Depends(current_user),
        session: Session = Depends(get_session),
    ):
        profile = session.get(VaultProfileRecord, user.id)
        items = session.exec(
            select(VaultItemRecord)
            .where(VaultItemRecord.user_id == user.id)
            .order_by(VaultItemRecord.updated_at)
        ).all()
        return {
            "ok": True,
            "profile": profile_response(profile),
            "items": [item_response(item) for item in items],
        }

    @app.put("/api/vault/profile")
    def put_vault_profile(
        body: VaultProfilePutRequest,
        vault_authorization: str | None = Header(default=None, alias="X-Aegis-Vault-Authorization"),
        user: User = Depends(current_user),
        session: Session = Depends(get_session),
    ):
        record = session.get(VaultProfileRecord, user.id)
        current_revision = record.revision if record else 0
        if body.expectedRevision != current_revision:
            raise HTTPException(
                status_code=409,
                detail=f"Vault profile version conflict; current revision is {current_revision}",
            )
        encoded = json.dumps(body.profile.model_dump(mode="json"), separators=(",", ":"))
        if record is None:
            if not vault_authorization or not valid_vault_sync_secret(vault_authorization):
                raise HTTPException(status_code=403, detail="Vault unlock authorization required")
            record = VaultProfileRecord(
                user_id=user.id,
                profile_json=encoded,
                sync_secret_hash=vault_sync_digest(vault_authorization, settings.mfa_encryption_key),
            )
        else:
            require_vault_write(record, vault_authorization)
            record.profile_json = encoded
            record.revision += 1
            record.updated_at = utcnow()
        session.add(record)
        session.commit()
        session.refresh(record)
        return {"ok": True, **profile_response(record)}

    @app.put("/api/vault/items/{item_id}")
    def put_vault_item(
        item_id: str,
        body: VaultItemPutRequest,
        vault_authorization: str | None = Header(default=None, alias="X-Aegis-Vault-Authorization"),
        user: User = Depends(current_user),
        session: Session = Depends(get_session),
    ):
        if not re.fullmatch(r"[A-Za-z0-9_-]{6,128}", item_id):
            raise HTTPException(status_code=422, detail="Invalid item id")
        require_vault_write(session.get(VaultProfileRecord, user.id), vault_authorization)
        record = session.get(VaultItemRecord, (user.id, item_id))
        current_revision = record.revision if record else 0
        if body.expectedRevision != current_revision:
            raise HTTPException(
                status_code=409,
                detail=f"Vault item version conflict; current revision is {current_revision}",
            )
        # Extra defensive validation: ensure the incoming item contains a ciphertext blob
        item_dict = body.item.model_dump(mode="json")
        pw = item_dict.get('password')
        if not (isinstance(pw, dict) and all(k in pw for k in ('v', 'alg', 'iv', 'ct'))):
            raise HTTPException(status_code=422, detail="Vault items must contain ciphertext-only password blobs")
        encoded = json.dumps(item_dict, separators=(",", ":"))
        if record is None:
            record = VaultItemRecord(user_id=user.id, item_id=item_id, payload_json=encoded)
        else:
            record.payload_json = encoded
            record.deleted = False
            record.revision += 1
            record.updated_at = utcnow()
        session.add(record)
        session.commit()
        session.refresh(record)
        return {"ok": True, **item_response(record)}

    @app.delete("/api/vault/items/{item_id}")
    def delete_vault_item(
        item_id: str,
        expectedRevision: int,
        vault_authorization: str | None = Header(default=None, alias="X-Aegis-Vault-Authorization"),
        user: User = Depends(current_user),
        session: Session = Depends(get_session),
    ):
        require_vault_write(session.get(VaultProfileRecord, user.id), vault_authorization)
        record = session.get(VaultItemRecord, (user.id, item_id))
        if record is None:
            raise HTTPException(status_code=404, detail="Vault item not found")
        if expectedRevision != record.revision:
            raise HTTPException(
                status_code=409,
                detail=f"Vault item version conflict; current revision is {record.revision}",
            )
        record.payload_json = "{}"
        record.deleted = True
        record.revision += 1
        record.updated_at = utcnow()
        session.add(record)
        session.commit()
        session.refresh(record)
        return {"ok": True, **item_response(record)}

    return app
