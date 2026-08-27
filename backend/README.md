# AEGIS zero-knowledge vault service

This FastAPI service provides the **account authentication and encrypted vault
storage layers**. It verifies
an Argon2id-hashed account password and a Google Authenticator-compatible TOTP
before issuing a short-lived, HttpOnly, SameSite=Strict browser session.

It stores wrapped vault profiles and AES-GCM credential blobs for synchronized
web access. It does not receive the vault master password, vault recovery key,
plaintext credentials, or any vault encryption key. Passing one of those fields
to an authentication endpoint is rejected by strict request validation.

Account MFA permits reading encrypted records. Mutating the vault additionally
requires `X-Aegis-Vault-Authorization`, a random secret that is encrypted inside
the vault profile and available only after local vault unlock. The database
stores only a keyed hash of that secret. An account-only attacker can therefore
download ciphertext but cannot silently replace or delete it.

## Local setup

Python 3.11 or newer is required.

```powershell
python -m pip install -r backend/requirements-dev.txt
$env:AEGIS_JWT_SECRET = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:AEGIS_MFA_ENCRYPTION_KEY = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:AEGIS_COOKIE_SECURE = "false"
npm run dev:backend
```

In a second terminal:

```powershell
npm run dev:web
```

Open `http://localhost:5173`, create an account, scan the QR code with Google
Authenticator, confirm the current six-digit code, save the one-time MFA
recovery codes, and then create a separate vault master password.

Production must use HTTPS, leave `AEGIS_COOKIE_SECURE=true`, store both server
keys in a secret manager, and use independent random values in every
environment. Never copy development keys into production.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `AEGIS_JWT_SECRET` | 32-byte URL-safe base64 key used to sign short-lived session/challenge tokens |
| `AEGIS_MFA_ENCRYPTION_KEY` | Independent 32-byte URL-safe base64 key used for TOTP-seed encryption and keyed MFA/vault-write digests |
| `AEGIS_DATABASE_URL` | SQLAlchemy URL; defaults to `sqlite:///./aegis.db` |
| `AEGIS_COOKIE_SECURE` | Must be `true` in production; set `false` only for local HTTP development |
| `AEGIS_ALLOWED_ORIGINS` | Comma-separated exact CORS origins; wildcards are intentionally unsupported |
| `AEGIS_SESSION_MINUTES` | Browser session lifetime; defaults to 15 minutes |

## Authentication endpoints

- `POST /api/auth/register` — creates a pending account and returns the TOTP enrollment QR payload once.
- `POST /api/auth/enroll/confirm` — confirms a fresh TOTP and returns eight one-time MFA recovery codes once.
- `POST /api/auth/login` — verifies the account password and issues a five-minute, single-use MFA challenge.
- `POST /api/auth/totp` — consumes the challenge and a fresh, not-previously-used TOTP.
- `POST /api/auth/recovery` — consumes the challenge and one MFA recovery code.
- `GET /api/auth/me` — returns non-sensitive account identity for a valid session.
- `POST /api/auth/logout` — clears the browser session.
- `GET /api/health` — health check.

## Encrypted vault endpoints

- `GET /api/vault` — returns the current user's wrapped profile, ciphertext records, revisions, and deletion tombstones.
- `PUT /api/vault/profile` — creates or rotates the wrapped profile using optimistic revision checks.
- `PUT /api/vault/items/{item_id}` — creates or updates one AES-GCM credential record.
- `DELETE /api/vault/items/{item_id}?expectedRevision=N` — creates a versioned deletion tombstone.

All vault writes require the unlock-derived authorization header. The header is
sent only over HTTPS, is never written to browser storage, cannot decrypt any
credential, and is dropped from memory when the vault locks. Stale revisions
receive HTTP `409` instead of overwriting newer data.

TOTP attempts are throttled and codes are accepted only once. The limiter in
this phase is process-local; a multi-worker production deployment must replace
it with a shared Redis-backed limiter.

## Tests

```powershell
npm run test:backend
```

The 11 backend tests cover encrypted TOTP seed storage, Argon2id password hashing, enrollment,
password-plus-TOTP login, TOTP replay rejection, single-use recovery codes,
strict payload validation, secure sessions, logout, encrypted profile/item
round trips, ownership isolation, write authorization, version conflicts, and
deletion tombstones.
