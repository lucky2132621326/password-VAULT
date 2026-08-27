# AEGIS backend contract (implemented)

The FastAPI service under `backend/` implements account MFA and zero-knowledge
vault storage. The web client is connected through `frontend/src/lib/vault-api.js`.

## Non-negotiable boundary

The server never receives a vault master password, vault recovery key, vault
data key, or stored password plaintext. Stored passwords cross the API only as
validated AES-256-GCM blobs:

```json
{ "v": 2, "alg": "AES-256-GCM", "iv": "<96-bit base64 IV>", "ct": "<base64 ciphertext+tag>" }
```

Application name, username, URL, category, strength, and timestamps are
access-controlled metadata, not encrypted in the current schema. See
`docs/THREAT_MODEL.md` for the accepted metadata-leakage tradeoff.

## Authentication

```text
POST /api/auth/register
POST /api/auth/enroll/confirm
POST /api/auth/login
POST /api/auth/totp
POST /api/auth/recovery
GET  /api/auth/me
POST /api/auth/logout
```

Account passwords are Argon2id-hashed. Google Authenticator-compatible TOTP
seeds are AES-GCM-encrypted under a server environment key. Challenges,
authenticator steps, and recovery codes are single-use. Successful MFA creates
a short-lived HttpOnly, SameSite=Strict cookie.

## Vault synchronization

```text
GET    /api/vault
PUT    /api/vault/profile
PUT    /api/vault/items/{item_id}
DELETE /api/vault/items/{item_id}?expectedRevision=N
```

`GET /api/vault` requires the MFA session and returns the current user's wrapped
profile, live encrypted records, and deletion tombstones.

Every mutation also requires:

```text
X-Aegis-Vault-Authorization: AEGIS-SYNC-<256-bit base64url secret>
```

The client generates this secret, encrypts it inside the vault profile under
the random vault key, and holds it only in memory while unlocked. The backend
stores a keyed HMAC digest, never the plaintext secret. Consequently, stealing
only the account session permits ciphertext download but not vault mutation.

Profiles and items use monotonically increasing revisions. Clients send
`expectedRevision`; stale writes receive HTTP `409`. Deletes retain tombstones
so another client does not resurrect a removed credential.

## Current client coverage

- Web: connected to account MFA and encrypted synchronization.
- Chrome extension: local encrypted vault; remote device-token/MFA exchange remains.
- Desktop assistant: local encrypted vault; remote device-token/MFA exchange remains.

The extension and desktop already share the same crypto and item schema, so the
remaining work is authentication transport and a remote storage adapter—not a
new encryption format.
