# AEGIS backend implementation reference

The backend described by the original build prompt is now implemented under
`backend/`, and the web client is connected through
`frontend/src/lib/vault-api.js`. Use this file as the safety checklist for
future backend work.

## Security invariants

1. Account authentication and vault decryption remain independent.
2. The server never receives a vault master password, recovery key, vault data
   key, or stored password plaintext.
3. Stored password blobs are AES-256-GCM v2 with a 96-bit IV and authentication
   tag; the client binds them to user/item context.
4. A valid account MFA session permits ciphertext download only.
5. Profile/item mutations additionally require the random vault-write secret
   decrypted during local vault unlock. Store only its keyed digest.
6. Every update supplies an expected revision; reject stale writes with `409`.
7. Retain deletion tombstones so stale clients cannot resurrect records.
8. Reject unknown request fields. Never log tokens, ciphertext, authorization
   headers, recovery codes, or plaintext-bearing client variables.

## Implemented routes

```text
POST /api/auth/register
POST /api/auth/enroll/confirm
POST /api/auth/login
POST /api/auth/totp
POST /api/auth/recovery
GET  /api/auth/me
POST /api/auth/logout

GET    /api/vault
PUT    /api/vault/profile
PUT    /api/vault/items/{item_id}
DELETE /api/vault/items/{item_id}?expectedRevision=N
```

See `BACKEND_CONTRACT.md` for request semantics and `backend/README.md` for
local setup. Run:

```powershell
npm run test:backend
npm test
npm run build:web
```

## Remaining backend-adjacent work

- Replace the process-local login limiter with a shared Redis-backed limiter
  before running multiple workers.
- Design a short-lived device authorization exchange for the Chrome extension
  and desktop assistant; never persist device tokens beside vault keys.
- Add remote storage adapters to extension/desktop and test actual
  extension↔web↔desktop synchronization.
- Add database migrations, PostgreSQL, encrypted backups, retention policy,
  observability with secret redaction, and disaster-recovery exercises before
  production deployment.
- Prefer passkeys/WebAuthn over relayable TOTP when product scope allows.
