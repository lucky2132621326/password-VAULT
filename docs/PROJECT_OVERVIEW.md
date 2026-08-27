# AEGIS — Full Project Description

**Team:** 2 people · **Event:** TCS TechDay
**Problem statement:** A password vault that analyses passwords, recommends strong ones, has admin + user modes, and stays strictly focused on security.

---

## 1. The core idea (this is the pitch)

Most password-manager demos store passwords in a database and encrypt them with one shared server-side key. If the admin account or the database leaks, every password leaks with it.

**AEGIS is zero-knowledge: the server — and therefore the admin — mathematically cannot read any user's password, even with full database access.**

One sentence for judges:

> *Account password plus Google Authenticator proves who the user is; a separate vault master password unwraps a random vault key locally, so taking over the account still does not decrypt the vault.*

This is implemented for real using the browser's native WebCrypto API — not a progress bar, not a mock.

### How it works, step by step

1. Alice authenticates her account with an **Argon2id-hashed account password** and a fresh six-digit **TOTP** from Google Authenticator.
2. The server accepts each 30-second TOTP value once, throttles attempts, and issues a short-lived HttpOnly, SameSite=Strict session cookie.
3. Account authentication authorizes access only to encrypted data. Alice must separately enter her **vault master password**, which never leaves the client.
4. The client stretches that password with **PBKDF2-HMAC-SHA256 at 600,000 iterations** and uses the result only to unwrap a random 256-bit vault data key.
5. Every password is encrypted with **AES-256-GCM**, a fresh random 96-bit IV, and authenticated context binding it to its user and item IDs.
6. A separately wrapped, user-held vault recovery key can rotate the master-password wrapper without giving the server or an administrator decryption power.
7. Vault mutations require a separate random authorization secret encrypted under the vault key, so an account-only attacker cannot replace or delete ciphertext.
8. On lock / idle timeout / app exit, all in-memory key references are dropped.

The account password is allowed to reach the authentication service over HTTPS. The **vault master password, vault recovery key, random vault key, and credential plaintext never do**.

---

## 2. What is built today

### A. Web application (`frontend/`) — React 19 + Vite + Tailwind v4

**User role**
- **Dashboard** — vault strength score, passwords stored, weak count, reused count, quick-access list with real brand logos, inline password generator, security recommendations, recent activity feed
- **My Vault** — search/filter by category, reveal/copy/edit/delete, reuse warnings, compromise-lock state
- **Generator** — random-string and Diceware-passphrase modes, live strength analysis, breach check
- **Security Health** — breach/reuse/weak/stale scan, vault score, prioritised action queue, WhatsApp alert setup, demo breach trigger
- **About** — architecture explainer + threat model

**Admin role** (requires an administrator account provisioned outside public registration)
- **Users** — provision/suspend, force rotation, inspect metadata (never plaintext)
- **Vault Registry** — the zero-knowledge proof screen: real ciphertext for every credential, plus an "Attempt decrypt" button that genuinely fails with `OperationError` because AES-GCM's authentication tag can't be verified without the owner's key
- **Policy** — org-wide password rules (min length, complexity, entropy floor, rotation interval, auto-lock, clipboard clear), enforced client-side *before* encryption
- **Audit Log** — timestamped record of logins, failed logins, reveals, copies, policy changes, suspensions; exportable

**Security features (all real)**
- CSPRNG password generation (`crypto.getRandomValues` + rejection sampling — never `Math.random`)
- Breach checking via HIBP's **k-anonymity** range API (only the first 5 chars of a SHA-1 hash leave the device), with an offline corpus fallback
- Entropy-based strength scoring with explainable penalties (dictionary words, leetspeak, keyboard walks, sequences, repeats, years) and crack-time estimates
- Self-clearing clipboard, idle auto-lock that drops the key from memory
- Google Authenticator-compatible enrollment, TOTP login, single-use MFA recovery codes, and a separate vault-unlock screen
- Random vault data key wrapped by the master password, plus a separately wrapped one-time-display vault recovery key
- Authenticated credential context prevents valid ciphertext from being moved to a different user or item record
- Item-level compromise lock: a breached credential locks (reveal/copy disabled) until rotated — the whole account is never deleted
- Automatic WhatsApp breach alerts (metadata only — app name + severity, **never** the password)

### B. Shared package (`packages/shared/`) — **complete, 41 tests passing**

The canonical AEGIS crypto/strength/policy/schema modules, plus a `LocalVaultClient` interface used by both new clients. Kept byte-identical with the web app's versions so every client is cryptographically interoperable.

Also defines: strict origin normalisation & matching (phishing-resistant), desktop app-identity matching, and metadata-only audit events.

### C. Chrome extension (`apps/chrome-extension/`) — **complete, 46 tests passing, builds to a loadable MV3 unpacked extension**

- Detects login / signup / password-change / unknown forms via autocomplete attributes, labels, names, form structure, and URL context
- Shows an in-page suggestion panel (generated password + score + strength + crack time) on signup/password-change fields
- Fills both password and confirmation fields, only after explicit approval
- Offers saved credentials on login forms **only on an exactly-matching origin**
- Blocks fill on plain-HTTP pages, refuses payment forms and Chrome internal pages
- Service worker holds the key in memory only — an MV3 restart genuinely comes back locked
- Scoped, debounced MutationObserver (only new subtrees, never full-document rescans); Shadow-DOM aware; singleton panel prevents duplicates across framework re-renders
- Every privileged message is schema-validated with sender/tab/origin checks

### D. Windows desktop assistant (`apps/desktop/`) — **complete, 71 tests passing, Electron main process verified to launch**

- Electron + React UI with `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, strict CSP, minimal preload bridge
- .NET 8 native helper using **UI Automation focus-change events only** — no keyboard hooks, no keylogging, no screenshots, no OCR, no clipboard monitoring (enforced by an automated static test)
- Detects password controls via UIA `IsPassword`, control type, automation ID, labels, sibling controls
- Ignores browser processes so it never conflicts with the Chrome extension
- Re-validates window, process ID, executable/package identity, **and** the control itself immediately before insertion — any mismatch refuses
- Inserts only via UIA `ValuePattern`; never silently falls back to simulated keystrokes
- Binds credentials to package family ID (packaged apps) or executable hash (traditional apps) — **never** process name alone
- System tray, lock/unlock status, Pause Assistant, per-app allow/deny, global enable/disable, auto-lock, clipboard-clear countdown
- Named-pipe IPC secured by a current-user-only ACL, schema-validated in both directions
- Runs `asInvoker` — never requests administrator privileges

### E. Test coverage — **172 automated tests, all passing**

| Suite | Tests | Covers |
|---|---|---|
| `packages/shared` | 41 | KDF determinism, wrapped random vault keys, user-held recovery and rotation, ciphertext-context binding, legacy migration, AES-GCM safety, origin/phishing matching, no-plaintext-persistence, audit trail |
| `apps/chrome-extension` | 46 | Form classification (login/signup/change/unknown/payment), dynamic & SPA forms, duplicate-panel prevention, origin matching, phishing rejection, HTTP rejection, locked vault, service-worker restart, malformed/unauthorised messages, no plaintext persistence |
| `apps/desktop` | 71 | UIA classification, policy store, pause & per-app deny, clipboard auto-clear (incl. not clobbering user copies), IPC schema validation, identity mismatch refusal, locked vault, atomic storage writes, static no-keylogging/no-plaintext-logging guard |
| `frontend` | 3 | authenticated vault API transport, ciphertext/revision preservation, conflict handling |
| `backend` | 11 | Argon2id/TOTP authentication plus encrypted profile/item storage, ownership, vault-write proof, conflicts, and tombstones |

---

## 3. Backend status and remaining client integration

The FastAPI **account authentication and encrypted vault service is built** under `backend/`. It owns account-password verification, encrypted TOTP seeds, one-time MFA challenges, recovery-code hashes, throttling, short-lived browser sessions, wrapped vault profiles, versioned ciphertext records, and deletion tombstones. It deliberately owns no vault-decryption material.

Right now each client (web, extension, desktop) keeps its **own** encrypted local store:

| Client | Storage |
|---|---|
| Web app | synchronized backend ciphertext plus a local encrypted cache |
| Chrome extension | `chrome.storage.local` |
| Desktop assistant | JSON files under Electron's `userData` |

All three use the **identical encryption algorithm and identical item schema**. The web app now synchronizes with the backend. Extension and desktop remote adapters remain.

Browsers isolate storage per origin, and a native desktop process cannot read a browser tab's JavaScript state. The shared ciphertext API is the correct bridge; extension and desktop still need a short-lived device-session exchange before they can use it.

The remaining integration phase is connecting the Chrome extension and desktop assistant to account MFA and the implemented ciphertext API. Their local-profile unlock screens are not yet protected by the account session.

### The backend's job in one line

> Store ciphertext it cannot read, and serve it back to authenticated clients.

It never sees a **vault** master password, stored credential plaintext, vault recovery key, or vault encryption key. It is deliberately "dumb" about vault secrets — that dumbness *is* the security property.

### Implemented authentication stack

- **FastAPI** (Python) — fast to write, automatic Swagger docs at `/docs` (great for judges), easy JWT/session auth
- **SQLite + SQLModel** — plenty for a hackathon; a single file, no server to provision
- **Argon2id + RFC 6238 TOTP** — account-password hashing and Google Authenticator-compatible MFA
- **AES-256-GCM** — server-side encryption of TOTP seeds under an environment-provided key

---

## 4. Architecture at a glance

```
┌──────────────┐   ┌──────────────────┐   ┌───────────────────┐
│   Web app    │   │ Chrome extension │   │ Desktop assistant │
│  (React)     │   │     (MV3)        │   │ (Electron + .NET) │
└──────┬───────┘   └────────┬─────────┘   └─────────┬─────────┘
       │                    │                       │
       │ account password + TOTP → account session  │
       │ vault password → PBKDF2 → unwrap random key│
       │        (vault key in-memory only)          │
       │                    │                       │
       └────────────────────┼───────────────────────┘
                            │  only ciphertext + metadata
                            ▼
                 ┌─────────────────────┐
                 │ FastAPI vault API   │  ← BUILT
                 │ Argon2id + TOTP     │
                 │ encrypted-item sync│  ← WEB CONNECTED
                 └─────────────────────┘
```

---

## 5. Demo script (~90 seconds)

1. Create/sign in to an account, verify Google Authenticator, then point out the separate vault-unlock screen.
2. Unlock the vault → Dashboard: vault strength, stat tiles, brand logos.
3. **Security Health** — "it already found breached and reused passwords."
4. **Demo: Simulate a Breach** → pick GitHub → *Trigger breach*. Watch it flip ELITE → CRITICAL, auto-lock, and fire a WhatsApp alert — live, offline, no wifi needed.
5. **Generator** — generate one, show the live strength breakdown.
6. Lock, log in as **admin**.
7. **Vault Registry** — show real ciphertext → click **Attempt decrypt** → it fails on screen with `OperationError`.
8. **Policy** + **Audit Log** — org-wide control and accountability.
9. Close with the one-liner from §1.

---

## 6. Anticipated judge questions

**"What if I forget my master password?"**
Use the separately generated `AEGIS-…` vault recovery key. Recovery immediately rotates both the master-password wrapper and the recovery key, invalidating the old values. Losing both the master password and this user-held key remains unrecoverable by design.

**"Why PBKDF2 and not Argon2?"**
Argon2 resists GPU/ASIC attacks better and is a good v2 upgrade. PBKDF2 is natively supported by every browser's WebCrypto with no extra library — critical for a demo that must just work. 600,000 iterations follows OWASP's current guidance.

**"Can the admin see passwords?"**
No — and we demonstrate it live. Admin sees account existence, timestamps, categories, and non-reversible strength labels (computed client-side and uploaded without the password), which is enough to enforce policy without any privacy violation.

**"What if the database is stolen?"**
The attacker gets encrypted blobs and a wrapped random vault key. Account credentials and TOTP sessions do not unwrap it; an offline attacker must still attack the independent vault master password or obtain the user-held vault recovery key.

**"Is this actually secure or just a demo?"**
The primitives and boundaries are implemented and tested: Argon2id for account passwords, RFC 6238 TOTP with one-use enforcement, PBKDF2 for the client-side wrapping key, AES-256-GCM for vault encryption, write authorization available only after vault unlock, optimistic synchronization, and a CSPRNG for every key/IV. Remaining work is shared production rate limiting, passkeys, and connecting extension/desktop to account MFA and the ciphertext API.
