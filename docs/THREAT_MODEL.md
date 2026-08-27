# AEGIS — Threat Model

Scope: the FastAPI authentication service (`backend`), web client
(`frontend`), Chrome extension (`apps/chrome-extension`), Windows desktop
assistant (`apps/desktop`), and shared crypto/vault layer (`packages/shared`).

---

## Security goal

**An attacker who takes over an account session or obtains stored data — by
dumping a database, reading `localStorage`/`chrome.storage.local`, copying the
desktop files, or compromising the backend — still cannot decrypt vault
passwords without the independent vault master password or user-held vault
recovery key.**

Everything below follows from that one goal.

## Trust boundaries

| Boundary | Trusted? | Why |
|---|---|---|
| Account password + TOTP | Trusted by the auth service during verification | Proves account control but grants no decryption capability |
| User's typed vault master password | Trusted at the moment of entry | Used locally only to unwrap the random vault key |
| Random AES-256 vault key, in process memory | Trusted while unlocked | Non-extractable after import; dropped on lock/exit |
| Persisted storage (`localStorage`, `chrome.storage.local`, desktop JSON, backend DB) | **Untrusted** | Assumed readable by an attacker; stored passwords and vault secrets are ciphertext |
| FastAPI backend | **Untrusted for vault secrets** | Stores auth state, wrapped profiles, and encrypted items, but no vault key/material |
| Administrators | **Untrusted for secrets** | Can manage lifecycle and policy; cannot decrypt any credential |
| The web page a content script runs in | **Untrusted** | Isolated world; page scripts cannot reach extension state |
| Other desktop processes | **Untrusted** | Identity must be verified before any insertion |
| The user's OS and browser binary | Trusted | Out of scope — a compromised OS defeats any password manager |

---

## Assets

1. Vault master passwords — never persisted, transmitted, or logged.
2. Random AES-256 vault keys — wrapped at rest; non-extractable in memory.
3. Vault recovery keys — displayed once, user-held, and never persisted or transmitted.
4. Vault synchronization authorization secrets — encrypted under the vault
   key at rest; held only in memory after unlock; authorize writes but cannot decrypt.
5. Stored credential plaintext — exists only transiently during an approved
   fill/copy/reveal operation.
6. Vault metadata (app names, usernames, strength labels, timestamps) —
   lower sensitivity, but still access-controlled.

---

## Threats and mitigations

### T1 — Storage or backend compromise
*Attacker reads every stored byte.*

**Mitigated.** Each secret is sealed with AES-256-GCM under a random 256-bit
vault data key. The vault master password is stretched locally with
PBKDF2-HMAC-SHA256 at 600,000 iterations and wraps that random key; it does
not encrypt item data directly. Credential ciphertext uses authenticated
context containing the user and item IDs, so moving a valid blob to another
record fails GCM authentication. The server never receives the vault master
password, random vault key, or user-held recovery key.

An attacker with only an account session also lacks the random vault-write
authorization secret. Its keyed hash is stored by the backend and its plaintext
is encrypted inside the vault profile. Profile changes, item writes, and deletes
therefore require local vault unlock as well as account authentication.

*Tested:* `packages/shared/test/crypto.test.js`,
`test/vault-client.test.js` ("never persists plaintext anywhere in storage").

### T2 — Malicious or curious administrator
*Admin has full application and database access.*

**Mitigated.** No admin-facing code path can decrypt. The admin registry
returns ciphertext plus non-reversible metadata only, and its "Attempt
decrypt" action genuinely fails with an AES-GCM tag-verification error.
Every admin action is written to the audit log.

### T3 — Phishing / lookalike domains
*User visits `bank.com.evil.tld`; attacker wants the saved `bank.com` credential.*

**Mitigated.** Origin matching is exact on scheme + host + port. No
subdomain wildcarding, no `www.`-stripping, no suffix matching — precisely
because that fuzziness is what a lookalike domain exploits. The background
worker re-derives the origin from `sender.tab.url` rather than trusting any
origin claimed in the message payload.

*Tested:* `packages/shared/test/credential-schema.test.js`
("phishing resistance"), `apps/chrome-extension/test/router.test.js`
("rejects REVEAL_CREDENTIAL when the requesting tab is on a different origin").

### T4 — Network downgrade / plaintext HTTP
*Credential filled on an `http://` page could be captured in transit.*

**Mitigated.** Fill and save are refused on insecure origins at three
layers: the panel disables the buttons, the content script re-checks before
acting, and the background router rejects the request. `localhost` and
`127.0.0.1` are permitted for local development only.

### T5 — Page scripts stealing extension state
*Hostile page JavaScript tries to read the vault or the suggestion panel's password.*

**Mitigated.** Content scripts run in Chrome's isolated world — page script
cannot reach their variables or listeners. The suggestion panel renders
inside a shadow root attached to `documentElement`. No key material or
decrypted credential is ever placed in a DOM attribute, `window` property,
or `postMessage` payload. All privileged work happens in the service
worker; the content script only receives what a specific approved action
returns.

### T6 — Forged or malformed extension messages
*Another extension, or injected code, sends crafted runtime messages.*

**Mitigated.** Every inbound message is validated for sender identity
(`sender.id === chrome.runtime.id`), a known action name, a well-formed
payload against a per-action schema, and (for tab-sourced messages) a
present sender URL. Unknown actions are rejected explicitly rather than
falling through.

*Tested:* `apps/chrome-extension/test/messaging.test.js` (10 tests).

### T7 — MV3 service worker termination leaking an unlocked session
*Chrome kills the worker; a naive design would persist the key to "stay logged in".*

**Mitigated by construction.** The vault client is a module-level variable.
Worker termination destroys it. Nothing writes the key or session to
storage, so a restarted worker necessarily starts locked.

*Tested:* `apps/chrome-extension/test/router.test.js`
("a freshly constructed router … starts locked even though data was already persisted").

### T8 — Desktop: inserting a password into the wrong application
*Attacker races the approval dialog, swapping the foreground window.*

**Mitigated.** Before writing, the native helper re-validates: the focused
element's automation ID, the process ID, the live-resolved executable hash
or package family ID, and that the control is still a password field. Any
mismatch refuses the insert. Identity matching never accepts a process name
alone — `chrome.exe` exists on every Windows machine and proves nothing.

*Tested:* `apps/desktop/test/ipc-router.test.js` ("process/executable identity
mismatch"), `native-helper/AegisNativeHelper.Tests/IdentityResolverTests.cs`.

### T9 — Desktop: keylogging / screen scraping as an implementation shortcut
*A naive assistant would hook the keyboard or OCR the screen.*

**Mitigated and enforced.** Detection uses UI Automation focus-change events
only; insertion uses UIA `ValuePattern` only, with no silent fallback to
simulated keystrokes. An automated test greps the entire desktop source for
`SetWindowsHookEx`, `GetAsyncKeyState`, `iohook`, `robotjs`, screenshot and
clipboard-watching APIs and fails the build if any appear.

*Tested:* `apps/desktop/test/no-keylogging.test.js` (20 file checks).

### T10 — Left-unlocked device / lingering clipboard
**Mitigated.** Idle auto-lock drops the key (not merely the UI). Copied
secrets self-clear after the policy countdown, and only if the clipboard
still holds our value — never clobbering something the user copied since.
Suspend and screen-lock also trigger a lock.

*Tested:* `apps/desktop/test/clipboard-guard.test.js` (7 tests).

### T11 — Credential theft via payment/checkout confusion
**Mitigated.** The extension never engages on forms containing payment
autocomplete fields, and payment/checkout hosts are excluded in the
manifest.

### T12 — Account takeover, TOTP phishing, or stolen browser session
*Attacker passes account authentication and can request the user's stored data.*

**Vault confidentiality and mutation authorization remain mitigated.** Account authentication and vault
decryption are separate flows and use unrelated secrets. The account session
authorizes encrypted-data access only; the client still requires the vault
master password to unwrap its random vault key. Vault writes additionally need
a random authorization secret decrypted only during vault unlock; the server
stores only its keyed hash. Account passwords are hashed
with Argon2id. TOTP seeds are AES-GCM-encrypted at rest, login challenges and
MFA recovery codes are one-use, accepted TOTP steps cannot be replayed, and
attempts are throttled.

TOTP is not phishing-resistant: a real-time phishing proxy can relay a fresh
code and steal a session. The independent vault unlock limits the consequence,
but adding WebAuthn/passkeys remains recommended.

*Tested:* `backend/tests/test_auth.py`, `backend/tests/test_vault.py`, and the
wrapped-key/account-separation tests in `packages/shared/test/crypto.test.js`.

---

## Accepted risks (explicitly out of scope)

| Risk | Why accepted |
|---|---|
| Compromised OS, browser binary, or malicious browser extension with equal privileges | Any zero-knowledge design assumes an honest client at unlock time. Mitigated only by a strict extension CSP and shipping no remote code. |
| Malware with debugger access to process memory while unlocked | Defeats every password manager; out of scope for a user-level application. |
| Loss of both vault master password and vault recovery key | Unrecoverable by design. The server cannot manufacture a replacement decryption key. |
| Real-time TOTP phishing | TOTP is replay-resistant but not phishing-resistant. The vault still requires its separate password; WebAuthn/passkeys are the planned stronger account factor. |
| Malicious JavaScript served by a compromised web origin | A hostile client can capture a vault password at entry. Signed extension/desktop distribution and deployment hardening reduce this risk; an honest client at unlock remains a zero-knowledge assumption. |
| Metadata leakage (which apps a user has accounts for, credential strength labels) | Deliberately visible to admins so policy can be enforced centrally. Non-reversible; reveals no password content. |
| Traffic analysis of the k-anonymity breach lookup | The 5-character SHA-1 prefix is shared by hundreds of passwords; the service cannot determine which was checked. |
| UAC secure desktop, Windows sign-in, credential-provider screens, elevated processes | Never interacted with. Reported as unsupported rather than attempted. |

---

## What would break the model

Stated plainly so future contributors don't do it by accident:

1. Storing or transmitting the vault key, vault recovery key, or vault master password *in any form*.
2. Adding a server-side decrypt endpoint "for admin convenience".
3. Relaxing origin matching to suffix/subdomain comparison.
4. Matching desktop application identity on process name alone.
5. Falling back to simulated keystrokes when `ValuePattern` is unavailable.
6. Sending a password through the WhatsApp alert channel (metadata only).
7. Logging any variable holding a decrypted credential.
8. Letting a valid account session bypass the separate vault-unlock operation.
