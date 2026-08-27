# Compatibility and Known Limitations

Written to be honest rather than flattering. If something is unverified,
this document says so — do not claim otherwise in a demo.

---

## Verification status

| Component | Build | Automated tests | Run/manual verification |
|---|---|---|---|
| Web app (`frontend/`) | ✅ builds | ✅ 3 sync transport tests | ✅ exercised in browser |
| Account + encrypted vault API (`backend/`) | n/a | ✅ 11 passing | ✅ live TOTP + ciphertext CRUD flow verified |
| `packages/shared` | n/a (source) | ✅ 41 passing | ✅ via dependents |
| Chrome extension | ✅ builds to loadable MV3 unpacked | ✅ 46 passing | ⚠️ **not loaded into a real Chrome profile** |
| Desktop — Electron side | ✅ renderer builds; main process launches | ✅ 71 passing | ⚠️ partial (see below) |
| Desktop — .NET UIA helper | ❌ **never compiled** | ❌ **never run** | ❌ |

### What "not verified" concretely means

**Chrome extension.** `npm run build:extension` produces a valid, complete
`dist/` (manifest parses, every referenced file exists, no unresolved
imports). It has **not** been loaded via `chrome://extensions` in this
environment, so first-load runtime behaviour — panel positioning on real
sites, service-worker lifecycle under real Chrome suspension, permission
prompts — is unproven. The logic beneath it is unit-tested against jsdom.

**Electron main process.** It genuinely launches: window created, tray
initialised, vault client constructed, IPC router wired, and the
native-bridge reconnect loop logs an honest `ENOENT` because the helper is
not running. The renderer serves correctly from Vite on port 5180. What was
**not** verified is the visual UI end-to-end (no interactive GUI session was
available), so layout and interaction polish are untested.

**.NET helper.** This machine has no .NET SDK (`dotnet` absent, `winget`
absent), so `dotnet build` and `dotnet test` were never run. The C# passed
only a structural brace/paren balance check — that catches typos, **not**
type errors, missing usings, or API misuse. **Expect compilation fixes on
first build.** Do not demo this component unrehearsed.

Consequently, these acceptance criteria remain **unproven**:
- "detects supported UI Automation password fields in a provided Windows test application"
- "suggest, approve, insert, and save a password without recording keystrokes"
- "refuses insertion after the target window, process, application identity, or field changes"

The *logic* for the third is unit-tested in both JS and C# test suites; the
live UIA behaviour is not.

---

## Architectural limitation: extension/desktop remote integration

The FastAPI service and web flow now implement: account password →
TOTP/recovery code → short-lived HttpOnly session → separate local vault unlock
→ versioned ciphertext synchronization. Vault writes require an additional
random authorization secret that is encrypted under the vault key and exists
in plaintext only while unlocked.

The Chrome extension and desktop assistant still use local-only profiles and
are **not yet connected to the account MFA session or remote API**. Do not
claim that MFA protects their local profile unlock screens in this phase.

All three clients do not yet share one vault; the web backend path is complete,
while extension and desktop adapters remain.

Today each client keeps its own encrypted store:

| Client | Storage |
|---|---|
| Web app | backend ciphertext/tombstones plus a local encrypted cache |
| Chrome extension | `chrome.storage.local` |
| Desktop assistant | JSON files under Electron `userData` |

Browsers isolate storage per origin, and a native process cannot read a browser
tab's JavaScript state. The implemented shared encrypted-item service is the
bridge. Extension and desktop still require a safe device/session-token
exchange and remote storage adapter.

All three use the **identical algorithm and identical item schema**
(`packages/shared/src/credential-schema.js`), so their encrypted records remain
format-compatible with the implemented API.

**Claim web synchronization only.** Do not claim extension↔desktop↔web sync
until those two clients have remote authentication adapters.

---

## Chrome extension — functional limitations

- **Cross-origin iframes.** Content scripts run per-frame; a password field
  inside a cross-origin iframe is handled in that frame's own context, and
  parent/child coordination is not implemented. Fails safely (no panel)
  rather than misbehaving.
- **Closed shadow roots** are unreachable by any script, by definition.
  Open shadow roots are traversed.
- **Canvas/WebGL or custom-rendered "inputs"** that are not real `<input>`
  elements cannot be detected. No OCR fallback exists, deliberately.
- **Virtualised/lazy forms** are picked up when inserted, subject to the
  250 ms observer debounce.
- **Login autofill requires the popup.** A saved credential is filled via
  the popup's picker (which enforces explicit approval and re-validates
  origin), not by an in-page inline dropdown. The in-page panel is for
  *generating* new passwords on signup/change forms.
- **Username-field detection on save** uses a common-patterns heuristic
  (`autocomplete="username"`, `type="email"`, `name*="user"`) and can miss
  unconventional markup; the field is then saved blank and is editable later.
- **Classification confidence is not surfaced in the UI.** Low-confidence
  matches behave identically to high-confidence ones; only `unknown` is
  skipped.

## Desktop assistant — functional limitations

- **Windows only.** UI Automation is a Windows API. macOS/Linux are not
  supported and are not stubbed.
- **Applications without accessibility support are unsupported**, and are
  reported as such rather than silently skipped. This includes many games,
  custom-rendered UI toolkits, some Electron apps with accessibility
  disabled, and Java AWT/Swing apps without the Access Bridge.
- **No fallback insertion method by design.** If a control does not expose a
  settable UIA value, insertion is refused. Use the manual
  copy-and-paste fallback in the Credentials tab.
- **Unsigned, unpackaged executables** get a `win32` identity bound to an
  SHA-256 hash of the executable. A legitimate application update changes
  that hash and will correctly refuse to match — the credential must be
  re-bound. This is a deliberate security/convenience trade-off.
- **Never interacts with**: UAC secure desktop, Windows sign-in and
  credential-provider screens, protected system processes, or processes
  elevated beyond the helper's own privilege level.
- **Browsers are ignored on purpose** so the desktop assistant does not
  fight the Chrome extension over the same field.
- **The helper must be started separately** in development; it is not
  auto-spawned by the Electron app. `electron-builder` packages it under
  `resources/native-helper` for distribution.

## Shared/crypto limitations

- **Vault wrapping uses PBKDF2, not Argon2.** Account passwords are hashed
  server-side with Argon2id. The client-side vault wrapping key still uses
  PBKDF2 because it is natively available in
  every browser's WebCrypto with no additional library — important for a
  build that must work everywhere without bundling a WASM dependency.
  600,000 iterations follows current OWASP guidance for PBKDF2-HMAC-SHA256.
- **Key derivation takes ~0.5–2 s** on typical hardware. That cost is the
  security property, but it is user-visible on unlock.
- **Vault recovery is only as durable as the user's copy.** A 256-bit
  `AEGIS-…` recovery key is generated and displayed once. It is not stored by
  AEGIS. Recovery rotates the master-password wrapper and generates a new
  recovery key. Losing both the master password and recovery key is
  intentionally unrecoverable.
- **Breach checking needs network** for the live HIBP range API. Offline, it
  falls back to a small local corpus of the most common breached passwords,
  which is far less comprehensive — the demo breach simulator uses that
  corpus deliberately so it works without venue wifi.
- **Reuse detection is per-client**, because it requires decrypting that
  client's own items. It will become global once the backend ships.
- **Local vault unlock cannot be centrally rate-limited.** Offline protection
  rests on the PBKDF2 cost. Account-password, TOTP, and MFA-recovery attempts
  are throttled by the backend, but its current limiter is process-local and
  must be replaced by Redis or equivalent before a multi-worker deployment.
- **TOTP is not phishing-resistant.** A real-time phishing proxy can relay a
  valid code. Account compromise still does not unwrap the independent vault,
  but WebAuthn/passkeys are the recommended next authentication upgrade.

---

## Browser and platform support

| Target | Status |
|---|---|
| Chrome / Chromium ≥ 116 | Supported (`minimum_chrome_version` in manifest) |
| Edge (Chromium) | Expected to work — MV3 compatible — **untested** |
| Firefox | **Not supported.** MV3 differences (background scripts, `browser.*` namespace) would need a port. |
| Safari | Not supported. |
| Windows 10 / 11 | Desktop assistant target |
| macOS / Linux | Desktop assistant not supported |
