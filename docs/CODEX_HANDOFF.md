# Handoff Plan — AEGIS Chrome Extension + Windows Desktop Assistant

**Read this first, in full, before touching anything.** This is a handoff
between AI coding sessions on the same repo — you have no memory of the
prior conversation, so this document is the only context you get. It is
self-contained on purpose.

---

## 0. What AEGIS is (30-second orientation)

AEGIS is a zero-knowledge password vault. Account authentication uses an
Argon2id-hashed password plus Google Authenticator-compatible TOTP. Vault
master passwords never leave the client; PBKDF2-HMAC-SHA256 (600k) unwraps
a random AES-256 vault key locally. Credentials use AES-256-GCM with
user/item authenticated context; the server and admins have no decrypt path.

Three clients exist:
1. **`frontend/`** — React web app with account registration, Authenticator
   enrollment, TOTP/recovery login, and a separate local vault unlock.
2. **`apps/chrome-extension/`** — a Manifest V3 extension. Built, unit-tested
   (46 tests), builds to a loadable unpacked extension. **Never loaded into
   a real Chrome browser.**
3. **`apps/desktop/`** — an Electron + React app with a .NET 8 native
   helper for Windows UI Automation. Electron side built, unit-tested (71
   tests), main process verified to launch. **The .NET helper has never
   been compiled** — the environment that wrote it had no .NET SDK
   installed (`dotnet` command absent) and no interactive Windows GUI
   session to click through a real app.

Shared logic lives in **`packages/shared/`** — canonical crypto, strength
analysis, credential schema, and a `LocalVaultClient` class both new clients
   build on. 41 unit tests.

Read `docs/PROJECT_OVERVIEW.md`, `docs/THREAT_MODEL.md`, and
`docs/LIMITATIONS.md` now if you have not already — `LIMITATIONS.md`
specifically enumerates every unverified claim; treat it as the authoritative
list of what this handoff exists to close out.

---

## 1. Non-negotiable constraints (do not violate these while continuing)

These are the properties the entire project is built to demonstrate. Every
task below must preserve them:

1. **Never make the vault master password, random vault key, or vault recovery key leave the client**, in
   any form — not in a log, not in a network payload, not in a crash report.
2. **Never add a decrypt path for admins.** The admin registry in the web
   app shows real ciphertext and a genuinely-failing decrypt attempt — do
   not "fix" that to make a demo look smoother.
3. **Never relax origin matching** to subdomain/suffix comparison. It is
   exact scheme+host+port on purpose (phishing resistance).
4. **Never match desktop application identity on process name alone.**
   Only `packageFamilyId` or `executableHash`.
5. **Never add a keyboard hook, screen capture, OCR, or clipboard-watching
   code path** to the desktop assistant. `apps/desktop/test/no-keylogging.test.js`
   statically enforces this — if you need to bypass it, you are doing
   something wrong, not fixing a false positive.
6. **Never fall back to simulated keystrokes** if UI Automation's
   `ValuePattern` is unavailable on a control. Report it as unsupported.
7. Run `npm test` (root) before and after every phase. It must stay green —
   currently **152 passing** across 3 workspaces (`packages/shared` 35,
   `apps/chrome-extension` 46, `apps/desktop` 71).
8. Run `npm run build:web` after any change and confirm the frontend still
   builds — it must never regress.

---

## 2. Phase 1 — Compile and verify the .NET native helper (do this first)

This is the single biggest gap. Everything else is secondary to getting a
real compiler to look at this code.

### 2.1 Prerequisites

Install .NET 8 SDK: <https://dotnet.microsoft.com/download/dotnet/8.0>
Verify: `dotnet --version` should print `8.x.x`.

### 2.2 Build

```bash
cd apps/desktop/native-helper
dotnet restore
dotnet build
```

**Expect compilation errors.** This code was written against documented API
signatures without a compiler in the loop. Known risk areas to check first:

- `AegisNativeHelper.csproj` — `<UseWPF>true</UseWPF>` is how
  `System.Windows.Automation.*` (UIAutomationClient/UIAutomationTypes) gets
  pulled in without a manual assembly reference. If this doesn't resolve
  `System.Windows.Automation`, the project may need an explicit
  `<Reference Include="UIAutomationClient" />` /
  `<Reference Include="UIAutomationTypes" />` instead, or a NuGet package —
  check what actually resolves in your SDK version.
- `IdentityResolver.cs` — the `GetPackageFamilyName` P/Invoke signature.
  Verify the marshaling attributes and error codes
  (`APPMODEL_ERROR_NO_PACKAGE = 15700`, `ERROR_INSUFFICIENT_BUFFER = 122`)
  against the actual Win32 header values.
- `IdentityResolver.cs` — `X509Certificate.CreateFromSignedFile` is marked
  obsolete (`SYSLIB0057`) in newer .NET; there's a pragma suppressing the
  warning, but confirm it still compiles, or migrate to
  `X509CertificateLoader` if required by your SDK version.
- `PipeServer.cs` — `NamedPipeServerStreamAcl.Create` comes from the
  `System.IO.Pipes.AccessControl` NuGet package (referenced in the csproj).
  Confirm the parameter order/names match the installed package version.
- `Protocol.cs` — `required` record properties need C# 11+ (should be fine
  on .NET 8, but confirm `<LangVersion>` isn't pinned lower somewhere).

Fix whatever the compiler finds. Do not change the *behavior* described in
`Program.cs`, `UiaWatcher.cs`, `Classification.cs`, or `IdentityResolver.cs`
while fixing syntax/API errors — the logic was designed deliberately (see
constraint list above and the inline comments explaining *why*).

### 2.3 Run the unit tests

```bash
cd apps/desktop/native-helper
dotnet test
```

`AegisNativeHelper.Tests/ClassificationTests.cs` (9 tests) and
`IdentityResolverTests.cs` (9 tests) should pass once it compiles — they're
pure-logic tests with no UIA dependency. Fix any that fail; they encode real
requirements (e.g. "refuses to match on process name alone").

### 2.4 Update the delete-on-sight structural checker

Once `dotnet build` succeeds, delete or repurpose
`apps/desktop/native-helper/check-syntax.mjs` — it was a brace-balance-only
stand-in for a real compiler and is no longer needed once one exists. If you
keep it, don't let anyone mistake its "OK" output for a compile pass again.

### 2.5 Acceptance for this phase

- [ ] `dotnet build` succeeds with zero errors
- [ ] `dotnet test` passes all 18 tests
- [ ] Update `docs/LIMITATIONS.md`'s verification table — flip the `.NET
      helper` row from ❌ to ✅ for build/tests once true

---

## 3. Phase 2 — Live-run the .NET helper and verify real UI Automation behavior

Needs an interactive Windows desktop session (not headless/remote).

### 3.1 Run it standalone first

```bash
cd apps/desktop/native-helper/AegisNativeHelper
dotnet run
```

It should create the named pipe `\\.\pipe\aegis-native-helper` and print
nothing (it's headless) unless an error occurs. Leave it running.

### 3.2 Build a minimal test target

The spec this was built against calls for "a provided Windows test
application" with UI Automation-visible password fields. None currently
exists in this repo. Build one — the simplest option is a small WPF or
WinForms app with:
- A plain `PasswordBox`/`TextBox` with `IsPassword` semantics for a "login"
  screen (username + current-password)
- A second window/tab with two password fields for "signup" (new + confirm)
- Give the fields sensible `AutomationProperties.AutomationId` / `Name`
  values (e.g. `"NewPasswordBox"`, window title `"Create account"`) so
  `Classification.cs`'s heuristics have something to match — see
  `ClassificationTests.cs` for the exact hint patterns it looks for.

Put it under `apps/desktop/native-helper/TestHarness/` (new folder) with its
own minimal `.csproj`, and document how to run it in `docs/INSTALL.md`.

### 3.3 Verify detection

With the helper running and the test app focused:
- Focus the password field → confirm (via a temporary `Console.WriteLine`
  in `Program.cs`, or by connecting a raw named-pipe client) that a
  `field-detected` message is sent with a sensible `classification`.
- Tab away → confirm `field-lost` fires.
- Focus a *non-password* field → confirm nothing fires.

### 3.4 Verify insertion + refusal

Wire this up through the real Electron app (Phase 3) rather than a raw pipe
client, since that's the actual approval flow. Confirm:
- Clicking **Insert Password** in the AEGIS window writes into the focused
  field via `ValuePattern.SetValue` (verify the value actually appears).
- Switch the foreground window between detection and clicking Insert →
  confirm the insert is refused with a specific reason, not silently
  ignored or force-inserted.

### 3.5 Acceptance for this phase

- [ ] Helper detects a password field in the test harness and reports a
      sensible classification
- [ ] `field-lost` fires correctly on focus change
- [ ] A same-target insert succeeds and the value is verifiably present
- [ ] A changed-target insert is refused with a specific reason
- [ ] Update `docs/LIMITATIONS.md` verification table accordingly

---

## 4. Phase 3 — Run the full Electron app end-to-end

### 4.1 Start all three processes

```bash
# terminal 1
cd apps/desktop/native-helper/AegisNativeHelper && dotnet run

# terminal 2
npm run dev:renderer -w @aegis/desktop     # port 5180

# terminal 3
npm run start:electron -w @aegis/desktop
```

### 4.2 Walk the UI manually

- Unlock with a fresh account name + any master password (first unlock
  provisions it locally — see `packages/shared/src/vault-client.js`).
- Confirm the tray icon appears with working Lock/Pause/Enable menu items.
- Focus a password field in your test harness app → confirm the AEGIS
  window (or a popup near the field, per the original spec's "small
  assistant window near the active application without stealing focus" —
  **check whether the current implementation does this, or just relies on
  the always-open main window**; if it's the latter, that's a real gap
  worth closing, see Phase 5).
- Click through Generate Again / Insert / Copy / Save to Vault / Dismiss.
- Verify Save to Vault actually persists (check
  `%APPDATA%/aegis-assistant/vault-store/` for the encrypted JSON files —
  confirm no plaintext appears anywhere in those files).
- Test per-app deny: add a rule for your test harness's process name/hash in
  the **Apps** tab, confirm detection stops firing for it.
- Test Pause Assistant from the tray, confirm detection stops globally.
- Let the auto-lock timer expire (or lower `autoLockMinutes` in
  `packages/shared/src/config.js`'s `DEFAULT_POLICY` temporarily for
  testing) and confirm it actually locks.

### 4.3 Acceptance for this phase

- [ ] Full detect → suggest → approve → insert loop works against the test
      harness with zero crashes
- [ ] Save to Vault produces a file containing zero occurrences of the
      plaintext password (grep for it)
- [ ] Per-app deny and global pause both verifiably stop detection
- [ ] Auto-lock verified to actually drop the key (status flips to locked,
      and a subsequent reveal attempt fails until re-unlock)

---

## 5. Phase 4 — Load and verify the Chrome extension in real Chrome

### 5.1 Build and load

```bash
npm run build:extension
```

`chrome://extensions` → Developer mode → Load unpacked →
`apps/chrome-extension/dist`.

### 5.2 Serve and walk the fixtures

```bash
npx serve apps/chrome-extension/test/fixtures -l 8080
```

Open <http://localhost:8080/demo.html> and walk every section per
`docs/DEMO_SCRIPT.md` §A2–A7. For each, confirm the **actual browser
behavior** matches what the unit tests assert in isolation:

- §1 login form → popup offers the saved credential only when unlocked and
  on a matching origin
- §2 signup → panel appears on focus, Use Password fills both fields
  (inspect the actual DOM values, not just visually)
- §3 password-change → panel only on the *new* password field
- §4 dynamic/re-rendered form → exactly one panel node
  (`document.querySelectorAll('#aegis-assistant-host').length === 1` in
  DevTools console)
- §5 payment form → confirm zero AEGIS engagement (no panel, no console
  activity from the extension)
- §6 unknown form → no engagement

### 5.3 Cross-site / real-site smoke test

Try a couple of real, low-risk sites (e.g. a personal test account on a
site you control, or a throwaway signup form) to confirm the classifier
generalizes beyond the fixtures. **Do not use real credentials for this.**
If you find a misclassification, add a regression test to
`apps/chrome-extension/test/classifier.test.js` before fixing it.

### 5.4 Service-worker restart

`chrome://extensions` → AEGIS → **service worker** link → note it says
"Inactive" after idling, or manually terminate it via DevTools → confirm the
popup shows locked afterward (already unit-tested in `router.test.js`; this
step just confirms it holds in real Chrome).

### 5.5 Acceptance for this phase

- [ ] Every fixture section behaves as `docs/DEMO_SCRIPT.md` describes, in
      an actual Chrome window
- [ ] At least one non-fixture real-world site tested without a crash
- [ ] Service-worker restart re-locks in real Chrome, not just in tests
- [ ] Update `docs/LIMITATIONS.md` verification table accordingly

---

## 6. Phase 5 — Close gaps found during Phases 2–4

You will find real gaps doing the above — that's the point of this phase
existing. Known candidates worth checking specifically, from re-reading the
original spec against what's implemented:

- **"Show a small AEGIS assistant window near the active application
  without stealing focus"** (desktop spec, item 6) — confirm whether
  `apps/desktop/electron/main/index.js`'s single always-open `BrowserWindow`
  actually satisfies this, or whether a separate small non-focus-stealing
  popup window needs to be added for the in-context suggestion (distinct
  from the main AEGIS window). If the latter, this is a real feature gap,
  not a bug — plan it as new work, write tests for the window-positioning
  logic, don't just eyeball it.
- **In-page login-fill picker** — the Chrome extension's inline suggestion
  panel only appears for signup/change forms; login autofill currently
  requires opening the popup (see `docs/LIMITATIONS.md`). Confirm this
  matches the spec's intent ("offer saved credentials... on login forms")
  or whether an in-page picker is expected. If expected, extend
  `content-script.js`'s `handleLoginField` to render a picker via
  `panel.js` instead of only badging the toolbar icon.
- **Confidence surfacing** — classification confidence is computed
  (`classifier.js`, `Classification.cs`) but never shown in either UI.
  Decide whether to surface it (e.g. a subtle "likely signup" label) or
  formally drop it from the requirement.
- **Frame/iframe coordination** — cross-origin iframe password fields are
  currently handled independently per-frame with no parent/child
  coordination. If manual testing surfaces a real broken case (e.g. a
  payment-embedded-in-login iframe), fix it; don't speculatively build
  coordination logic no test demonstrates is needed.

For each gap you decide to close: write the test first (extending the
existing suites — do not create parallel ad hoc test files), then implement,
then re-run `npm test` to confirm nothing regressed.

---

## 7. Phase 6 — Remaining extension/desktop backend integration

The FastAPI account-authentication and encrypted-item backend now exists under
`backend/`. The web client uses its versioned ciphertext endpoints. The
remaining phase is connecting extension/desktop to account MFA and that API.
Preserve the existing auth/vault boundary and unlock-derived write
authorization; do not reintroduce the old master-password-derived verifier.

### 7.1 What changes

`packages/shared/src/vault-client.js`'s `LocalVaultClient` needs a
sibling `RemoteVaultClient` (or a mode flag) that swaps the `storageAdapter`
calls for `fetch` calls to the backend endpoints listed in
`BACKEND_PROMPT.md`. **No page/component in `frontend/`, `apps/chrome-
extension/`, or `apps/desktop/` should need to change** — they all consume
the vault client through the same interface (`unlock`, `lock`,
`createCredential`, `findByOrigin`, `findByAppIdentity`, `revealCredential`,
etc.), which is the entire point of that abstraction.

### 7.2 Order of operations

1. Confirm the backend's `Item` JSON shape matches
   `packages/shared/src/credential-schema.js` exactly (field names,
   optionality).
2. Reuse the existing HttpOnly session cookie for the web client. Design a
   separate short-lived device/session-token exchange for extension/desktop;
   never persist it beside vault keys or let it bypass local vault unlock.
3. The web swap is complete. Add extension next, then desktop, confirming
   existing local accounts/credentials still work at each step.
4. Once all three point at the backend, verify the actual cross-client sync
   claim: save a credential in the extension, confirm it appears in the
   web app and desktop app without re-entering it.

### 7.3 Acceptance

- [ ] A credential created in any one client is readable in the other two
- [x] Existing web local-only vault data has an upload migration path
- [ ] Existing extension/desktop local-only vault data has a documented migration path (or an
      explicit "local vaults are not migrated" note if that's the decision)
- [x] `npm test` is green after the web swap
- [x] `docs/LIMITATIONS.md` distinguishes implemented web sync from remaining clients

---

## 8. Running log — update this section as you go

Keep a running note of what you did, in case another session picks this up
after you. Append, don't rewrite history.

```
[date] — [what you did] — [what's still open]
2026-08-27 — Added FastAPI Argon2id + TOTP account authentication, encrypted TOTP seeds, one-use/replay-protected challenges and MFA recovery codes, HttpOnly sessions, throttling, the web enrollment/login flow, wrapped random vault keys, user-held vault recovery with key rotation, credential AAD binding, legacy local-vault migration, and security regression tests. Updated Electron/build dependencies. — Still open: encrypted-item backend endpoints/sync; extension and desktop account-MFA integration; shared production rate limiter; passkeys; live Chrome/.NET verification.
2026-08-27 — Added authenticated wrapped-profile and encrypted-item APIs, per-user ownership, unlock-derived vault-write authorization, optimistic revisions, deletion tombstones, web ciphertext hydration/migration/CRUD sync, 5 backend vault tests, 3 frontend transport tests, and live HTTP verification. — Still open: extension/desktop account-MFA + remote adapters; shared production rate limiter; passkeys; live Chrome/.NET verification.
```

---

## 9. Quick reference — commands you'll use constantly

```bash
npm test                          # all JS tests (must stay green)
npm run test:backend              # FastAPI auth security tests
npm run build:web                 # frontend must never regress
npm run build:extension           # rebuild before every reload
npm run test:desktop              # after any electron/main change
cd apps/desktop/native-helper && dotnet build && dotnet test
```
