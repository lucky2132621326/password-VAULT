// ─── Shared AEGIS vault client ─────────────────────────────────────────────
// The interface every non-web client (Chrome extension, Windows desktop
// assistant) talks to. Built entirely on the canonical crypto/strength
// modules in this package — no parallel encryption scheme, no plaintext
// persistence.
//
// WHY A LOCAL STORE, NOT THE WEB APP'S localStorage: browsers isolate
// storage per origin by design, and a native desktop process cannot read a
// browser tab's in-memory JS state at all. Until BACKEND_CONTRACT.md's
// FastAPI service exists and all three clients (web, extension, desktop)
// talk to it, there is no mechanism — short of breaking the browser's
// security model — for an extension or a desktop app to literally share the
// web app's localStorage. So each client keeps its own encrypted store
// TODAY, using the identical algorithm and the identical item schema as the
// web app (see credential-schema.js), which makes every record forward-
// compatible the instant a shared backend ships. This is staged rollout,
// not a second conflicting vault.
//
// The caller supplies a `storageAdapter`: { get(key), set(key,value),
// remove(key) } — async, JSON-serializable values. Chrome extension code
// wraps chrome.storage.local; the desktop app wraps a per-user JSON file
// under Electron's userData directory. See lib/storage-adapter.js in each
// app for the concrete implementations.

import {
  deriveKey, createVaultProfile, unlockVaultProfile, recoverAndRewrapVaultProfile, credentialAad,
  encryptField, decryptField, randomBytes, b64, checkBreached,
  generatePassword, generatePassphrase, sha256Hex,
} from './crypto.js'
import { analyze, checkPolicy } from './strength.js'
import { DEFAULT_POLICY } from './config.js'
import { validateCredentialDraft, normalizeOrigin, originsMatch, appIdentityMatches, isSecureOrigin } from './credential-schema.js'
import { makeAuditEvent, AUDIT_ACTIONS } from './audit.js'

const KEYS = {
  users: 'aegis.local.users',
  items: 'aegis.local.items',
  audit: 'aegis.local.audit',
  policy: 'aegis.local.policy',
}

const uid = () => b64(randomBytes(9)).replace(/[^a-zA-Z0-9]/g, '').slice(0, 10)
const now = () => new Date().toISOString()
const MIN_NEW_VAULT_PASSWORD_LENGTH = 14

export class LocalVaultClient {
  /**
   * @param {{get:Function,set:Function,remove:Function}} storageAdapter
   * @param {{clientName?: string}} [opts]
   */
  constructor(storageAdapter, opts = {}) {
    this._storage = storageAdapter
    this._clientName = opts.clientName ?? 'unknown-client'
    // Private-by-convention (not exported, not serialized): the derived
    // CryptoKey and the identity of the unlocked user. Dies on lock()/
    // process exit — nothing here is ever written to storage.
    this._session = null // { userId, username, key, unlockedAt }
  }

  // ── Status ────────────────────────────────────────────────────────────
  getStatus() {
    return this._session
      ? { locked: false, username: this._session.username, unlockedAt: this._session.unlockedAt }
      : { locked: true }
  }

  isUnlocked() {
    return !!this._session
  }

  // ── Unlock / lock ────────────────────────────────────────────────────
  async unlock(username, masterPassword) {
    const uname = String(username).trim().toLowerCase()
    const users = (await this._storage.get(KEYS.users)) ?? []
    let user = users.find((u) => u.username === uname)

    if (!user) {
      // First unlock for this local profile: provision it. Mirrors the web
      // app's demo-account bootstrap, minus the fixed demo password list —
      // any master password provided here becomes that profile's password.
      if (String(masterPassword).length < MIN_NEW_VAULT_PASSWORD_LENGTH) {
        return { ok: false, error: `New vault master password must be at least ${MIN_NEW_VAULT_PASSWORD_LENGTH} characters` }
      }
      const { key, profile, recoveryKey } = await createVaultProfile(masterPassword)
      user = { id: uid(), username: uname, vaultProfile: profile, createdAt: now() }
      users.push(user)
      await this._storage.set(KEYS.users, users)
      this._session = { userId: user.id, username: uname, key, unlockedAt: Date.now() }
      await this._audit('vault.unlocked', `Local profile provisioned and unlocked by ${this._clientName}`, 'info')
      return { ok: true, recoveryKey, recoveryKeyIssued: true }
    }

    if (user.vaultProfile) {
      const key = await unlockVaultProfile(masterPassword, user.vaultProfile)
      if (!key) {
        await this._audit(AUDIT_ACTIONS.UNLOCK_FAILED, `Wrong vault master password for "${uname}"`, 'warn')
        return { ok: false, error: 'Invalid vault master password' }
      }
      let legacyKey = null
      if (user.legacy?.salt && user.legacy?.verifier) {
        const legacy = await deriveKey(masterPassword, user.legacy.salt)
        if (legacy.verifier === user.legacy.verifier) legacyKey = legacy.key
      }
      this._session = { userId: user.id, username: uname, key, legacyKey, unlockedAt: Date.now() }
      if (legacyKey) await this._completeLegacyMigration(user, users)
      await this._audit('vault.unlocked', `Random vault key unwrapped by ${this._clientName}`, 'info')
      return { ok: true }
    }

    // Backward-compatible one-time migration from version 1, where the
    // password-derived key encrypted items directly.
    const legacy = await deriveKey(masterPassword, user.salt)
    if (legacy.verifier !== user.verifier) {
      await this._audit(AUDIT_ACTIONS.UNLOCK_FAILED, `Wrong vault master password for "${uname}"`, 'warn')
      return { ok: false, error: 'Invalid vault master password' }
    }
    const created = await createVaultProfile(masterPassword)
    user.vaultProfile = created.profile
    user.legacy = { salt: user.salt, verifier: user.verifier }
    await this._storage.set(KEYS.users, users)
    this._session = { userId: user.id, username: uname, key: created.key, legacyKey: legacy.key, unlockedAt: Date.now() }
    await this._completeLegacyMigration(user, users)
    await this._audit('vault.migrated', `Legacy profile migrated to a wrapped random vault key by ${this._clientName}`, 'info')
    return { ok: true, recoveryKey: created.recoveryKey, recoveryKeyIssued: true, migrated: true }
  }

  async recover(username, recoveryKey, newMasterPassword) {
    const uname = String(username).trim().toLowerCase()
    const users = (await this._storage.get(KEYS.users)) ?? []
    const user = users.find((entry) => entry.username === uname)
    if (!user?.vaultProfile) return { ok: false, error: 'Recovery unavailable' }
    if (String(newMasterPassword).length < MIN_NEW_VAULT_PASSWORD_LENGTH) {
      return { ok: false, error: `New vault master password must be at least ${MIN_NEW_VAULT_PASSWORD_LENGTH} characters` }
    }
    const recovered = await recoverAndRewrapVaultProfile(recoveryKey, newMasterPassword, user.vaultProfile)
    if (!recovered) {
      await this._audit(AUDIT_ACTIONS.UNLOCK_FAILED, `Invalid vault recovery key for "${uname}"`, 'warn')
      return { ok: false, error: 'Invalid vault recovery key' }
    }
    user.vaultProfile = recovered.profile
    await this._storage.set(KEYS.users, users)
    this._session = { userId: user.id, username: uname, key: recovered.key, unlockedAt: Date.now(), recovered: true }
    await this._audit('vault.recovered', `Vault recovered and rewrapped by ${this._clientName}`, 'warn')
    return { ok: true, recoveryKey: recovered.recoveryKey, recoveryKeyIssued: true }
  }

  async _completeLegacyMigration(user, users) {
    const items = (await this._storage.get(KEYS.items)) ?? []
    for (const item of items.filter((entry) => entry.userId === user.id && (entry.password?.v ?? 1) < 2)) {
      const plaintext = await decryptField(this._session.legacyKey, item.password)
      if (plaintext == null) throw new Error('Legacy vault migration failed authentication')
      item.password = await encryptField(this._session.key, plaintext, credentialAad(user.id, item.id))
    }
    await this._storage.set(KEYS.items, items)
    delete user.salt
    delete user.verifier
    delete user.legacy
    this._session.legacyKey = null
    await this._storage.set(KEYS.users, users)
  }

  async lock(reason = 'manual') {
    if (this._session) await this._audit('vault.locked', `Session ended (${reason}) in ${this._clientName} — key zeroed`, 'info')
    this._session = null // drops the only reference to the CryptoKey
  }

  // ── Generation & analysis (no vault access required) ────────────────────
  generatePassword(opts) {
    return generatePassword(opts)
  }

  generatePassphrase(opts) {
    return generatePassphrase(opts)
  }

  async analyzePassword(password, extra = {}) {
    const policy = await this.getPolicy()
    return analyze(password, { policy, ...extra })
  }

  async checkBreached(password) {
    return checkBreached(password)
  }

  async getPolicy() {
    return (await this._storage.get(KEYS.policy)) ?? { ...DEFAULT_POLICY }
  }

  // ── Lookup (metadata only — no decryption) ──────────────────────────────
  async _myItems() {
    this._requireUnlocked()
    const items = (await this._storage.get(KEYS.items)) ?? []
    return items.filter((i) => i.userId === this._session.userId)
  }

  /** Website credentials whose saved origin exactly matches `pageOrigin`. */
  async findByOrigin(pageOrigin) {
    const target = normalizeOrigin(pageOrigin)
    if (!target) return []
    const items = await this._myItems()
    return items
      .filter((i) => i.url && originsMatch(i.url, pageOrigin))
      .map((i) => this._publicMeta(i))
  }

  /** Desktop credentials bound to a specific verified application identity. */
  async findByAppIdentity(appIdentity) {
    const items = await this._myItems()
    return items
      .filter((i) => i.appIdentity && appIdentityMatches(i.appIdentity, appIdentity))
      .map((i) => this._publicMeta(i))
  }

  async listMetadata() {
    return (await this._myItems()).map((i) => this._publicMeta(i))
  }

  _publicMeta(i) {
    // Exactly what a popup/suggestion UI needs to render a picker — never
    // the ciphertext, never plaintext.
    const { password, ...meta } = i
    return meta
  }

  // ── Create / update (encrypt-before-persist) ────────────────────────────
  async createCredential(draft) {
    this._requireUnlocked()
    const { ok, errors } = validateCredentialDraft(draft)
    if (!ok) return { ok: false, errors }

    const itemId = uid()
    const blob = await encryptField(this._session.key, draft.password, credentialAad(this._session.userId, itemId))
    const a = analyze(draft.password)
    const item = {
      id: itemId, userId: this._session.userId,
      app: draft.app, username: draft.username, url: draft.url ?? null, category: draft.category ?? 'Other',
      password: blob, strength: a.level, entropy: a.entropy,
      createdAt: now(), updatedAt: now(), favorite: false,
      locked: false, compromisedAt: null, compromiseReason: null, breachNotifiedAt: null,
      source: draft.source ?? this._clientName,
      originHash: draft.url ? await sha256Hex(normalizeOrigin(draft.url) ?? draft.url) : null,
      appIdentity: draft.appIdentity ?? null,
    }
    const items = (await this._storage.get(KEYS.items)) ?? []
    items.push(item)
    await this._storage.set(KEYS.items, items)
    await this._audit(AUDIT_ACTIONS.SAVE, `${draft.app} saved via ${this._clientName}`, 'info')
    return { ok: true, id: item.id }
  }

  async updateCredential(id, draft) {
    this._requireUnlocked()
    const items = (await this._storage.get(KEYS.items)) ?? []
    const item = items.find((i) => i.id === id && i.userId === this._session.userId)
    if (!item) return { ok: false, error: 'Not found' }

    if (draft.password) {
      const blob = await encryptField(this._session.key, draft.password, credentialAad(item.userId, item.id))
      const a = analyze(draft.password)
      Object.assign(item, {
        password: blob, strength: a.level, entropy: a.entropy,
        locked: false, compromisedAt: null, compromiseReason: null, breachNotifiedAt: null,
      })
    }
    if (draft.app != null) item.app = draft.app
    if (draft.username != null) item.username = draft.username
    if (draft.url != null) { item.url = draft.url; item.originHash = await sha256Hex(normalizeOrigin(draft.url) ?? draft.url) }
    if (draft.category != null) item.category = draft.category
    item.updatedAt = now()

    await this._storage.set(KEYS.items, items)
    await this._audit(AUDIT_ACTIONS.SAVE, `${item.app} updated via ${this._clientName}`, 'info')
    return { ok: true }
  }

  // ── Reveal (the ONLY path that returns plaintext) ───────────────────────
  // Callers must treat the return value as ephemeral: use it for the single
  // approved fill/copy/reveal action and let it fall out of scope. Never
  // log it, never persist it, never send it in a message that outlives the
  // fill operation.
  async revealCredential(id, { reasonForAudit = 'reveal' } = {}) {
    this._requireUnlocked()
    const items = (await this._storage.get(KEYS.items)) ?? []
    const item = items.find((i) => i.id === id && i.userId === this._session.userId)
    if (!item) return null
    if (item.locked) {
      await this._audit(AUDIT_ACTIONS.AUTOFILL_BLOCKED, `${item.app} is locked pending rotation`, 'warn')
      return null
    }
    const decryptionKey = (item.password?.v ?? 1) >= 2 ? this._session.key : this._session.legacyKey
    if (!decryptionKey) return null
    const pt = await decryptField(decryptionKey, item.password, credentialAad(item.userId, item.id))
    await this._audit(AUDIT_ACTIONS.AUTOFILL_FILLED, `${item.app} revealed via ${this._clientName} (${reasonForAudit})`, 'warn')
    return pt
  }

  async checkAgainstPolicy(password, extra = {}) {
    return checkPolicy(password, await this.getPolicy(), extra)
  }

  // ── Guardrails callers are expected to invoke before ANY fill ───────────
  assertSecureOrigin(pageOrigin) {
    if (!isSecureOrigin(pageOrigin)) {
      this._audit(AUDIT_ACTIONS.INSECURE_ORIGIN_BLOCKED, `Fill blocked on insecure origin ${normalizeOrigin(pageOrigin) ?? pageOrigin}`, 'critical')
      return false
    }
    return true
  }

  assertOriginMatch(item, pageOrigin) {
    const match = !!item.url && originsMatch(item.url, pageOrigin)
    if (!match) {
      this._audit(AUDIT_ACTIONS.ORIGIN_MISMATCH_BLOCKED, `Saved origin for "${item.app}" does not match ${normalizeOrigin(pageOrigin) ?? pageOrigin}`, 'critical')
    }
    return match
  }

  assertAppIdentityMatch(item, observedIdentity) {
    const match = !!item.appIdentity && appIdentityMatches(item.appIdentity, observedIdentity)
    if (!match) {
      this._audit(AUDIT_ACTIONS.IDENTITY_MISMATCH_BLOCKED, `Saved identity for "${item.app}" does not match the foreground process`, 'critical')
    }
    return match
  }

  // ── Audit ────────────────────────────────────────────────────────────
  async _audit(action, detail, severity) {
    const events = (await this._storage.get(KEYS.audit)) ?? []
    events.unshift(makeAuditEvent(action, detail, severity, {
      actor: this._session?.username ?? 'anonymous',
      role: 'user',
    }))
    await this._storage.set(KEYS.audit, events.slice(0, 300))
  }

  async submitAudit(action, detail, severity = 'info') {
    return this._audit(action, detail, severity)
  }

  async getAudit() {
    return (await this._storage.get(KEYS.audit)) ?? []
  }

  _requireUnlocked() {
    if (!this._session) throw new VaultLockedError()
  }
}

export class VaultLockedError extends Error {
  constructor() {
    super('Vault is locked — call unlock() before requesting vault data')
    this.name = 'VaultLockedError'
  }
}
