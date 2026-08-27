// ─── Vault store ──────────────────────────────────────────────────────────
// Holds the encrypted database + the in-memory session. Deliberately plain:
// a module-level store with a subscribe hook, no state library needed.
//
// What is persisted: ciphertext, wrapped random vault keys, salts, metadata.
// What is NEVER persisted: the vault master password, recovery key, vault key, plaintext.

import {
  deriveKey, createVaultProfile, unlockVaultProfile, unlockVaultSyncSecret, provisionVaultSyncSecret,
  recoverAndRewrapVaultProfile, credentialAad,
  encryptField, decryptField, b64, randomBytes, DEMO_BREACHED_PASSWORDS,
} from './crypto'
import { DEFAULT_POLICY } from './config'
import { analyze } from './strength'
import { sendBreachAlert } from './alerts'
import { deleteEncryptedItem, getEncryptedVault, putEncryptedItem, putVaultProfile } from './vault-api'

const DB_KEY = 'aegis.db.v1'

// ─── Reactive store plumbing ──────────────────────────────────────────────
const listeners = new Set()
let state = {
  db: load(),
  session: null,   // { userId, username, name, role, key, unlockedAt }
  locked: true,
}

export const subscribe = (fn) => { listeners.add(fn); return () => listeners.delete(fn) }
export const getState = () => state
export const hasLocalVault = (username) => state.db.users.some((user) => user.username === String(username).trim().toLowerCase())

function set(patch) {
  state = { ...state, ...patch }
  listeners.forEach((f) => f(state))
}

function persist() {
  try { localStorage.setItem(DB_KEY, JSON.stringify(state.db)) } catch { /* quota / private mode */ }
  set({ db: { ...state.db } })
}

function load() {
  try {
    const raw = localStorage.getItem(DB_KEY)
    if (raw) return JSON.parse(raw)
  } catch { /* corrupt or unavailable — fall through to a fresh db */ }
  return { users: [], items: [], audit: [], policy: { ...DEFAULT_POLICY }, seeded: false }
}

const uid = () => b64(randomBytes(9)).replace(/[^a-zA-Z0-9]/g, '').slice(0, 10)
const now = () => new Date().toISOString()
export const MIN_NEW_VAULT_PASSWORD_LENGTH = 14

const syncedItem = (item) => ({
  app: item.app,
  username: item.username,
  url: item.url ?? '',
  category: item.category,
  password: item.password,
  strength: item.strength,
  entropy: Math.round(item.entropy),
  createdAt: item.createdAt,
  updatedAt: item.updatedAt,
  favorite: !!item.favorite,
  locked: !!item.locked,
  compromisedAt: item.compromisedAt ?? null,
  compromiseReason: item.compromiseReason ?? null,
  breachNotifiedAt: item.breachNotifiedAt ?? null,
})

const sameVaultProfile = (left, right) => Boolean(left && right
  && left.version === right.version
  && left.salt === right.salt
  && left.wrappedVaultKey?.iv === right.wrappedVaultKey?.iv
  && left.wrappedVaultKey?.ct === right.wrappedVaultKey?.ct
  && left.recoveryWrappedVaultKey?.iv === right.recoveryWrappedVaultKey?.iv
  && left.recoveryWrappedVaultKey?.ct === right.recoveryWrappedVaultKey?.ct
  && left.wrappedSyncSecret?.iv === right.wrappedSyncSecret?.iv
  && left.wrappedSyncSecret?.ct === right.wrappedSyncSecret?.ct)

async function uploadItem(item, syncSecret = state.session?.syncSecret) {
  if (!syncSecret) return { ok: false, error: 'Unlock the vault before changing synchronized data' }
  const result = await putEncryptedItem(item.id, syncedItem(item), item.syncRevision ?? 0, syncSecret)
  if (result.ok) item.syncRevision = result.revision
  return result
}

// Hydrate ciphertext before asking for the vault master password. The server
// is authoritative for records it already knows; a pre-backend local vault is
// uploaded once without ever decrypting it on the server.
export async function prepareVault(accountProfile) {
  if (!accountProfile?.username) return { ok: false, error: 'Account authentication required' }
  const remote = await getEncryptedVault()
  if (!remote.ok) return remote

  const uname = accountProfile.username.trim().toLowerCase()
  let user = state.db.users.find((entry) => entry.username === uname)
  const remoteProfile = remote.profile

  if (remoteProfile) {
    const sameProfile = sameVaultProfile(user?.vaultProfile, remoteProfile.profile)
    if (!user) {
      user = {
        id: accountProfile.id, username: uname, name: accountProfile.name, role: accountProfile.role,
        vaultProfile: remoteProfile.profile, vaultRevision: remoteProfile.revision,
        createdAt: now(), status: 'active', mfa: true, lastSeen: now(), phone: '',
      }
      state.db.users.push(user)
    } else {
      user.vaultProfile = remoteProfile.profile
      user.vaultRevision = remoteProfile.revision
      user.name = accountProfile.name
      user.role = accountProfile.role
    }

    const otherItems = state.db.items.filter((entry) => entry.userId !== user.id)
    const unsynced = sameProfile
      ? state.db.items.filter((entry) => entry.userId === user.id && entry.syncRevision == null)
      : []
    const tombstones = new Set(remote.items.filter((entry) => entry.deleted).map((entry) => entry.id))
    const live = remote.items
      .filter((entry) => !entry.deleted)
      .map((entry) => ({ id: entry.id, userId: user.id, ...entry.item, syncRevision: entry.revision }))
    const remoteIds = new Set(remote.items.map((entry) => entry.id))
    state.db.items = [
      ...otherItems,
      ...live,
      ...unsynced.filter((entry) => !remoteIds.has(entry.id) && !tombstones.has(entry.id)),
    ]
    persist()
    return { ok: true, remote: true }
  }

  // A local pre-backend vault cannot be uploaded until its independent
  // master password decrypts the sync authorization secret.
  return { ok: true, remote: false }
}

// ─── Audit log ────────────────────────────────────────────────────────────
export function audit(action, detail = '', severity = 'info') {
  state.db.audit.unshift({
    id: uid(),
    ts: now(),
    actor: state.session?.username ?? 'anonymous',
    role: state.session?.role ?? '-',
    action,
    detail,
    severity,
    ip: '10.42.0.17',           // demo value; the backend fills this in for real
  })
  state.db.audit = state.db.audit.slice(0, 300)
  persist()
}

// ─── Account bootstrap ────────────────────────────────────────────────────
// Demo accounts are created lazily: we can only encrypt their seed data once
// we hold a key derived from the master password they just typed.

export const DEMO_ACCOUNTS = [
  { username: 'alice',  name: 'Alice Menon',  role: 'user',  master: 'Demo@Vault2026',  phone: '+919966007804' },
  { username: 'admin',  name: 'R. Krishnan',  role: 'admin', master: 'Admin@Vault2026', phone: '' },
]

const SEED_ITEMS = [
  { app: 'Gmail',            username: 'alice.menon@gmail.com', url: 'mail.google.com',   category: 'Email',     password: 'Tr0ub4dor&3xK!vp',        age: 40 },
  { app: 'HDFC NetBanking',  username: 'alicem94',              url: 'netbanking.hdfcbank.com', category: 'Banking', password: 'alice1994',           age: 420 },
  { app: 'Instagram',        username: '@alice.m',              url: 'instagram.com',     category: 'Social',    password: 'Sunshine2021!',           age: 190 },
  { app: 'GitHub',           username: 'alicemenon',            url: 'github.com',        category: 'Developer', password: 'kQ7#vLm2$pWx9!zRt4',      age: 12 },
  { app: 'Amazon',           username: 'alice.menon@gmail.com', url: 'amazon.in',         category: 'Shopping',  password: 'Sunshine2021!',           age: 220 },
  { app: 'Netflix',          username: 'alice.menon@gmail.com', url: 'netflix.com',       category: 'Other',     password: 'password123',             age: 500 },
  { app: 'Slack (Work)',     username: 'a.menon@corp.io',       url: 'corp.slack.com',    category: 'Work',      password: 'Wq3!nZ8@fJ6%rB1^tY',     age: 5 },
  { app: 'LinkedIn',         username: 'alice.menon@gmail.com', url: 'linkedin.com',      category: 'Social',    password: 'Qwerty@12345',            age: 310 },
]

async function seedFor(user, key) {
  const created = []
  for (const s of SEED_ITEMS) {
    const itemId = uid()
    const blob = await encryptField(key, s.password, credentialAad(user.id, itemId))
    const a = analyze(s.password)
    created.push({
      id: itemId,
      userId: user.id,
      app: s.app,
      username: s.username,
      url: s.url,
      category: s.category,
      password: blob,                      // ciphertext only
      strength: a.level,                   // non-reversible metadata for policy reporting
      entropy: a.entropy,
      createdAt: new Date(Date.now() - s.age * 864e5).toISOString(),
      updatedAt: new Date(Date.now() - s.age * 864e5).toISOString(),
      favorite: ['Gmail', 'HDFC NetBanking'].includes(s.app),
      locked: false, compromisedAt: null, compromiseReason: null, breachNotifiedAt: null,
    })
  }
  return created
}

// ─── Unlock / lock ────────────────────────────────────────────────────────

export async function unlock(username, masterPassword, accountProfile) {
  const uname = username.trim().toLowerCase()
  let user = state.db.users.find((u) => u.username === uname)

  if (!accountProfile || accountProfile.username !== uname) {
    return { ok: false, error: 'Account authentication required before vault unlock' }
  }

  const prepared = await prepareVault(accountProfile)
  if (!prepared.ok) return { ok: false, error: prepared.error || 'Encrypted vault synchronization failed' }
  user = state.db.users.find((u) => u.username === uname)

  // Account creation and vault creation are independent. The backend account
  // owns no decryption material; this profile is provisioned only after MFA.
  if (!user) {
    if (String(masterPassword).length < MIN_NEW_VAULT_PASSWORD_LENGTH) {
      return { ok: false, error: `New vault master password must be at least ${MIN_NEW_VAULT_PASSWORD_LENGTH} characters` }
    }
    const created = await createVaultProfile(masterPassword)
    user = {
      id: accountProfile.id || uid(), username: uname, name: accountProfile.name,
      role: accountProfile.role, vaultProfile: created.profile,
      createdAt: now(), status: 'active', mfa: true, lastSeen: now(), phone: '',
    }
    const stored = await putVaultProfile(created.profile, 0, created.syncSecret)
    if (!stored.ok) return { ok: false, error: stored.error || 'Could not create encrypted vault' }
    user.vaultRevision = stored.revision
    state.db.users.push(user)
    persist()
    set({
      session: {
        userId: user.id, username: user.username, name: user.name, role: user.role,
        key: created.key, syncSecret: created.syncSecret,
        unlockedAt: Date.now(), pendingRecoveryKey: created.recoveryKey,
      },
      locked: false,
    })
    audit('vault.unlocked', 'Random AES-256 vault key created and wrapped locally', 'info')
    return { ok: true, user, recoveryKey: created.recoveryKey }
  }

  user.name = accountProfile.name
  user.role = accountProfile.role
  user.mfa = true

  if (user.vaultProfile) {
    const key = await unlockVaultProfile(masterPassword, user.vaultProfile)
    if (!key) {
      audit('vault.unlock_failed', `Wrong vault master password for "${uname}"`, 'warn')
      return { ok: false, error: 'Invalid vault master password' }
    }
    let syncSecret = await unlockVaultSyncSecret(key, user.vaultProfile)
    if (!syncSecret) {
      const provisioned = await provisionVaultSyncSecret(key, user.vaultProfile)
      user.vaultProfile = provisioned.profile
      syncSecret = provisioned.syncSecret
    }
    let legacyKey = null
    if (user.legacy?.salt && user.legacy?.verifier) {
      const legacy = await deriveKey(masterPassword, user.legacy.salt)
      if (legacy.verifier === user.legacy.verifier) legacyKey = legacy.key
    }
    set({ session: { userId: user.id, username: user.username, name: user.name, role: user.role, key, legacyKey, syncSecret, unlockedAt: Date.now() }, locked: false })
    if (legacyKey) await completeLegacyMigration(user)
    if (!prepared.remote) {
      const stored = await putVaultProfile(user.vaultProfile, user.vaultRevision ?? 0, syncSecret)
      if (!stored.ok) {
        lock('profile-sync-failed')
        return { ok: false, error: stored.error || 'Could not synchronize vault profile' }
      }
      user.vaultRevision = stored.revision
      for (const item of state.db.items.filter((entry) => entry.userId === user.id)) {
        const result = await uploadItem(item, syncSecret)
        if (!result.ok) {
          lock('item-sync-failed')
          return { ok: false, error: result.error || 'Could not synchronize vault items' }
        }
      }
    }
    user.lastSeen = now()
    persist()
    audit('vault.unlocked', 'Random vault key unwrapped locally after account MFA', 'info')
    return { ok: true, user }
  }

  // One-time migration for databases written by the original direct-key design.
  const legacy = await deriveKey(masterPassword, user.salt)
  if (legacy.verifier !== user.verifier) {
    audit('vault.unlock_failed', `Wrong vault master password for "${uname}"`, 'warn')
    return { ok: false, error: 'Invalid vault master password' }
  }
  const created = await createVaultProfile(masterPassword)
  user.vaultProfile = created.profile
  user.legacy = { salt: user.salt, verifier: user.verifier }
  persist()
  set({
    session: {
      userId: user.id, username: user.username, name: user.name, role: user.role,
      key: created.key, legacyKey: legacy.key, syncSecret: created.syncSecret,
      unlockedAt: Date.now(), pendingRecoveryKey: created.recoveryKey,
    },
    locked: false,
  })
  await completeLegacyMigration(user)
  const stored = await putVaultProfile(user.vaultProfile, user.vaultRevision ?? 0, created.syncSecret)
  if (!stored.ok) {
    lock('profile-sync-failed')
    return { ok: false, error: stored.error || 'Could not synchronize migrated vault' }
  }
  user.vaultRevision = stored.revision
  for (const item of state.db.items.filter((entry) => entry.userId === user.id)) {
    const result = await uploadItem(item, created.syncSecret)
    if (!result.ok) {
      lock('item-sync-failed')
      return { ok: false, error: result.error || 'Could not synchronize migrated vault items' }
    }
  }
  user.lastSeen = now()
  persist()
  audit('vault.migrated', 'Legacy credentials re-encrypted under a wrapped random vault key', 'info')
  return { ok: true, user, recoveryKey: created.recoveryKey, migrated: true }
}

async function completeLegacyMigration(user) {
  for (const item of state.db.items.filter((entry) => entry.userId === user.id && (entry.password?.v ?? 1) < 2)) {
    const plaintext = await decryptField(state.session.legacyKey, item.password)
    if (plaintext == null) throw new Error('Legacy vault migration failed authentication')
    item.password = await encryptField(state.session.key, plaintext, credentialAad(user.id, item.id))
  }
  delete user.salt
  delete user.verifier
  delete user.legacy
  state.session.legacyKey = null
  persist()
}

export async function recoverVault(username, recoveryKey, newMasterPassword, accountProfile) {
  const uname = String(username).trim().toLowerCase()
  if (!accountProfile || accountProfile.username !== uname) return { ok: false, error: 'Account authentication required' }
  const user = state.db.users.find((entry) => entry.username === uname)
  if (!user?.vaultProfile) return { ok: false, error: 'Recovery unavailable' }
  if (String(newMasterPassword).length < MIN_NEW_VAULT_PASSWORD_LENGTH) {
    return { ok: false, error: `New vault master password must be at least ${MIN_NEW_VAULT_PASSWORD_LENGTH} characters` }
  }
  const recovered = await recoverAndRewrapVaultProfile(recoveryKey, newMasterPassword, user.vaultProfile)
  if (!recovered) return { ok: false, error: 'Invalid vault recovery key' }
  const stored = await putVaultProfile(recovered.profile, user.vaultRevision ?? 0, recovered.syncSecret)
  if (!stored.ok) return { ok: false, error: stored.error || 'Could not rotate the remote vault profile' }
  user.vaultProfile = recovered.profile
  user.vaultRevision = stored.revision
  persist()
  set({
    session: {
      userId: user.id, username: user.username, name: user.name, role: user.role,
      key: recovered.key, syncSecret: recovered.syncSecret, unlockedAt: Date.now(), recovered: true,
      pendingRecoveryKey: recovered.recoveryKey,
    },
    locked: false,
  })
  audit('vault.recovered', 'User-held recovery key unlocked vault and rotated its master-password wrapper', 'warn')
  return { ok: true, recoveryKey: recovered.recoveryKey }
}

export function acknowledgeRecoveryKey() {
  if (!state.session?.pendingRecoveryKey) return
  set({ session: { ...state.session, pendingRecoveryKey: null } })
}

export function lock(reason = 'manual') {
  if (state.session) audit('vault.locked', `Session ended (${reason}) — key zeroed from memory`, 'info')
  set({ session: null, locked: true })   // dropping the reference discards the CryptoKey
}

// ─── Item access ──────────────────────────────────────────────────────────

export const itemsForCurrentUser = () =>
  state.db.items.filter((i) => i.userId === state.session?.userId)

export async function revealPassword(itemId) {
  const item = state.db.items.find((i) => i.id === itemId)
  if (!item || !state.session) return null
  const key = (item.password?.v ?? 1) >= 2 ? state.session.key : state.session.legacyKey
  if (!key) return null
  const pt = await decryptField(key, item.password, credentialAad(item.userId, item.id))
  audit('item.revealed', `${item.app} (${item.username})`, 'warn')
  return pt
}

// Decrypt every item once — used by the health scan and reuse detection.
export async function decryptAll() {
  if (!state.session) return []
  const mine = itemsForCurrentUser()
  const out = []
  for (const it of mine) {
    const key = (it.password?.v ?? 1) >= 2 ? state.session.key : state.session.legacyKey
    out.push({ ...it, plaintext: key ? await decryptField(key, it.password, credentialAad(it.userId, it.id)) : null })
  }
  return out
}

export async function saveItem(draft) {
  if (!state.session) return { ok: false, error: 'Vault locked' }
  const a = analyze(draft.password)

  if (draft.id) {
    const item = state.db.items.find((i) => i.id === draft.id)
    if (!item) return { ok: false, error: 'Not found' }
    const blob = await encryptField(state.session.key, draft.password, credentialAad(item.userId, item.id))
    const wasLocked = item.locked
    const candidate = { ...item,
      app: draft.app, username: draft.username, url: draft.url, category: draft.category,
      password: blob, strength: a.level, entropy: a.entropy, updatedAt: now(),
      // Setting a new password IS the rotation — clear any compromise lock
      // and let a genuinely new breach re-alert instead of staying suppressed.
      locked: false, compromisedAt: null, compromiseReason: null, breachNotifiedAt: null,
    }
    const synced = await uploadItem(candidate)
    if (!synced.ok) return { ok: false, error: synced.error || 'Could not synchronize credential' }
    Object.assign(item, candidate)
    audit('item.updated', `${draft.app} — re-encrypted with a fresh IV${wasLocked ? ' (rotation cleared the compromise lock)' : ''}`, 'info')
  } else {
    const itemId = uid()
    const blob = await encryptField(state.session.key, draft.password, credentialAad(state.session.userId, itemId))
    const item = {
      id: itemId, userId: state.session.userId,
      app: draft.app, username: draft.username, url: draft.url, category: draft.category,
      password: blob, strength: a.level, entropy: a.entropy,
      createdAt: now(), updatedAt: now(), favorite: false,
      locked: false, compromisedAt: null, compromiseReason: null, breachNotifiedAt: null,
    }
    const synced = await uploadItem(item)
    if (!synced.ok) return { ok: false, error: synced.error || 'Could not synchronize credential' }
    state.db.items.push(item)
    audit('item.created', `${draft.app} (${draft.username})`, 'info')
  }
  persist()
  return { ok: true }
}

// ─── Demo tooling ───────────────────────────────────────────────────────
// For live presentations: swaps one item's password for a value guaranteed
// to be in the LOCAL breach corpus (see lib/crypto.js), so the detection →
// lock → auto-alert pipeline fires deterministically and offline, without
// depending on venue wifi reaching the real HIBP API. Runs through the exact
// same saveItem() path a real password edit would — nothing here is faked,
// only the input password is chosen to guarantee a breach hit.
export async function simulateBreach(itemId) {
  const item = state.db.items.find((i) => i.id === itemId)
  if (!item) return { ok: false, error: 'Not found' }
  const demoPassword = DEMO_BREACHED_PASSWORDS[Math.floor(Math.random() * DEMO_BREACHED_PASSWORDS.length)]
  const res = await saveItem({
    id: item.id, app: item.app, username: item.username, url: item.url,
    category: item.category, password: demoPassword,
  })
  if (res.ok) audit('demo.breach_simulated', `${item.app} password set to a known-breached demo value`, 'warn')
  return res
}

export async function deleteItem(id) {
  const item = state.db.items.find((i) => i.id === id)
  if (!item) return { ok: false, error: 'Not found' }
  const result = await deleteEncryptedItem(id, item.syncRevision ?? 0, state.session?.syncSecret)
  if (!result.ok) return { ok: false, error: result.error || 'Could not synchronize deletion' }
  state.db.items = state.db.items.filter((i) => i.id !== id)
  audit('item.deleted', item ? `${item.app} (${item.username})` : id, 'warn')
  persist()
  return { ok: true }
}

export async function toggleFavorite(id) {
  const item = state.db.items.find((i) => i.id === id)
  if (!item) return { ok: false, error: 'Not found' }
  const candidate = { ...item, favorite: !item.favorite, updatedAt: now() }
  const result = await uploadItem(candidate)
  if (!result.ok) return { ok: false, error: result.error || 'Could not synchronize favorite' }
  Object.assign(item, candidate)
  persist()
  return { ok: true }
}

// ─── Admin operations (metadata only — no plaintext access, by design) ─────

export function allUsers() { return state.db.users }

export function allItemsMeta() {
  // Exactly what an admin is permitted to see: identity + ciphertext + strength.
  return state.db.items.map((i) => {
    const owner = state.db.users.find((u) => u.id === i.userId)
    return {
      id: i.id, owner: owner?.username ?? 'unknown', ownerPhone: owner?.phone ?? '', app: i.app, username: i.username,
      category: i.category, strength: i.strength, entropy: i.entropy,
      updatedAt: i.updatedAt, createdAt: i.createdAt,
      cipher: i.password.alg, iv: i.password.iv, ct: i.password.ct,
      locked: !!i.locked, compromisedAt: i.compromisedAt ?? null,
    }
  })
}

export function setUserStatus(userId, status) {
  const u = state.db.users.find((x) => x.id === userId)
  if (!u) return
  u.status = status
  audit('user.status', `${u.username} → ${status}`, status === 'suspended' ? 'warn' : 'info')
  persist()
}

export function forceRotation(userId) {
  const u = state.db.users.find((x) => x.id === userId)
  if (!u) return
  u.rotationRequired = true
  audit('user.rotation', `Rotation enforced for ${u.username}`, 'warn')
  persist()
}

// ─── Breach response: out-of-band alert + item lockdown ───────────────────
// Deliberately NOT "delete the account, email the old passwords." Deleting
// destroys every unrelated credential in the vault over a single leaked app;
// mailing/WhatsApp-ing the password would ship plaintext through a third
// party, which is exactly what the zero-knowledge design exists to prevent.
// Instead: lock only the affected item, force its rotation, and notify the
// user on a channel independent of whichever app just leaked — never the
// secret itself, only metadata (see lib/alerts.js).

const maskPhone = (p) => (p ? p.slice(0, 3) + '•'.repeat(Math.max(0, p.length - 6)) + p.slice(-3) : '')

export function setPhone(phone) {
  if (!state.session) return
  const u = state.db.users.find((x) => x.id === state.session.userId)
  if (!u) return
  u.phone = phone
  audit('user.phone_set', `WhatsApp alert number set to ${maskPhone(phone)}`, 'info')
  persist()
}

export const myPhone = () => state.db.users.find((u) => u.id === state.session?.userId)?.phone ?? ''

// Marks a breach as already alerted so useVaultScan's auto-notify effect
// doesn't re-fire on every subsequent scan of the same compromised password.
export function markBreachNotified(itemId) {
  const item = state.db.items.find((i) => i.id === itemId)
  if (!item || item.breachNotifiedAt) return
  item.breachNotifiedAt = now()
  persist()
}

// Self-service reminder — the user notifies themselves, nothing is locked.
export async function notifySelf(item, reason, occurrences) {
  const phone = myPhone()
  const res = await sendBreachAlert({ phone, app: item.app, reason, occurrences })
  audit(
    res.ok ? 'alert.whatsapp_sent' : 'alert.whatsapp_failed',
    res.ok ? `Breach alert sent for ${item.app} to ${maskPhone(phone)}${res.simulated ? ' (simulated — backend offline)' : ''}` : res.error,
    res.ok ? 'warn' : 'critical',
  )
  return res
}

// Admin response to a confirmed compromise: lock the one item, force
// rotation on the account, and notify the owner. Never touches the other
// items in that vault, and never suspends or deletes the account.
export async function flagCompromised(itemId, { reason = 'admin-flag', occurrences } = {}) {
  const item = state.db.items.find((i) => i.id === itemId)
  if (!item) return { ok: false, error: 'Not found' }
  const owner = state.db.users.find((u) => u.id === item.userId)

  item.locked = true
  item.compromisedAt = now()
  item.compromiseReason = reason
  if (owner) owner.rotationRequired = true
  audit('item.locked', `${item.app} (${owner?.username ?? 'unknown'}) locked — mandatory rotation required`, 'critical')
  persist()

  const res = await sendBreachAlert({ phone: owner?.phone, app: item.app, reason, occurrences })
  audit(
    res.ok ? 'alert.whatsapp_sent' : 'alert.whatsapp_failed',
    res.ok
      ? `Breach alert sent to ${owner?.username} (${maskPhone(owner?.phone)})${res.simulated ? ' (simulated — backend offline)' : ''}`
      : (res.error ?? `${owner?.username} has no WhatsApp number on file`),
    res.ok ? 'warn' : 'critical',
  )
  return res
}

export function updatePolicy(patch) {
  state.db.policy = { ...state.db.policy, ...patch }
  audit('policy.updated', Object.entries(patch).map(([k, v]) => `${k}=${v}`).join(', '), 'warn')
  persist()
}

export const getPolicy = () => state.db.policy
export const getAudit = () => state.db.audit

export function resetDemo() {
  localStorage.removeItem(DB_KEY)
  state = { db: load(), session: null, locked: true }
  listeners.forEach((f) => f(state))
}

// Start a local demo session without contacting the backend. Creates a
// local demo user, seeds demo items, and unlocks the vault using the
// built-in demo master password. Useful for offline demos when the
// authenticator/backend is unavailable.
export async function enterDemo(username = null) {
  try {
    console.debug('enterDemo() invoked, username=', username)
    const demo = (username && DEMO_ACCOUNTS.find((d) => d.username === username)) || DEMO_ACCOUNTS[0]
    const uname = String(demo.username).trim().toLowerCase()
    let user = state.db.users.find((u) => u.username === uname)

    if (!user) {
      const created = await createVaultProfile(demo.master)
      user = {
        id: uid(), username: uname, name: demo.name, role: demo.role,
        vaultProfile: created.profile, createdAt: now(), status: 'active', mfa: false, lastSeen: now(), phone: demo.phone,
      }
      state.db.users.push(user)

      const seeded = await seedFor(user, created.key)
      for (const it of seeded) state.db.items.push(it)
      persist()

      set({
        session: {
          userId: user.id, username: user.username, name: user.name, role: user.role,
          key: created.key, syncSecret: created.syncSecret, unlockedAt: Date.now(), pendingRecoveryKey: created.recoveryKey,
        },
        locked: false,
      })
      audit('demo.entered', `Demo user ${user.username} started`, 'info')
      console.debug('enterDemo() created demo user', user.username)
      return { ok: true, user, recoveryKey: created.recoveryKey }
    }

    // If a local demo user already exists, attempt a normal unlock with the
    // demo master password to restore a session (this reuses existing logic).
    console.debug('enterDemo() found existing user, unlocking', uname)
    const res = await unlock(uname, demo.master, { id: user.id, username: user.username, name: user.name, role: user.role })
    if (!res || !res.ok) {
      console.warn('enterDemo() unlock failed', res)
      return { ok: false, error: res?.error || 'Demo unlock failed' }
    }
    return res
  } catch (err) {
    console.error('enterDemo() error', err)
    return { ok: false, error: err?.message || String(err) }
  }
}
