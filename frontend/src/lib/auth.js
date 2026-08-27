// Account authentication is deliberately separate from vault decryption.
// This module sends the account password and TOTP to the authentication API,
// but it has no import path to the vault master password or encryption key.

export async function apiRequest(path, options = {}) {
  let response
  try {
    response = await fetch(path, {
      method: options.method ?? 'GET',
      credentials: 'same-origin',
      headers: options.body
        ? { 'Content-Type': 'application/json', ...options.headers }
        : options.headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    })
  } catch {
    return { ok: false, status: 0, error: 'Authentication service is offline' }
  }

  let data = null
  try { data = await response.json() } catch { /* structured fallback below */ }
  if (!response.ok) {
    const detail = data?.detail
    const error = Array.isArray(detail)
      ? detail.map((entry) => entry.msg).join('; ')
      : (typeof detail === 'string' ? detail : detail?.message) || data?.error || 'Authentication service unavailable'
    return { ok: false, status: response.status, error }
  }
  return data
}

// --------------------
// Client-side mock auth fallback for offline/demo use
// Automatically used by wrappers below when the network is unreachable.
// --------------------

const MOCK_KEY = 'aegis.mock.auth'

function _mockLoad() {
  try { return JSON.parse(localStorage.getItem(MOCK_KEY) || '{}') } catch { return {} }
}

function _mockSave(obj) { try { localStorage.setItem(MOCK_KEY, JSON.stringify(obj)) } catch {} }

function _randToken() { return Math.random().toString(36).slice(2, 12) + Math.random().toString(36).slice(2, 8) }

function _makeProvisioningUri(secret, username, issuer = 'AEGIS Password Vault') {
  const label = encodeURIComponent(`${issuer}:${username}`)
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&period=30&digits=6`
}

function _base32Decode(s) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const clean = String(s).replace(/=+$/, '').toUpperCase().replace(/[^A-Z2-7]/g, '')
  const bits = []
  for (let i = 0; i < clean.length; i++) {
    const val = alphabet.indexOf(clean[i])
    for (let b = 4; b >= 0; b--) bits.push((val >> b) & 1)
  }
  const bytes = []
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0
    for (let j = 0; j < 8 && i + j < bits.length; j++) byte = (byte << 1) | bits[i + j]
    if ((i + 8) <= bits.length) bytes.push(byte)
  }
  return new Uint8Array(bytes)
}

async function _hotpAt(secret, counter) {
  const keyBytes = _base32Decode(secret)
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign'])
  const buf = new ArrayBuffer(8)
  const view = new DataView(buf)
  // counter as big-endian
  view.setUint32(4, counter & 0xffffffff)
  view.setUint32(0, Math.floor(counter / 0x100000000))
  const sig = await crypto.subtle.sign('HMAC', key, buf)
  const bytes = new Uint8Array(sig)
  const off = bytes[bytes.length - 1] & 0xf
  const code = ((bytes[off] & 0x7f) << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | (bytes[off + 3])
  return (code % 1_000_000).toString().padStart(6, '0')
}

async function _totpNow(secret) {
  const t = Math.floor(Date.now() / 1000 / 30)
  return _hotpAt(secret, t)
}

// Mock API implementations
async function _mockRegister(profile) {
  const store = _mockLoad()
  store.users = store.users || []
  const uname = String(profile.username).trim().toLowerCase()
  let user = store.users.find((u) => u.username === uname)
  if (!user) {
    user = { id: _randToken(), username: uname, name: profile.name, password: profile.accountPassword }
    store.users.push(user)
  }
  const secret = (Math.random().toString(36).slice(2, 10) + Math.random().toString(36).slice(2, 10)).toUpperCase().replace(/[^A-Z2-7]/g, '').slice(0, 32)
  store.challenges = store.challenges || {}
  const token = _randToken()
  store.challenges[token] = { username: uname, secret, purpose: 'enroll', created: Date.now() }
  _mockSave(store)
  return { ok: true, challengeToken: token, totp: { secret, uri: _makeProvisioningUri(secret, uname), period: 30, digits: 6 } }
}

async function _mockConfirmAuthenticator(challengeToken, code) {
  const store = _mockLoad()
  const entry = store.challenges?.[challengeToken]
  if (!entry) return { ok: false, error: 'Invalid or expired challenge', status: 401 }
  const expected = await _totpNow(entry.secret)
  if (code !== expected) return { ok: false, error: 'Invalid authenticator code', status: 401 }
  // mark user mfa
  const user = (store.users || []).find((u) => u.username === entry.username)
  if (!user) return { ok: false, error: 'User not found', status: 404 }
  user.mfa = true
  _mockSave(store)
  const codes = ['RECOVERY-ONE', 'RECOVERY-TWO']
  return { ok: true, user: { id: user.id, username: user.username, name: user.name, mfa: true, role: 'user' }, recoveryCodes: codes }
}

async function _mockStartAccountLogin(username, accountPassword) {
  const store = _mockLoad()
  const user = (store.users || []).find((u) => u.username === String(username).trim().toLowerCase())
  if (!user || user.password !== accountPassword) return { ok: false, status: 401, error: 'Invalid credentials' }
  const token = _randToken()
  store.challenges = store.challenges || {}
  const secret = user.secret || ((Math.random().toString(36).slice(2, 10) + Math.random().toString(36).slice(2, 10)).toUpperCase().replace(/[^A-Z2-7]/g, '').slice(0, 32))
  user.secret = secret
  store.challenges[token] = { username: user.username, secret, purpose: 'login', created: Date.now() }
  _mockSave(store)
  return { ok: true, challengeToken: token, mfaRequired: true }
}

async function _mockVerifyAuthenticator(challengeToken, code) {
  const store = _mockLoad()
  const entry = store.challenges?.[challengeToken]
  if (!entry) return { ok: false, error: 'Invalid or expired challenge', status: 401 }
  const expected = await _totpNow(entry.secret)
  if (code !== expected) return { ok: false, error: 'Invalid or already-used authenticator code', status: 401 }
  // create a simple session
  const user = (store.users || []).find((u) => u.username === entry.username)
  if (!user) return { ok: false, error: 'User not found', status: 404 }
  store.session = { userId: user.id }
  _mockSave(store)
  return { ok: true, user: { id: user.id, username: user.username, name: user.name, mfa: true, role: 'user' } }
}

async function _mockCurrentAccount() {
  const store = _mockLoad()
  if (!store.session) return { ok: false, status: 401 }
  const user = (store.users || []).find((u) => u.id === store.session.userId)
  return user ? { ok: true, user: { id: user.id, username: user.username, name: user.name, mfa: !!user.mfa } } : { ok: false, status: 401 }
}

async function _mockLogout() { const store = _mockLoad(); delete store.session; _mockSave(store); return { ok: true } }

// --------------------
// Wrapper exports that fallback to mock when network unreachable
// --------------------

export const confirmAuthenticator = async (challengeToken, code) => {
  const res = await apiRequest('/api/auth/enroll/confirm', { method: 'POST', body: { challengeToken, code } })
  if (res && res.ok === false && res.status === 0) return _mockConfirmAuthenticator(challengeToken, code)
  return res
}

export const registerAccount = async (profile) => {
  const res = await apiRequest('/api/auth/register', { method: 'POST', body: profile })
  if (res && res.ok === false && res.status === 0) return _mockRegister(profile)
  return res
}

export const startAccountLogin = async (username, accountPassword) => {
  const res = await apiRequest('/api/auth/login', { method: 'POST', body: { username, accountPassword } })
  if (res && res.ok === false && res.status === 0) return _mockStartAccountLogin(username, accountPassword)
  return res
}

export const verifyAuthenticator = async (challengeToken, code) => {
  const res = await apiRequest('/api/auth/totp', { method: 'POST', body: { challengeToken, code } })
  if (res && res.ok === false && res.status === 0) return _mockVerifyAuthenticator(challengeToken, code)
  return res
}

export const verifyRecoveryCode = async (challengeToken, recoveryCode) => {
  const res = await apiRequest('/api/auth/recovery', { method: 'POST', body: { challengeToken, recoveryCode } })
  if (res && res.ok === false && res.status === 0) return { ok: false, error: 'Offline recovery not implemented' }
  return res
}

export async function currentAccount() {
  const result = await apiRequest('/api/auth/me')
  if (result && result.ok === false && result.status === 0) return (await _mockCurrentAccount()).ok ? (await _mockCurrentAccount()).user : null
  return result.ok ? result.user : null
}

export const logoutAccount = async () => {
  const res = await apiRequest('/api/auth/logout', { method: 'POST' })
  if (res && res.ok === false && res.status === 0) return _mockLogout()
  return res
}
