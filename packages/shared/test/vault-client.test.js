import { describe, it, expect, beforeEach } from 'vitest'
import { LocalVaultClient, VaultLockedError } from '../src/vault-client.js'
import { deriveKey, encryptField } from '../src/crypto.js'
import { makeMemoryStorage } from './storage-fixture.js'

let storage, client

beforeEach(() => {
  storage = makeMemoryStorage()
  client = new LocalVaultClient(storage, { clientName: 'test-client' })
})

describe('unlock / lock lifecycle', () => {
  it('provisions a local profile on first unlock and reports unlocked status', async () => {
    const res = await client.unlock('alice', 'Demo@Vault2026')
    expect(res.ok).toBe(true)
    expect(res.recoveryKey).toMatch(/^AEGIS-/)
    const persisted = await storage.get('aegis.local.users')
    expect(persisted[0].vaultProfile.version).toBe(2)
    expect(persisted[0].verifier).toBeUndefined()
    expect(JSON.stringify(storage._dump())).not.toContain(res.recoveryKey)
    expect(client.getStatus().locked).toBe(false)
  })

  it('rejects the wrong master password on a second unlock attempt', async () => {
    await client.unlock('alice', 'Demo@Vault2026')
    await client.lock('test')
    const res = await client.unlock('alice', 'wrong-password')
    expect(res.ok).toBe(false)
    expect(client.getStatus().locked).toBe(true)
  })

  it('accepts the correct password on a second unlock', async () => {
    await client.unlock('alice', 'Demo@Vault2026')
    await client.lock('test')
    const res = await client.unlock('alice', 'Demo@Vault2026')
    expect(res.ok).toBe(true)
  })

  it('recovery rotates the old master password and the old recovery key', async () => {
    const first = await client.unlock('alice', 'old-vault-master')
    await client.lock('test')
    const recovered = await client.recover('alice', first.recoveryKey, 'new-vault-master')
    expect(recovered.ok).toBe(true)
    expect(recovered.recoveryKey).not.toBe(first.recoveryKey)
    await client.lock('test')
    expect((await client.unlock('alice', 'old-vault-master')).ok).toBe(false)
    expect((await client.unlock('alice', 'new-vault-master')).ok).toBe(true)
    await client.lock('test')
    expect((await client.recover('alice', first.recoveryKey, 'another-master')).ok).toBe(false)
  })

  it('migrates a version 1 direct-key profile and its ciphertext without data loss', async () => {
    const legacy = await deriveKey('legacy-master')
    const legacyBlob = await encryptField(legacy.key, 'legacy-secret')
    await storage.set('aegis.local.users', [{ id: 'legacy-user', username: 'alice', salt: legacy.salt, verifier: legacy.verifier }])
    await storage.set('aegis.local.items', [{ id: 'legacy-item', userId: 'legacy-user', app: 'Legacy', username: 'alice', password: legacyBlob }])

    const result = await client.unlock('alice', 'legacy-master')
    expect(result.migrated).toBe(true)
    expect(result.recoveryKey).toMatch(/^AEGIS-/)
    expect(await client.revealCredential('legacy-item')).toBe('legacy-secret')
    const users = await storage.get('aegis.local.users')
    const items = await storage.get('aegis.local.items')
    expect(users[0].verifier).toBeUndefined()
    expect(items[0].password.v).toBe(2)
  })

  it('throws VaultLockedError for vault operations while locked', async () => {
    await expect(client.createCredential({ app: 'x', username: 'y', password: 'z' })).rejects.toThrow(VaultLockedError)
  })
})

describe('credential create / update / reveal', () => {
  beforeEach(() => client.unlock('alice', 'Demo@Vault2026'))

  it('never persists plaintext anywhere in storage', async () => {
    await client.createCredential({ app: 'GitHub', username: 'alice', password: 'S3cr3t!Passphrase', url: 'https://github.com' })
    const raw = JSON.stringify(storage._dump())
    expect(raw).not.toContain('S3cr3t!Passphrase')
  })

  it('round-trips through create -> reveal', async () => {
    const { id } = await client.createCredential({ app: 'GitHub', username: 'alice', password: 'S3cr3t!Passphrase', url: 'https://github.com' })
    const revealed = await client.revealCredential(id)
    expect(revealed).toBe('S3cr3t!Passphrase')
  })

  it('rejects ciphertext copied into a different item identity', async () => {
    const first = await client.createCredential({ app: 'One', username: 'alice', password: 'first-secret' })
    const second = await client.createCredential({ app: 'Two', username: 'alice', password: 'second-secret' })
    const items = await storage.get('aegis.local.items')
    items.find((item) => item.id === second.id).password = items.find((item) => item.id === first.id).password
    await storage.set('aegis.local.items', items)
    expect(await client.revealCredential(second.id)).toBeNull()
  })

  it('rotating the password clears a compromise lock', async () => {
    const { id } = await client.createCredential({ app: 'GitHub', username: 'alice', password: 'old-pw-123', url: 'https://github.com' })
    const items = await storage.get('aegis.local.items')
    items.find((i) => i.id === id).locked = true
    await storage.set('aegis.local.items', items)

    expect(await client.revealCredential(id)).toBeNull() // blocked while locked

    await client.updateCredential(id, { password: 'new-rotated-pw-456' })
    const revealed = await client.revealCredential(id)
    expect(revealed).toBe('new-rotated-pw-456')
  })
})

describe('origin-scoped lookup', () => {
  beforeEach(() => client.unlock('alice', 'Demo@Vault2026'))

  it('finds a credential only on its exact saved origin', async () => {
    await client.createCredential({ app: 'Bank', username: 'alice', password: 'x', url: 'https://bank.com/login' })
    const onReal = await client.findByOrigin('https://bank.com/account')
    const onPhish = await client.findByOrigin('https://bank.com.evil.tld')
    expect(onReal).toHaveLength(1)
    expect(onPhish).toHaveLength(0)
  })

  it('lookup results never include the encrypted password field', async () => {
    await client.createCredential({ app: 'Bank', username: 'alice', password: 'x', url: 'https://bank.com' })
    const [meta] = await client.findByOrigin('https://bank.com')
    expect(meta.password).toBeUndefined()
  })
})

describe('appIdentity-scoped lookup', () => {
  beforeEach(() => client.unlock('alice', 'Demo@Vault2026'))

  it('finds a desktop credential only for a matching verified identity', async () => {
    await client.createCredential({
      app: 'Slack', username: 'alice', password: 'x',
      appIdentity: { type: 'win32', executableHash: 'hash-abc' },
    })
    const match = await client.findByAppIdentity({ type: 'win32', executableHash: 'hash-abc' })
    const mismatch = await client.findByAppIdentity({ type: 'win32', executableHash: 'hash-different' })
    expect(match).toHaveLength(1)
    expect(mismatch).toHaveLength(0)
  })
})

describe('fill guardrails', () => {
  beforeEach(() => client.unlock('alice', 'Demo@Vault2026'))

  it('assertSecureOrigin blocks plain-http fill targets', () => {
    expect(client.assertSecureOrigin('http://bank.com')).toBe(false)
    expect(client.assertSecureOrigin('https://bank.com')).toBe(true)
  })

  it('assertOriginMatch blocks a phishing-origin fill attempt', async () => {
    const { id } = await client.createCredential({ app: 'Bank', username: 'alice', password: 'x', url: 'https://bank.com' })
    const items = await storage.get('aegis.local.items')
    const item = items.find((i) => i.id === id)
    expect(client.assertOriginMatch(item, 'https://bank.com')).toBe(true)
    expect(client.assertOriginMatch(item, 'https://bank.com.evil.tld')).toBe(false)
  })
})

describe('audit trail', () => {
  it('records unlock, create, and reveal events with metadata only', async () => {
    await client.unlock('alice', 'Demo@Vault2026')
    const { id } = await client.createCredential({ app: 'GitHub', username: 'alice', password: 'S3cr3t!Passphrase' })
    await client.revealCredential(id)
    const events = await client.getAudit()
    const actions = events.map((e) => e.action)
    expect(actions).toContain('vault.unlocked')
    expect(actions).toContain('assistant.save')
    expect(actions).toContain('assistant.autofill_filled')
    expect(JSON.stringify(events)).not.toContain('S3cr3t!Passphrase')
  })
})
