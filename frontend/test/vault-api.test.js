import assert from 'node:assert/strict'
import { afterEach, test } from 'node:test'

import { deleteEncryptedItem, getEncryptedVault, putEncryptedItem, putVaultProfile } from '../src/lib/vault-api.js'

const originalFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = originalFetch })

function reply(status, body) {
  return Promise.resolve(new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  }))
}

test('vault snapshot uses the authenticated same-origin session', async () => {
  let captured
  globalThis.fetch = async (...args) => {
    captured = args
    return reply(200, { ok: true, profile: null, items: [] })
  }
  const result = await getEncryptedVault()
  assert.equal(result.ok, true)
  assert.equal(captured[0], '/api/vault')
  assert.equal(captured[1].credentials, 'same-origin')
})

test('profile and item writes preserve encrypted payloads and revisions', async () => {
  const requests = []
  globalThis.fetch = async (url, options) => {
    requests.push({ url, options })
    return reply(200, { ok: true, revision: requests.length })
  }
  const profile = { version: 2, wrappedVaultKey: { v: 2, iv: 'iv', ct: 'cipher' } }
  const item = { app: 'Mail', password: { v: 2, iv: 'iv', ct: 'cipher' } }
  await putVaultProfile(profile, 3, 'sync-secret')
  await putEncryptedItem('item_01', item, 7, 'sync-secret')

  assert.deepEqual(JSON.parse(requests[0].options.body), { profile, expectedRevision: 3 })
  assert.deepEqual(JSON.parse(requests[1].options.body), { item, expectedRevision: 7 })
  assert.equal(requests[1].options.method, 'PUT')
  assert.equal(requests[1].options.headers['X-Aegis-Vault-Authorization'], 'sync-secret')
  assert.equal(requests[1].url, '/api/vault/items/item_01')
})

test('delete sends the expected revision and conflicts surface cleanly', async () => {
  let captured
  globalThis.fetch = async (...args) => {
    captured = args
    return reply(409, { detail: 'Vault item version conflict; current revision is 4' })
  }
  const result = await deleteEncryptedItem('item conflict', 2, 'sync-secret')
  assert.equal(result.ok, false)
  assert.equal(result.status, 409)
  assert.match(result.error, /version conflict/)
  assert.equal(captured[0], '/api/vault/items/item%20conflict?expectedRevision=2')
  assert.equal(captured[1].method, 'DELETE')
})
