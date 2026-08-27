// Ciphertext-only synchronization API. Payloads passed to this module have
// already been encrypted by vault.js; this file must never accept plaintext
// passwords, a vault master password, a recovery key, or an in-memory key.

import { apiRequest } from './auth.js'

export const getEncryptedVault = () => apiRequest('/api/vault')

const vaultHeaders = (syncSecret) => (
  syncSecret ? { 'X-Aegis-Vault-Authorization': syncSecret } : {}
)

export const putVaultProfile = (profile, expectedRevision = 0, syncSecret) => apiRequest('/api/vault/profile', {
  method: 'PUT', body: { profile, expectedRevision }, headers: vaultHeaders(syncSecret),
})

export const putEncryptedItem = (id, item, expectedRevision = 0, syncSecret) => apiRequest(
  `/api/vault/items/${encodeURIComponent(id)}`,
  { method: 'PUT', body: { item, expectedRevision }, headers: vaultHeaders(syncSecret) },
)

export const deleteEncryptedItem = (id, expectedRevision, syncSecret) => apiRequest(
  `/api/vault/items/${encodeURIComponent(id)}?expectedRevision=${encodeURIComponent(expectedRevision)}`,
  { method: 'DELETE', headers: vaultHeaders(syncSecret) },
)
