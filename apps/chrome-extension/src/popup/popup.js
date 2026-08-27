import { ACTIONS } from '../lib/messaging.js'

const root = document.getElementById('root')

function send(action, payload) {
  return chrome.runtime.sendMessage({ action, payload })
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  return tab
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
}

async function render() {
  const status = await send(ACTIONS.GET_STATUS)
  const tab = await activeTab()
  const insecure = tab?.url && !/^https:|^http:\/\/localhost|^http:\/\/127\.0\.0\.1/.test(tab.url)

  if (status.locked) {
    root.innerHTML = `
      <h1>AEGIS</h1>
      <div class="status"><span class="dot locked"></span> Vault locked</div>
      <input class="field" id="u" placeholder="Account" autocomplete="off" />
      <input class="field" id="p" placeholder="Master password" type="password" autocomplete="off" />
      <div class="error" id="err"></div>
      <button class="primary" id="unlock">Unlock vault</button>
    `
    document.getElementById('unlock').addEventListener('click', async () => {
      const username = document.getElementById('u').value
      const masterPassword = document.getElementById('p').value
      const res = await send(ACTIONS.UNLOCK, { username, masterPassword })
      if (!res.ok) { document.getElementById('err').textContent = res.error; return }
      if (res.recoveryKey) { renderRecoveryKey(res.recoveryKey); return }
      render()
    })
    return
  }

  root.innerHTML = `
    <h1>AEGIS</h1>
    <div class="status"><span class="dot unlocked"></span> Unlocked as ${escapeHtml(status.username)}</div>
    ${insecure ? '<div class="error">This page is not served over HTTPS — autofill is disabled here.</div>' : ''}
    <div id="creds"><span class="muted">Checking this site…</span></div>
    <button id="lock" style="margin-top:8px">Lock vault</button>
  `
  document.getElementById('lock').addEventListener('click', async () => { await send(ACTIONS.LOCK); render() })

  if (!tab?.url || insecure) return
  const origin = new URL(tab.url).origin
  const res = await send(ACTIONS.FIND_BY_ORIGIN, { origin })
  const list = document.getElementById('creds')
  if (!res.ok) { list.innerHTML = `<span class="muted">${escapeHtml(res.error ?? 'Unavailable')}</span>`; return }
  if (!res.matches.length) { list.innerHTML = `<span class="muted">No saved credentials for this site.</span>`; return }

  list.innerHTML = res.matches.map((m) => `
    <div class="cred">
      <div><strong>${escapeHtml(m.app)}</strong><small>${escapeHtml(m.username)}</small></div>
      <button data-id="${m.id}" style="width:auto">Fill</button>
    </div>
  `).join('')

  list.querySelectorAll('button[data-id]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const revealRes = await send(ACTIONS.REVEAL_CREDENTIAL, { id: btn.dataset.id, origin })
      if (!revealRes.ok) { btn.textContent = 'Blocked'; return }
      await chrome.tabs.sendMessage(tab.id, { action: 'aegis/fill-login', payload: { username: revealRes.username, password: revealRes.password } })
      window.close()
    })
  })
}

function renderRecoveryKey(recoveryKey) {
  root.innerHTML = `
    <h1>AEGIS</h1>
    <div class="status"><span class="dot unlocked"></span> Save vault recovery key</div>
    <div class="error" style="color:#fef3c7;border-color:#f59e0b55;background:#f59e0b11">
      This is shown once. Store it offline; anyone holding it can recover this local vault.
    </div>
    <div class="field" id="recovery" style="height:auto;word-break:break-all;font-family:monospace">${escapeHtml(recoveryKey)}</div>
    <button id="copy-recovery">Copy recovery key</button>
    <button class="primary" id="saved-recovery" style="margin-top:8px">I stored it safely</button>
  `
  document.getElementById('copy-recovery').addEventListener('click', async () => {
    await navigator.clipboard.writeText(recoveryKey)
    document.getElementById('copy-recovery').textContent = 'Copied'
  })
  document.getElementById('saved-recovery').addEventListener('click', render)
}

render()
