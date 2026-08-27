import { useCallback, useEffect, useState } from 'react'

const invoke = (action, payload) => window.aegis.invoke(action, payload)

function useAegisStatus() {
  const [status, setStatus] = useState({ locked: true })
  const refresh = useCallback(() => invoke('desktop/get-status').then(setStatus), [])
  useEffect(() => { refresh() }, [refresh])
  return [status, refresh]
}

export default function App() {
  const [status, refreshStatus] = useAegisStatus()
  const [policy, setPolicy] = useState(null)
  const [detected, setDetected] = useState(null)
  const [suggested, setSuggested] = useState(null)
  const [analysis, setAnalysis] = useState(null)
  const [countdown, setCountdown] = useState(null)
  const [tab, setTab] = useState('assistant')

  const refreshPolicy = useCallback(() => invoke('desktop/get-assistant-policy').then((r) => setPolicy(r.policy)), [])
  useEffect(() => { refreshPolicy() }, [refreshPolicy])

  useEffect(() => {
    const offDetected = window.aegis.on('native/field-detected', async (payload) => {
      setDetected(payload)
      const gen = await invoke('desktop/generate-password', { length: 20 })
      setSuggested(gen.password)
      const a = await invoke('desktop/analyze-password', { password: gen.password })
      setAnalysis(a.analysis)
    })
    const offLost = window.aegis.on('native/field-lost', () => { setDetected(null); setSuggested(null); setAnalysis(null) })
    const offClipboard = window.aegis.on('clipboard/countdown', ({ remaining }) => setCountdown(remaining > 0 ? remaining : null))
    const offPolicyChanged = window.aegis.on('assistant/policy-changed', () => refreshStatus())
    return () => { offDetected(); offLost(); offClipboard(); offPolicyChanged() }
  }, [refreshStatus])

  if (status.locked) return <Unlock onUnlocked={refreshStatus} />

  return (
    <div style={{ padding: 14 }}>
      <Header status={status} policy={policy} onChange={refreshPolicy} />

      <nav style={{ display: 'flex', gap: 6, margin: '10px 0' }}>
        <TabButton active={tab === 'assistant'} onClick={() => setTab('assistant')}>Assistant</TabButton>
        <TabButton active={tab === 'vault'} onClick={() => setTab('vault')}>Credentials</TabButton>
        <TabButton active={tab === 'apps'} onClick={() => setTab('apps')}>Apps</TabButton>
      </nav>

      {tab === 'assistant' && (
        <AssistantPanel
          detected={detected}
          suggested={suggested}
          analysis={analysis}
          countdown={countdown}
          onRegenerate={async () => {
            const gen = await invoke('desktop/generate-password', { length: 20 })
            setSuggested(gen.password)
            const a = await invoke('desktop/analyze-password', { password: gen.password })
            setAnalysis(a.analysis)
          }}
          onDismiss={() => { setDetected(null); setSuggested(null); setAnalysis(null) }}
        />
      )}
      {tab === 'vault' && <CredentialList detected={detected} />}
      {tab === 'apps' && <AppRules policy={policy} onChange={refreshPolicy} />}
    </div>
  )
}

function TabButton({ active, children, ...props }) {
  return (
    <button
      {...props}
      style={{
        flex: 1, padding: '6px 8px', fontSize: 11.5, borderRadius: 6, cursor: 'pointer',
        border: '1px solid #1e293b', background: active ? '#131c30' : 'transparent',
        color: active ? '#38bdf8' : '#7b8aa5',
      }}
    >
      {children}
    </button>
  )
}

function Unlock({ onUnlocked }) {
  const [username, setUsername] = useState('')
  const [masterPassword, setMasterPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [recoveryKey, setRecoveryKey] = useState('')

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError('')
    const res = await invoke('desktop/unlock', { username, masterPassword })
    setBusy(false)
    if (!res.ok) { setError(res.error); return }
    if (res.recoveryKey) { setRecoveryKey(res.recoveryKey); return }
    onUnlocked()
  }

  if (recoveryKey) {
    return (
      <div style={{ padding: 24 }}>
        <h1 style={{ fontSize: 15, letterSpacing: '.14em', color: '#fbbf24' }}>SAVE RECOVERY KEY</h1>
        <p style={{ color: '#9fb0c9', fontSize: 12, lineHeight: 1.5 }}>
          This key is shown once. Store it offline; anyone holding it can recover this local vault.
        </p>
        <div style={{ ...fieldStyle, wordBreak: 'break-all', fontFamily: 'ui-monospace, monospace', marginTop: 12 }}>{recoveryKey}</div>
        <button style={smallButtonStyle} onClick={() => navigator.clipboard.writeText(recoveryKey)}>Copy recovery key</button>
        <button style={{ ...primaryButtonStyle, width: '100%', marginTop: 10 }} onClick={onUnlocked}>I stored it safely</button>
      </div>
    )
  }

  return (
    <div style={{ padding: 24, textAlign: 'center' }}>
      <h1 style={{ fontSize: 15, letterSpacing: '.14em', color: '#38bdf8' }}>AEGIS</h1>
      <p style={{ color: '#7b8aa5', fontSize: 12 }}>Desktop Assistant</p>
      <form onSubmit={submit} style={{ marginTop: 16, textAlign: 'left' }}>
        <input
          value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Account"
          style={fieldStyle}
        />
        <input
          type="password" value={masterPassword} onChange={(e) => setMasterPassword(e.target.value)}
          placeholder="Master password" style={fieldStyle}
        />
        {error && <div style={{ color: '#fb7185', fontSize: 11.5, marginBottom: 8 }}>{error}</div>}
        <button type="submit" disabled={busy} style={primaryButtonStyle}>{busy ? 'Unlocking…' : 'Unlock vault'}</button>
      </form>
    </div>
  )
}

function Header({ status, policy, onChange }) {
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ fontSize: 12, fontWeight: 700, letterSpacing: '.1em', color: '#38bdf8' }}>AEGIS</div>
          <div style={{ fontSize: 11, color: '#7b8aa5' }}>Unlocked as {status.username}</div>
        </div>
        <button
          onClick={async () => { await invoke('desktop/lock'); onChange() }}
          style={{ ...smallButtonStyle }}
        >
          Lock
        </button>
      </div>
      {policy && (
        <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
          <Toggle
            label={policy.globallyEnabled ? 'Enabled' : 'Disabled'}
            on={policy.globallyEnabled}
            onClick={async () => { await invoke('desktop/set-globally-enabled', { enabled: !policy.globallyEnabled }); onChange() }}
          />
          <Toggle
            label={policy.paused ? 'Paused' : 'Active'}
            on={!policy.paused}
            onClick={async () => { await invoke('desktop/set-paused', { paused: !policy.paused }); onChange() }}
          />
        </div>
      )}
    </div>
  )
}

function Toggle({ label, on, onClick }) {
  return (
    <button onClick={onClick} style={{ ...smallButtonStyle, borderColor: on ? '#34d39955' : '#1e293b', color: on ? '#34d399' : '#7b8aa5' }}>
      <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: 99, background: on ? '#34d399' : '#f59e0b', marginRight: 5 }} />
      {label}
    </button>
  )
}

function AssistantPanel({ detected, suggested, analysis, countdown, onRegenerate, onDismiss }) {
  const [error, setError] = useState('')

  const target = detected && {
    observedIdentity: detected.appIdentity,
    expectedProcessId: detected.process?.pid,
    expectedAutomationId: detected.control?.automationId,
  }

  async function insert() {
    setError('')
    const res = await invoke('desktop/insert-generated', { password: suggested, ...target })
    // A refusal here is the safety mechanism working (window/process/control
    // changed since detection, or the control has no settable UIA value) —
    // surface it plainly rather than failing silently.
    if (!res.ok) setError(res.error === 'locked' ? 'Vault is locked.' : `Insert refused: ${res.error}`)
  }

  async function copy() {
    setError('')
    const res = await invoke('desktop/copy-generated', { password: suggested })
    if (!res.ok) setError(`Copy failed: ${res.error}`)
  }

  async function save() {
    setError('')
    const res = await invoke('desktop/create-credential', {
      app: detected.window?.title || detected.process?.processName || 'Desktop application',
      username: '',
      password: suggested,
      appIdentity: detected.appIdentity,
    })
    if (!res.ok) setError(`Save failed: ${res.error ?? res.errors?.join('; ')}`)
  }

  if (!detected) {
    return (
      <Card>
        <p style={{ color: '#7b8aa5', fontSize: 12, textAlign: 'center', padding: '20px 0' }}>
          Waiting for a signup or password-change field in a supported application…
        </p>
      </Card>
    )
  }

  return (
    <Card>
      <div style={{ fontSize: 11, color: '#7b8aa5', marginBottom: 6 }}>
        Detected: <strong style={{ color: '#e8eefc' }}>{detected.classification}</strong>
        {' · confidence '}{Math.round(detected.confidence * 100)}%
      </div>
      <div style={{ fontFamily: 'ui-monospace, monospace', fontSize: 12, background: '#070b14', border: '1px solid #1e293b', borderRadius: 6, padding: 8, wordBreak: 'break-all', marginBottom: 8 }}>
        {suggested ?? '…'}
      </div>
      {analysis && (
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10.5, color: '#7b8aa5', marginBottom: 8 }}>
          <strong style={{ color: levelColor(analysis.level) }}>{analysis.level?.toUpperCase()}</strong>
          <span>score {analysis.score}/100</span>
        </div>
      )}
      {countdown != null && (
        <div style={{ fontSize: 10.5, color: '#fbbf24', marginBottom: 8 }}>Clipboard clears in {countdown}s</div>
      )}
      {error && <div style={{ color: '#fb7185', fontSize: 11.5, marginBottom: 8 }}>{error}</div>}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
        <button onClick={onRegenerate} style={smallButtonStyle}>Generate Again</button>
        <button style={primaryButtonStyle} onClick={insert}>Insert Password</button>
        <button style={smallButtonStyle} onClick={copy}>Copy Password</button>
        <button style={smallButtonStyle} onClick={save}>Save to Vault</button>
        <button style={{ ...smallButtonStyle, background: 'transparent', color: '#7b8aa5' }} onClick={onDismiss}>Dismiss</button>
      </div>
    </Card>
  )
}

function CredentialList({ detected }) {
  const [items, setItems] = useState([])
  useEffect(() => { invoke('desktop/list-credentials').then((r) => setItems(r.ok ? r.items : [])) }, [])

  return (
    <Card>
      {items.length === 0 && <p style={{ color: '#7b8aa5', fontSize: 12 }}>No saved desktop credentials yet.</p>}
      {items.map((i) => (
        <div key={i.id} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #1e293b' }}>
          <div>
            <div style={{ fontWeight: 600 }}>{i.app}</div>
            <div style={{ fontSize: 11, color: '#7b8aa5' }}>{i.username}</div>
          </div>
          <button style={smallButtonStyle} onClick={() => invoke('desktop/copy-credential', { id: i.id })}>Copy</button>
        </div>
      ))}
      <p style={{ fontSize: 10.5, color: '#4d5f7a', marginTop: 8 }}>
        Manual fallback: open the target app, click Copy above, then paste — used whenever automatic
        detection is unavailable for that application.
      </p>
    </Card>
  )
}

function AppRules({ policy, onChange }) {
  const [appKey, setAppKey] = useState('')
  if (!policy) return null
  const entries = Object.entries(policy.perAppRules ?? {})

  return (
    <Card>
      <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
        <input value={appKey} onChange={(e) => setAppKey(e.target.value)} placeholder="process name or package family ID" style={{ ...fieldStyle, marginBottom: 0, flex: 1 }} />
        <button style={smallButtonStyle} onClick={async () => { await invoke('desktop/set-app-rule', { appKey, rule: 'deny' }); setAppKey(''); onChange() }}>Deny</button>
      </div>
      {entries.length === 0 && <p style={{ color: '#7b8aa5', fontSize: 12 }}>No per-application rules yet — every supported app is allowed.</p>}
      {entries.map(([key, rule]) => (
        <div key={key} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid #1e293b', fontSize: 12 }}>
          <span>{key}</span>
          <span style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <span style={{ color: rule === 'deny' ? '#fb7185' : '#34d399' }}>{rule}</span>
            <button style={smallButtonStyle} onClick={async () => { await invoke('desktop/clear-app-rule', { appKey: key }); onChange() }}>Remove</button>
          </span>
        </div>
      ))}
    </Card>
  )
}

function Card({ children }) {
  return <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 10, padding: 12 }}>{children}</div>
}

function levelColor(level) {
  return { critical: '#f43f5e', weak: '#fb7185', fair: '#f59e0b', strong: '#38bdf8', elite: '#34d399' }[level] ?? '#38bdf8'
}

const fieldStyle = { display: 'block', width: '100%', marginBottom: 8, padding: 8, background: '#0d1424', border: '1px solid #1e293b', borderRadius: 6, color: '#e8eefc', font: 'inherit' }
const primaryButtonStyle = { font: 'inherit', cursor: 'pointer', borderRadius: 6, padding: '7px 10px', border: 'none', background: 'linear-gradient(#38bdf8,#0ea5e9)', color: '#061019', fontWeight: 600 }
const smallButtonStyle = { font: 'inherit', cursor: 'pointer', borderRadius: 6, padding: '6px 9px', fontSize: 11.5, border: '1px solid #1e293b', background: '#131c30', color: '#e8eefc' }
