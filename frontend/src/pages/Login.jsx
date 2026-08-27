import { useEffect, useState } from 'react'
import QRCode from 'qrcode'
import {
  AlertCircle, Check, Clipboard, KeyRound, Loader2, Lock, LogOut,
  QrCode, ShieldCheck, Smartphone, User, UserPlus,
} from 'lucide-react'
import { APP, CRYPTO } from '../lib/config'
import {
  confirmAuthenticator, currentAccount, logoutAccount, registerAccount,
  startAccountLogin, verifyAuthenticator, verifyRecoveryCode,
} from '../lib/auth'
import { hasLocalVault, MIN_NEW_VAULT_PASSWORD_LENGTH, prepareVault, recoverVault, unlock, enterDemo } from '../lib/vault'

const waitForPaint = () => new Promise((resolve) => setTimeout(resolve, 60))

export default function Login() {
  const [stage, setStage] = useState('checking')
  const [mode, setMode] = useState('login')
  const [account, setAccount] = useState(null)
  const [username, setUsername] = useState('')
  const [name, setName] = useState('')
  const [accountPassword, setAccountPassword] = useState('')
  const [masterPassword, setMasterPassword] = useState('')
  const [confirmMaster, setConfirmMaster] = useState('')
  const [vaultRecoveryKey, setVaultRecoveryKey] = useState('')
  const [useVaultRecovery, setUseVaultRecovery] = useState(false)
  const [code, setCode] = useState('')
  const [challengeToken, setChallengeToken] = useState('')
  const [enrollment, setEnrollment] = useState(null)
  const [qrDataUrl, setQrDataUrl] = useState('')
  const [recoveryCodes, setRecoveryCodes] = useState([])
  const [useRecovery, setUseRecovery] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [lastDemoStatus, setLastDemoStatus] = useState(null)

  useEffect(() => {
    currentAccount()
      .then(async (user) => {
        if (user) {
          const prepared = await prepareVault(user)
          setAccount(user); setUsername(user.username); setStage('vault')
          if (!prepared.ok) setError(prepared.error)
        }
        else setStage('account')
      })
      .catch(() => setStage('account'))
    // Auto-enter demo when ?demo=1 is present in URL (handy for quick demos)
    try {
      const url = new URL(window.location.href)
      if (url.searchParams.get('demo') === '1') {
        // small delay so the page can finish initial paint
        setTimeout(() => continueAsGuest(), 60)
      }
    } catch (err) { /* ignore in non-browser tests */ }
  }, [])

  async function run(action) {
    if (busy) return null
    setBusy(true)
    setError('')
    try {
      return await action()
    } catch (err) {
      console.error('run() caught', err)
      const msg = err?.message || String(err) || 'Internal error'
      setError(msg)
      return { ok: false, error: msg }
    } finally { setBusy(false) }
  }

  async function submitAccount(e) {
    e.preventDefault()
    const result = await run(() => startAccountLogin(username, accountPassword))
    if (!result) return
    if (!result.ok) { setError(result.error); return }
    setChallengeToken(result.challengeToken)
    setCode('')
    setStage('totp')
  }

  async function submitRegistration(e) {
    e.preventDefault()
    const result = await run(() => registerAccount({ username, name, accountPassword }))
    if (!result) return
    if (!result.ok) { setError(result.error); return }
    const image = await QRCode.toDataURL(result.totp.uri, { width: 220, margin: 1, errorCorrectionLevel: 'M' })
    setEnrollment(result.totp)
    setQrDataUrl(image)
    setChallengeToken(result.challengeToken)
    setCode('')
    setStage('enroll')
  }

  async function continueAsGuest() {
    const result = await run(() => enterDemo())
    if (!result) return
    setLastDemoStatus(result)
    if (!result.ok) { setError(result.error); return }
    setError('')
    setAccount(result.user)
    setUsername(result.user.username)
    setAccountPassword('')
    setCode('')
    setStage('vault')
  }

  async function submitTotp(e) {
    e.preventDefault()
    const result = await run(() => (
      useRecovery
        ? verifyRecoveryCode(challengeToken, code)
        : verifyAuthenticator(challengeToken, code)
    ))
    if (!result) return
    if (!result.ok) { setError(result.error); return }
    const prepared = await prepareVault(result.user)
    setAccount(result.user)
    setUsername(result.user.username)
    setAccountPassword('')
    setCode('')
    setStage('vault')
    if (!prepared.ok) setError(prepared.error)
  }

  async function confirmEnrollment(e) {
    e.preventDefault()
    const result = await run(() => confirmAuthenticator(challengeToken, code))
    if (!result) return
    if (!result.ok) { setError(result.error); return }
    setAccount(result.user)
    setRecoveryCodes(result.recoveryCodes)
    setAccountPassword('')
    setCode('')
    setStage('recovery')
  }

  async function finishEnrollment() {
    const prepared = await run(() => prepareVault(account))
    if (!prepared) return
    if (!prepared.ok) { setError(prepared.error); return }
    setStage('vault')
  }

  async function unlockVault(e) {
    e.preventDefault()
    if (confirmMaster && masterPassword !== confirmMaster) {
      setError('Vault master passwords do not match')
      return
    }
    const result = await run(async () => {
      await waitForPaint()
      return useVaultRecovery
        ? recoverVault(account.username, vaultRecoveryKey, masterPassword, account)
        : unlock(account.username, masterPassword, account)
    })
    if (!result) return
    if (!result.ok) setError(result.error)
  }

  async function signOut() {
    await run(logoutAccount)
    setAccount(null)
    setMasterPassword('')
    setConfirmMaster('')
    setStage('account')
  }

  if (stage === 'checking') {
    return <Centered><Loader2 size={24} className="animate-spin text-sky-400" /></Centered>
  }

  return (
    <div className="relative z-10 grid min-h-full place-items-center p-6">
      <div className="fade-up w-full max-w-[430px]">
        <Brand />

        <div className="rounded-2xl border border-[#1e293b] bg-[#0d1424]/90 p-6 shadow-2xl shadow-black/40 backdrop-blur">
          {stage === 'account' && (
            <>
              <div className="mb-5 grid grid-cols-2 gap-2 rounded-lg bg-[#070b14] p-1">
                <ModeButton active={mode === 'login'} onClick={() => { setMode('login'); setError('') }}>Sign in</ModeButton>
                <ModeButton active={mode === 'register'} onClick={() => { setMode('register'); setError('') }}>Create account</ModeButton>
              </div>
              <div className="mb-3 text-center">
                <button type="button" onClick={continueAsGuest} className="text-[12px] text-sky-300 hover:text-sky-200">Continue as guest</button>
              </div>
              {lastDemoStatus && (
                <div className="mb-3 text-center text-[12px] text-amber-200">
                  Demo status: {typeof lastDemoStatus === 'string' ? lastDemoStatus : JSON.stringify(lastDemoStatus)}
                </div>
              )}
              {mode === 'login'
                ? <AccountLogin {...{ username, setUsername, accountPassword, setAccountPassword, busy, error, submitAccount }} />
                : <Registration {...{ username, setUsername, name, setName, accountPassword, setAccountPassword, busy, error, submitRegistration }} />}
            </>
          )}

          {stage === 'totp' && (
            <TotpForm
              title="Second-factor verification"
              description={useRecovery ? 'Enter one unused recovery code.' : 'Enter the current six-digit code from Google Authenticator.'}
              {...{ code, setCode, busy, error }}
              submit={submitTotp}
              recovery={useRecovery}
              toggleRecovery={() => { setUseRecovery((value) => !value); setCode(''); setError('') }}
              back={() => { setStage('account'); setCode(''); setError('') }}
            />
          )}

          {stage === 'enroll' && (
            <form onSubmit={confirmEnrollment}>
              <StepTitle icon={QrCode} title="Connect Google Authenticator" />
              <p className="mb-4 text-[12px] leading-5 text-[#7b8aa5]">
                Scan this QR code, then enter the current code to prove enrollment. The seed is encrypted by the server and will not be shown again.
              </p>
              {qrDataUrl && <img src={qrDataUrl} alt="Google Authenticator enrollment QR code" className="mx-auto mb-3 rounded-xl bg-white p-2" />}
              <div className="mb-4 break-all rounded-lg border border-[#1e293b] bg-[#070b14] p-3 font-mono text-[11px] text-[#9fb0c9]">
                Manual key: {enrollment?.secret}
              </div>
              <CodeInput value={code} onChange={setCode} />
              <ErrorMessage error={error} />
              <Primary disabled={busy || code.length !== 6} busy={busy}>Confirm authenticator</Primary>
            </form>
          )}

          {stage === 'recovery' && (
            <div>
              <StepTitle icon={ShieldCheck} title="Save recovery codes" />
              <p className="mb-4 text-[12px] leading-5 text-[#7b8aa5]">
                Each code replaces TOTP once. Store them offline; AEGIS stores only keyed hashes and cannot show them again.
              </p>
              <div className="grid grid-cols-2 gap-2 rounded-xl border border-amber-400/30 bg-amber-400/5 p-3 font-mono text-[11px] text-amber-100">
                {recoveryCodes.map((entry) => <span key={entry}>{entry}</span>)}
              </div>
              <button
                type="button"
                onClick={() => navigator.clipboard?.writeText(recoveryCodes.join('\n'))}
                className="mt-3 flex items-center gap-2 text-[12px] text-sky-300 hover:text-sky-200"
              >
                <Clipboard size={13} /> Copy once
              </button>
              <ErrorMessage error={error} />
              <Primary onClick={finishEnrollment} busy={busy}><Check size={14} />I stored these safely</Primary>
            </div>
          )}

          {stage === 'vault' && (
            <form onSubmit={unlockVault}>
              <div className="mb-4 flex items-start justify-between gap-3">
                <StepTitle icon={Lock} title="Unlock encrypted vault" />
                <button type="button" onClick={signOut} className="flex items-center gap-1 text-[11px] text-[#7b8aa5] hover:text-rose-300">
                  <LogOut size={12} /> Sign out
                </button>
              </div>
              <div className="mb-4 rounded-lg border border-emerald-400/20 bg-emerald-400/5 px-3 py-2 text-[11px] leading-5 text-emerald-200">
                Account verified as <strong>{account?.username}</strong>. Your separate vault master password stays on this device and is never sent to the authentication server.
              </div>
              {useVaultRecovery && (
                <Field icon={ShieldCheck} label="Vault recovery key">
                  <TextInput value={vaultRecoveryKey} onChange={setVaultRecoveryKey} autoComplete="off" placeholder="AEGIS-…" />
                </Field>
              )}
              <Field icon={KeyRound} label={(useVaultRecovery || !hasLocalVault(account?.username)) ? `New vault master password (${MIN_NEW_VAULT_PASSWORD_LENGTH}+ characters)` : 'Vault master password'}>
                <PasswordInput value={masterPassword} onChange={setMasterPassword} autoComplete="off" />
              </Field>
              {(!hasLocalVault(account?.username) || useVaultRecovery) && (
                <Field icon={KeyRound} label={useVaultRecovery ? 'Confirm new vault master password' : 'Confirm new vault master password'}>
                  <PasswordInput value={confirmMaster} onChange={setConfirmMaster} autoComplete="off" />
                </Field>
              )}
              <ErrorMessage error={error} />
              <Primary disabled={busy || !masterPassword || (useVaultRecovery && !vaultRecoveryKey) || ((!hasLocalVault(account?.username) || useVaultRecovery) && (masterPassword.length < MIN_NEW_VAULT_PASSWORD_LENGTH || !confirmMaster || masterPassword !== confirmMaster))} busy={busy}>
                {busy ? `Deriving key — ${CRYPTO.iterations.toLocaleString()} iterations…` : (useVaultRecovery ? 'Recover and rotate vault keys' : 'Unlock vault')}
              </Primary>
              {hasLocalVault(account?.username) && (
                <button
                  type="button"
                  onClick={() => { setUseVaultRecovery((value) => !value); setError(''); setMasterPassword(''); setConfirmMaster('') }}
                  className="mt-3 w-full text-center text-[11px] text-sky-300 hover:text-sky-200"
                >
                  {useVaultRecovery ? 'Use vault master password' : 'Lost vault master password? Use recovery key'}
                </button>
              )}
              <p className="mt-3 text-[10.5px] leading-4 text-[#53647e]">
                Login grants access only to encrypted data. Decryption requires this independent password.
              </p>
            </form>
          )}
        </div>
      </div>
    </div>
  )
}

function AccountLogin({ username, setUsername, accountPassword, setAccountPassword, busy, error, submitAccount }) {
  return (
    <form onSubmit={submitAccount}>
      <StepTitle icon={User} title="Account sign in" />
      <Field icon={User} label="Account"><TextInput value={username} onChange={setUsername} autoComplete="username" placeholder="alice" /></Field>
      <Field icon={KeyRound} label="Account password"><PasswordInput value={accountPassword} onChange={setAccountPassword} autoComplete="current-password" /></Field>
      <ErrorMessage error={error} />
      <Primary disabled={busy || !username || !accountPassword} busy={busy}>Continue to authenticator</Primary>
    </form>
  )
}

function Registration({ username, setUsername, name, setName, accountPassword, setAccountPassword, busy, error, submitRegistration }) {
  return (
    <form onSubmit={submitRegistration}>
      <StepTitle icon={UserPlus} title="Create protected account" />
      <Field icon={User} label="Display name"><TextInput value={name} onChange={setName} autoComplete="name" placeholder="Alice Menon" /></Field>
      <Field icon={User} label="Username"><TextInput value={username} onChange={setUsername} autoComplete="username" placeholder="alice" /></Field>
      <Field icon={KeyRound} label="Account password (12+ characters)"><PasswordInput value={accountPassword} onChange={setAccountPassword} autoComplete="new-password" /></Field>
      <ErrorMessage error={error} />
      <Primary disabled={busy || !name || !username || accountPassword.length < 12} busy={busy}>Create and enroll MFA</Primary>
    </form>
  )
}

function TotpForm({ title, description, code, setCode, busy, error, submit, recovery, toggleRecovery, back }) {
  return (
    <form onSubmit={submit}>
      <StepTitle icon={Smartphone} title={title} />
      <p className="mb-4 text-[12px] leading-5 text-[#7b8aa5]">{description}</p>
      {recovery
        ? <Field icon={ShieldCheck} label="Recovery code"><TextInput value={code} onChange={setCode} autoComplete="one-time-code" placeholder="XXXXX-XXXXX-XXXXX-XXXXX" /></Field>
        : <CodeInput value={code} onChange={setCode} />}
      <ErrorMessage error={error} />
      <Primary disabled={busy || (!recovery && code.length !== 6) || (recovery && code.length < 12)} busy={busy}>Verify and continue</Primary>
      <div className="mt-3 flex justify-between text-[11px]">
        <button type="button" onClick={back} className="text-[#7b8aa5] hover:text-white">Back</button>
        <button type="button" onClick={toggleRecovery} className="text-sky-300 hover:text-sky-200">{recovery ? 'Use Authenticator' : 'Use recovery code'}</button>
      </div>
    </form>
  )
}

function CodeInput({ value, onChange }) {
  return (
    <Field icon={Smartphone} label="Six-digit code">
      <input
        value={value} onChange={(e) => onChange(e.target.value.replace(/\D/g, '').slice(0, 6))}
        inputMode="numeric" autoComplete="one-time-code" placeholder="000000"
        className="w-full bg-transparent font-mono text-lg tracking-[0.35em] text-[#e8eefc] outline-none placeholder:text-[#3d4d66]"
      />
    </Field>
  )
}

function Brand() {
  return (
    <div className="mb-7 text-center">
      <div className="mx-auto mb-3 grid h-14 w-14 place-items-center rounded-2xl bg-gradient-to-br from-sky-400 to-indigo-500 shadow-xl shadow-sky-500/25">
        <ShieldCheck size={28} className="text-[#070b14]" />
      </div>
      <h1 className="text-xl font-bold tracking-[0.2em] text-[#e8eefc]">{APP.name}</h1>
      <p className="mt-1 text-[12px] text-[#7b8aa5]">Account MFA + independent zero-knowledge vault</p>
    </div>
  )
}

function StepTitle({ icon: Icon, title }) {
  return <h2 className="mb-3 flex items-center gap-2 text-[14px] font-semibold text-[#e8eefc]"><Icon size={16} className="text-sky-400" />{title}</h2>
}

function Field({ icon: Icon, label, children }) {
  return (
    <label className="mb-3 block rounded-lg border border-[#1e293b] bg-[#070b14]/60 px-3 py-2 focus-within:border-sky-400/50">
      <span className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-[#53647e]"><Icon size={11} />{label}</span>
      {children}
    </label>
  )
}

function TextInput({ value, onChange, ...props }) {
  return <input value={value} onChange={(e) => onChange(e.target.value)} className="w-full bg-transparent text-[13px] text-[#e8eefc] outline-none placeholder:text-[#3d4d66]" {...props} />
}

function PasswordInput({ value, onChange, ...props }) {
  return <input type="password" value={value} onChange={(e) => onChange(e.target.value)} placeholder="••••••••••••" className="w-full bg-transparent font-mono text-[13px] text-[#e8eefc] outline-none placeholder:text-[#3d4d66]" {...props} />
}

function ErrorMessage({ error }) {
  if (!error) return null
  return <div className="mt-3 flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-[12px] text-rose-300"><AlertCircle size={14} className="shrink-0" />{error}</div>
}

function Primary({ busy, children, className = '', ...props }) {
  return (
    <button
      type={props.onClick ? 'button' : 'submit'} {...props}
      className={`mt-4 flex w-full items-center justify-center gap-2 rounded-lg bg-gradient-to-b from-sky-400 to-sky-500 py-2.5 text-[13px] font-semibold text-[#061019] shadow-lg shadow-sky-500/20 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-35 disabled:shadow-none ${className}`}
    >
      {busy && <Loader2 size={15} className="animate-spin" />}{children}
    </button>
  )
}

function ModeButton({ active, children, ...props }) {
  return <button type="button" {...props} className={`rounded-md px-3 py-2 text-[12px] transition ${active ? 'bg-[#17233a] text-sky-300' : 'text-[#64748b] hover:text-white'}`}>{children}</button>
}

function Centered({ children }) {
  return <div className="grid min-h-full place-items-center">{children}</div>
}
