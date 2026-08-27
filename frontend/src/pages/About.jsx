import { ShieldCheck, KeyRound, Lock, Eye, Clipboard, Timer, Fingerprint, ScrollText, Layers, Cpu } from 'lucide-react'
import { APP, CRYPTO } from '../lib/config'
import { Card } from '../components/ui'

const FLOW = [
  { n: '01', t: 'Account authentication', d: 'An Argon2id-hashed account password plus a fresh Google Authenticator code proves account control. It grants no vault decryption key.' },
  { n: '02', t: 'Separate vault master password', d: `The client applies ${CRYPTO.kdf} with a 128-bit random salt and ${CRYPTO.iterations.toLocaleString()} iterations. This password never reaches the authentication server.` },
  { n: '03', t: 'Random vault key unwrapped', d: 'The derived key unwraps a random AES-256 vault data key, which is imported as non-extractable in WebCrypto.' },
  { n: '04', t: 'Context-bound encryption', d: `Each secret is sealed with ${CRYPTO.cipher}, a fresh 96-bit IV, and authenticated user/item context. Tampering or moving ciphertext to another record fails.` },
  { n: '05', t: 'Only encrypted data persists', d: 'Storage contains wrapped keys, ciphertext, salts, IVs, and metadata — never the vault master password, recovery key, or plaintext.' },
  { n: '06', t: 'User-held recovery', d: 'A separately wrapped recovery key is shown once. Using it rotates both the master-password wrapper and the recovery key.' },
  { n: '07', t: 'Key dies on lock', d: 'Locking, idle timeout, or closing the tab drops the only in-memory reference to the random vault key.' },
]

const CONTROLS = [
  { icon: Lock,        t: 'Zero-knowledge storage',  d: 'Administrators manage accounts and policy but cannot decrypt any credential.' },
  { icon: Timer,       t: 'Idle auto-lock',           d: 'The key is discarded after the configured idle period, not merely hidden behind a screen.' },
  { icon: Clipboard,   t: 'Clipboard auto-clear',     d: 'Copied secrets are wiped after a countdown, and only if the clipboard still holds our value.' },
  { icon: Eye,         t: 'Reveal auditing',          d: 'Every plaintext reveal and copy is written to the tamper-evident audit trail.' },
  { icon: Fingerprint, t: 'k-anonymous breach check', d: 'Only the first five characters of a SHA-1 hash leave the device; matching happens locally.' },
  { icon: KeyRound,    t: 'CSPRNG generation',        d: 'Passwords come from crypto.getRandomValues with rejection sampling to eliminate modulo bias.' },
  { icon: ScrollText,  t: 'Policy enforcement',       d: 'Non-compliant passwords are rejected client-side before encryption, and every policy change is logged.' },
  { icon: ShieldCheck, t: 'Reuse detection',          d: 'Duplicate passwords are detected after local decryption — the server never learns which secrets match.' },
]

export default function About() {
  return (
    <div className="mx-auto max-w-4xl space-y-5">
      <Card>
        <div className="flex items-start gap-4">
          <div className="grid h-12 w-12 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-sky-400 to-indigo-500">
            <ShieldCheck size={24} className="text-[#070b14]" />
          </div>
          <div>
            <h2 className="text-lg font-bold tracking-[0.18em] text-[#e8eefc]">{APP.name}</h2>
            <p className="text-[13px] text-[#7b8aa5]">{APP.tagline}</p>
            <p className="mt-3 max-w-2xl text-[13px] leading-relaxed text-[#e8eefc]">
              Most password managers ask you to trust the operator. {APP.name} removes that requirement:
              encryption and decryption happen entirely in the browser, so the server — and anyone who
              compromises it — holds nothing but ciphertext. Administrators keep the controls they genuinely
              need (provisioning, policy, rotation, audit) and none of the access they do not.
            </p>
          </div>
        </div>
      </Card>

      <Card title="How a secret is protected">
        <ol className="space-y-3">
          {FLOW.map((s) => (
            <li key={s.n} className="flex gap-3">
              <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-lg border border-sky-400/25 bg-sky-400/10 font-mono text-[11px] font-semibold text-sky-300">
                {s.n}
              </span>
              <div>
                <div className="text-[13px] font-medium text-[#e8eefc]">{s.t}</div>
                <p className="text-[12px] leading-relaxed text-[#7b8aa5]">{s.d}</p>
              </div>
            </li>
          ))}
        </ol>
      </Card>

      <Card title="Security controls">
        <div className="grid gap-3 sm:grid-cols-2">
          {CONTROLS.map((c) => (
            <div key={c.t} className="flex items-start gap-3 rounded-lg border border-[#1e293b] bg-[#131c30]/50 p-3">
              <c.icon size={16} className="mt-0.5 shrink-0 text-sky-400" />
              <div>
                <div className="text-[12.5px] font-medium text-[#e8eefc]">{c.t}</div>
                <div className="text-[11.5px] leading-relaxed text-[#7b8aa5]">{c.d}</div>
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Threat model">
        <div className="space-y-2.5 text-[12.5px] leading-relaxed">
          <Threat ok label="Database dump / backend compromise">
            Attacker obtains ciphertext and a wrapped random vault key. Account credentials do not unwrap it;
            the independent vault password still costs {CRYPTO.iterations.toLocaleString()} PBKDF2 iterations per guess.
          </Threat>
          <Threat ok label="Stolen account session">
            The account can download encrypted data, but decryption and vault mutations remain locked until the separate master password unwraps the random key and write authorization locally.
          </Threat>
          <Threat ok label="Malicious or curious administrator">
            Full application and database access grants no plaintext. Every administrative action is logged.
          </Threat>
          <Threat ok label="Lost or stolen unlocked device">
            Idle auto-lock discards the key; the clipboard self-clears; reveals are audited.
          </Threat>
          <Threat ok label="Credential stuffing against stored accounts">
            Breach checks and reuse detection surface exposed passwords before they are exploited.
          </Threat>
          <Threat label="Compromised client / malicious browser extension">
            Out of scope. Any zero-knowledge design assumes an honest client at the moment of unlock — this is
            why we ship a strict CSP and never load third-party scripts.
          </Threat>
        </div>
      </Card>

      <Card title="Stack">
        <div className="grid gap-3 sm:grid-cols-2">
          <Row icon={Layers} k="Frontend" v="React 19 · Vite · Tailwind v4 · Recharts" />
          <Row icon={Cpu} k="Cryptography" v="Argon2id account hash · PBKDF2 wrapping · AES-256-GCM vault" />
          <Row icon={ShieldCheck} k="Backend" v="FastAPI · TOTP MFA · versioned ciphertext sync · write proof" />
          <Row icon={Fingerprint} k="Breach data" v="HIBP range API via k-anonymity, offline fallback" />
        </div>
      </Card>
    </div>
  )
}

function Threat({ ok, label, children }) {
  return (
    <div className={`rounded-lg border p-3 ${ok ? 'border-emerald-400/25 bg-emerald-400/[0.06]' : 'border-amber-400/25 bg-amber-400/[0.06]'}`}>
      <div className={`mb-0.5 flex items-center gap-2 font-medium ${ok ? 'text-emerald-300' : 'text-amber-300'}`}>
        <span className="font-mono text-[10px]">{ok ? 'MITIGATED' : 'ACCEPTED'}</span>
        <span className="text-[#e8eefc]">{label}</span>
      </div>
      <p className="text-[11.5px] leading-relaxed text-[#7b8aa5]">{children}</p>
    </div>
  )
}

function Row({ icon: Icon, k, v }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-[#1e293b] bg-[#131c30]/50 p-3">
      <Icon size={16} className="mt-0.5 shrink-0 text-sky-400" />
      <div>
        <div className="text-[12px] font-medium text-[#e8eefc]">{k}</div>
        <div className="text-[11.5px] text-[#7b8aa5]">{v}</div>
      </div>
    </div>
  )
}
