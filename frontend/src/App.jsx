import { useState } from 'react'
import {
  ShieldCheck, LayoutDashboard, KeySquare, Wand2, HeartPulse, Users, FileLock2,
  SlidersHorizontal, ScrollText, Info, Lock, LogOut, Timer, MessageCircle, X, ShieldAlert, Copy,
} from 'lucide-react'
import { APP } from './lib/config'
import { acknowledgeRecoveryKey, lock } from './lib/vault'
import { useVault, useAutoLock, useAlertToast } from './lib/hooks'

import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Vault from './pages/Vault'
import Generator from './pages/Generator'
import Health from './pages/Health'
import AdminUsers from './pages/AdminUsers'
import AdminRegistry from './pages/AdminRegistry'
import AdminPolicy from './pages/AdminPolicy'
import AdminAudit from './pages/AdminAudit'
import About from './pages/About'

const NAV = {
  user: [
    { id: 'dashboard', label: 'Dashboard',       icon: LayoutDashboard, el: Dashboard },
    { id: 'vault',     label: 'My Vault',        icon: KeySquare,  el: Vault },
    { id: 'generator', label: 'Generator',       icon: Wand2,      el: Generator },
    { id: 'health',    label: 'Security Health', icon: HeartPulse, el: Health },
    { id: 'about',     label: 'About',           icon: Info,       el: About },
  ],
  admin: [
    { id: 'users',    label: 'Users',          icon: Users,             el: AdminUsers },
    { id: 'registry', label: 'Vault Registry', icon: FileLock2,         el: AdminRegistry },
    { id: 'policy',   label: 'Policy',         icon: SlidersHorizontal, el: AdminPolicy },
    { id: 'audit',    label: 'Audit Log',      icon: ScrollText,        el: AdminAudit },
    { id: 'about',    label: 'About',          icon: Info,              el: About },
  ],
}

export default function App() {
  const { session } = useVault()
  if (!session) return <Login />
  return <Shell session={session} />
}

function Shell({ session }) {
  const nav = NAV[session.role]
  const [page, setPage] = useState(nav[0].id)
  const { remaining } = useAutoLock()
  const { toast, dismiss } = useAlertToast()

  const current = nav.find((n) => n.id === page) ?? nav[0]
  const Active = current.el
  const mins = Math.floor(remaining / 60)
  const secs = Math.floor(remaining % 60)
  const lockSoon = remaining < 60

  return (
    <div className="relative z-10 flex h-full">
      {/* ── Sidebar ─────────────────────────────────────────────── */}
      <aside className="flex w-[214px] shrink-0 flex-col border-r border-[#1e293b] bg-[#0a0f1c]/70 backdrop-blur">
        <div className="flex items-center gap-2.5 border-b border-[#1e293b] px-4 py-4">
          <div className="grid h-8 w-8 place-items-center rounded-lg bg-gradient-to-br from-sky-400 to-indigo-500 shadow-lg shadow-sky-500/20">
            <ShieldCheck size={17} className="text-[#070b14]" />
          </div>
          <div className="leading-tight">
            <div className="text-sm font-bold tracking-[0.18em] text-[#e8eefc]">{APP.name}</div>
            <div className="text-[9px] uppercase tracking-wider text-[#7b8aa5]">
              {session.role === 'admin' ? 'admin console' : 'credential vault'}
            </div>
          </div>
        </div>

        <nav className="flex-1 space-y-1 p-3">
          {nav.map((n) => {
            const on = page === n.id
            return (
              <button
                key={n.id}
                onClick={() => setPage(n.id)}
                className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] transition ${
                  on
                    ? 'bg-sky-400/10 font-medium text-sky-300 ring-1 ring-sky-400/25'
                    : 'text-[#7b8aa5] hover:bg-white/[0.04] hover:text-[#e8eefc]'
                }`}
              >
                <n.icon size={15} />
                {n.label}
              </button>
            )
          })}
        </nav>

        <div className="border-t border-[#1e293b] p-3">
          <div className="mb-2 flex items-center gap-2.5">
            <div
              className={`grid h-8 w-8 shrink-0 place-items-center rounded-full text-[11px] font-bold ${
                session.role === 'admin'
                  ? 'bg-indigo-400/15 text-indigo-300'
                  : 'bg-sky-400/15 text-sky-300'
              }`}
            >
              {session.name.split(' ').map((w) => w[0]).join('').slice(0, 2)}
            </div>
            <div className="min-w-0 leading-tight">
              <div className="truncate text-[12px] font-medium text-[#e8eefc]">{session.name}</div>
              <div className="text-[10px] uppercase tracking-wider text-[#7b8aa5]">{session.role}</div>
            </div>
          </div>
          <button
            onClick={() => lock('manual')}
            className="flex w-full items-center justify-center gap-1.5 rounded-lg border border-[#1e293b] py-1.5 text-[11.5px] text-[#7b8aa5] transition hover:border-rose-400/40 hover:text-rose-300"
          >
            <LogOut size={12} /> Lock vault
          </button>
          <div className="mt-2 text-center text-[9.5px] text-[#3d4d66]">
            {APP.team} · TCS TechDay
          </div>
        </div>
      </aside>

      {/* ── Main ────────────────────────────────────────────────── */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-[#1e293b] bg-[#0a0f1c]/50 px-6 py-3.5 backdrop-blur">
          <div>
            <h1 className="text-[15px] font-semibold text-[#e8eefc]">{current.label}</h1>
            <p className="text-[11px] text-[#7b8aa5]">{APP.tagline}</p>
          </div>

          <div className="flex items-center gap-2.5">
            <span
              title="AES-256-GCM key held in memory only"
              className="inline-flex items-center gap-1.5 rounded-md border border-emerald-400/30 bg-emerald-400/10 px-2.5 py-1 font-mono text-[10px] font-semibold tracking-wider text-emerald-300"
            >
              <span className="live-dot h-1.5 w-1.5 rounded-full bg-emerald-400" />
              UNLOCKED
            </span>
            <span
              title="Vault auto-locks after inactivity"
              className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 font-mono text-[10px] tabular-nums ${
                lockSoon
                  ? 'border-amber-400/40 bg-amber-400/10 text-amber-300'
                  : 'border-[#1e293b] text-[#7b8aa5]'
              }`}
            >
              <Timer size={11} />
              {String(mins).padStart(2, '0')}:{String(secs).padStart(2, '0')}
            </span>
            <button
              onClick={() => lock('manual')}
              title="Lock now"
              className="grid h-[26px] w-[26px] place-items-center rounded-md border border-[#1e293b] text-[#7b8aa5] transition hover:border-rose-400/40 hover:text-rose-300"
            >
              <Lock size={12} />
            </button>
          </div>
        </header>

        <main className="min-h-0 flex-1 overflow-y-auto p-6">
          <Active onNavigate={setPage} />
        </main>
      </div>

      {toast && (
        <div
          className={`fade-up fixed bottom-5 right-5 z-50 flex max-w-[360px] items-start gap-3 rounded-xl border p-3.5 shadow-2xl backdrop-blur ${
            toast.action === 'alert.whatsapp_sent'
              ? 'border-emerald-400/30 bg-[#0d1424]/95'
              : 'border-amber-400/30 bg-[#0d1424]/95'
          }`}
        >
          <span className={`grid h-8 w-8 shrink-0 place-items-center rounded-lg ${
            toast.action === 'alert.whatsapp_sent' ? 'bg-emerald-400/10 text-emerald-300' : 'bg-amber-400/10 text-amber-300'
          }`}>
            {toast.action === 'alert.whatsapp_sent' ? <MessageCircle size={15} /> : <ShieldAlert size={15} />}
          </span>
          <div className="min-w-0 flex-1">
            <div className="text-[12.5px] font-medium text-[#e8eefc]">
              {toast.action === 'alert.whatsapp_sent' ? 'WhatsApp alert sent' : 'Alert delivery failed'}
            </div>
            <p className="mt-0.5 text-[11.5px] leading-relaxed text-[#7b8aa5]">{toast.detail}</p>
          </div>
          <button onClick={dismiss} className="shrink-0 text-[#4d5f7a] transition hover:text-[#e8eefc]">
            <X size={14} />
          </button>
        </div>
      )}

      {session.pendingRecoveryKey && (
        <div className="fixed inset-0 z-[60] grid place-items-center bg-black/75 p-6 backdrop-blur-sm">
          <div className="w-full max-w-[500px] rounded-2xl border border-amber-400/35 bg-[#0d1424] p-6 shadow-2xl">
            <h2 className="flex items-center gap-2 text-[15px] font-semibold text-amber-200">
              <ShieldCheck size={18} /> Save your vault recovery key
            </h2>
            <p className="mt-2 text-[12px] leading-5 text-[#9fb0c9]">
              This key can decrypt your vault if the vault master password is lost. It is shown once, is never sent to the account server, and cannot be recovered by an administrator.
            </p>
            <div className="mt-4 break-all rounded-xl border border-amber-400/30 bg-[#070b14] p-4 font-mono text-[13px] leading-6 text-amber-100">
              {session.pendingRecoveryKey}
            </div>
            <button
              type="button"
              onClick={() => navigator.clipboard?.writeText(session.pendingRecoveryKey)}
              className="mt-3 flex items-center gap-2 text-[12px] text-sky-300 hover:text-sky-200"
            >
              <Copy size={13} /> Copy recovery key
            </button>
            <button
              type="button"
              onClick={acknowledgeRecoveryKey}
              className="mt-5 w-full rounded-lg bg-gradient-to-b from-sky-400 to-sky-500 py-2.5 text-[13px] font-semibold text-[#061019]"
            >
              I stored it safely
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
