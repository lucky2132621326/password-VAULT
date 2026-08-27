import { useMemo, useState } from 'react'
import { Search, Download, ScrollText, ShieldAlert, Info, AlertTriangle } from 'lucide-react'
import { getAudit } from '../lib/vault'
import { useVault } from '../lib/hooks'
import { Card, Kpi, Empty } from '../components/ui'

const LEVELS = ['all', 'info', 'warn', 'critical']

const TONE = {
  info:     { icon: Info,          cls: 'text-sky-300',     dot: '#38bdf8' },
  warn:     { icon: AlertTriangle, cls: 'text-amber-300',   dot: '#f59e0b' },
  critical: { icon: ShieldAlert,   cls: 'text-rose-300',    dot: '#f43f5e' },
}

export default function AdminAudit() {
  const { db } = useVault()
  const log = getAudit()
  const [q, setQ] = useState('')
  const [level, setLevel] = useState('all')

  const filtered = useMemo(() => {
    const n = q.toLowerCase()
    return log.filter(
      (e) =>
        (level === 'all' || e.severity === level) &&
        (e.action.toLowerCase().includes(n) ||
          e.actor.toLowerCase().includes(n) ||
          (e.detail ?? '').toLowerCase().includes(n)),
    )
  }, [log, q, level])

  function exportLog() {
    const head = 'timestamp,actor,role,action,severity,detail,ip\n'
    const body = filtered
      .map((e) => [e.ts, e.actor, e.role, e.action, e.severity, `"${(e.detail ?? '').replace(/"/g, "'")}"`, e.ip].join(','))
      .join('\n')
    const url = URL.createObjectURL(new Blob([head + body], { type: 'text/csv' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'aegis-audit-log.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  const warns = log.filter((e) => e.severity === 'warn').length
  const fails = log.filter((e) => e.action === 'auth.failed' || e.action === 'vault.unlock_failed').length
  const reveals = log.filter((e) => e.action === 'item.revealed').length

  return (
    <div className="space-y-5">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi icon={ScrollText}  label="Total Events"    value={log.length}  sub="this session" />
        <Kpi icon={AlertTriangle} label="Warnings"      value={warns}       sub="elevated actions" tone="warn" />
        <Kpi icon={ShieldAlert} label="Failed Vault Unlocks" value={fails} sub="wrong vault password" tone="danger" />
        <Kpi icon={Info}        label="Secret Reveals"  value={reveals}     sub="plaintext displayed" />
      </div>

      <Card
        title={`Audit Trail (${filtered.length})`}
        right={
          <button
            onClick={exportLog}
            className="inline-flex items-center gap-1.5 rounded-md border border-[#1e293b] px-2.5 py-1 text-[11px] text-[#7b8aa5] transition hover:border-sky-400/40 hover:text-sky-300"
          >
            <Download size={12} /> Export CSV
          </button>
        }
      >
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <div className="relative min-w-[220px] flex-1">
            <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[#4d5f7a]" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Filter by action, actor, or detail…"
              className="w-full rounded-lg border border-[#1e293b] bg-[#070b14] py-2 pl-9 pr-3 text-[12.5px] text-[#e8eefc] outline-none placeholder:text-[#3d4d66] focus:border-sky-400/50"
            />
          </div>
          <div className="flex gap-1">
            {LEVELS.map((l) => (
              <button
                key={l}
                onClick={() => setLevel(l)}
                className={`rounded-md border px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider transition ${
                  level === l
                    ? 'border-sky-400/40 bg-sky-400/10 text-sky-300'
                    : 'border-[#1e293b] text-[#7b8aa5] hover:text-[#e8eefc]'
                }`}
              >
                {l}
              </button>
            ))}
          </div>
        </div>

        {filtered.length === 0 ? (
          <Empty icon={ScrollText} title="No matching events" />
        ) : (
          <ul className="divide-y divide-[#1e293b]">
            {filtered.map((e) => {
              const t = TONE[e.severity] ?? TONE.info
              return (
                <li key={e.id} className="flex items-start gap-3 py-2.5">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: t.dot }} />
                  <span className="w-[68px] shrink-0 font-mono text-[10.5px] text-[#4d5f7a]">
                    {new Date(e.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </span>
                  <span className={`w-[110px] shrink-0 font-mono text-[11px] ${t.cls}`}>{e.action}</span>
                  <span className="min-w-0 flex-1 text-[12px] text-[#e8eefc]">{e.detail}</span>
                  <span className="hidden shrink-0 font-mono text-[10.5px] text-[#7b8aa5] sm:block">
                    {e.actor}
                    <span className="text-[#3d4d66]"> · {e.role}</span>
                  </span>
                </li>
              )
            })}
          </ul>
        )}
      </Card>
    </div>
  )
}
