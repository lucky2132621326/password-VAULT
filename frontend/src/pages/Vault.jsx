import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Search, Plus, Eye, EyeOff, Copy, Check, Star, Pencil, Trash2, ExternalLink, KeySquare, ShieldAlert, Wand2,
} from 'lucide-react'
import { CATEGORIES } from '../lib/config'
import { decryptAll, deleteItem, toggleFavorite } from '../lib/vault'
import { useVault, useSecureClipboard } from '../lib/hooks'
import { analyze } from '../lib/strength'
import { Card, Empty } from '../components/ui'
import { StrengthBadge } from '../components/StrengthMeter'
import AppLogo from '../components/AppLogo'
import ItemModal from '../components/ItemModal'

export default function Vault() {
  const { db } = useVault()
  const [items, setItems] = useState([])
  const [q, setQ] = useState('')
  const [cat, setCat] = useState('All')
  const [revealed, setRevealed] = useState({})
  const [editing, setEditing] = useState(null)
  const [confirmingDelete, setConfirmingDelete] = useState(null)
  const { copy, copiedId, remaining } = useSecureClipboard()

  // Decrypt the whole vault once per change — needed for reuse detection anyway.
  const refresh = useCallback(() => { decryptAll().then(setItems) }, [])
  useEffect(() => { refresh() }, [refresh, db.items.length])

  const reuseMap = useMemo(() => {
    const counts = {}
    items.forEach((i) => { if (i.plaintext) counts[i.plaintext] = (counts[i.plaintext] ?? 0) + 1 })
    return counts
  }, [items])

  const filtered = useMemo(() => {
    const needle = q.toLowerCase()
    return items
      .filter((i) => (cat === 'All' || i.category === cat))
      .filter((i) =>
        i.app.toLowerCase().includes(needle) ||
        i.username.toLowerCase().includes(needle) ||
        (i.url ?? '').toLowerCase().includes(needle))
      .sort((a, b) => (b.favorite === a.favorite ? a.app.localeCompare(b.app) : b.favorite - a.favorite))
  }, [items, q, cat])

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[240px] flex-1">
          <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[#4d5f7a]" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search applications, usernames…"
            className="w-full rounded-lg border border-[#1e293b] bg-[#0d1424] py-2.5 pl-9 pr-3 text-[13px] text-[#e8eefc] outline-none placeholder:text-[#3d4d66] focus:border-sky-400/50"
          />
        </div>
        <button
          onClick={() => setEditing({})}
          className="inline-flex items-center gap-1.5 rounded-lg bg-gradient-to-b from-sky-400 to-sky-500 px-4 py-2.5 text-[13px] font-semibold text-[#061019] shadow-lg shadow-sky-500/20 transition hover:brightness-110"
        >
          <Plus size={15} /> Add credential
        </button>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {['All', ...CATEGORIES].map((c) => (
          <button
            key={c}
            onClick={() => setCat(c)}
            className={`rounded-md border px-2.5 py-1 text-[11.5px] transition ${
              cat === c
                ? 'border-sky-400/40 bg-sky-400/10 text-sky-300'
                : 'border-[#1e293b] text-[#7b8aa5] hover:text-[#e8eefc]'
            }`}
          >
            {c}
            {c !== 'All' && (
              <span className="ml-1 text-[#4d5f7a]">{items.filter((i) => i.category === c).length}</span>
            )}
          </button>
        ))}
      </div>

      {copiedId && (
        <div className="fade-up flex items-center gap-2 rounded-lg border border-amber-400/30 bg-amber-400/10 px-3 py-2 text-[12px] text-amber-300">
          <Copy size={13} />
          Password copied — clipboard clears in <strong className="tabular-nums">{remaining}s</strong>
        </div>
      )}

      {filtered.length === 0 ? (
        <Card>
          <Empty
            icon={KeySquare}
            title={items.length === 0 ? 'Your vault is empty' : 'Nothing matches those filters'}
            sub={items.length === 0 ? 'Add your first credential to get started' : undefined}
          />
        </Card>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {filtered.map((item) => {
            const a = analyze(item.plaintext ?? '', { reused: reuseMap[item.plaintext] > 1 ? 'another account' : null })
            const isRevealed = revealed[item.id]
            const ageDays = Math.floor((Date.now() - new Date(item.updatedAt)) / 864e5)
            return (
              <div
                key={item.id}
                className="fade-up group rounded-xl border border-[#1e293b] bg-[#0d1424]/80 p-4 backdrop-blur transition hover:border-[#2b3b57]"
              >
                <div className="flex items-start gap-3">
                  <AppLogo name={item.app} size={36} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <h3 className="truncate text-[13.5px] font-semibold text-[#e8eefc]">{item.app}</h3>
                      {item.favorite && <Star size={11} className="shrink-0 fill-amber-400 text-amber-400" />}
                    </div>
                    <p className="truncate text-[11.5px] text-[#7b8aa5]">{item.username}</p>
                  </div>
                  {item.locked ? (
                    <span className="inline-flex shrink-0 items-center gap-1 rounded-md border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-rose-300">
                      <ShieldAlert size={10} /> LOCKED
                    </span>
                  ) : (
                    <StrengthBadge level={a.level} />
                  )}
                </div>

                {item.locked ? (
                  <div className="mt-3 space-y-2 rounded-lg border border-rose-500/30 bg-rose-500/[0.07] p-2.5">
                    <p className="text-[11.5px] leading-relaxed text-rose-300">
                      Flagged {item.compromiseReason === 'admin-flag' ? 'by an administrator' : 'as compromised'}.
                      Reveal and copy are disabled until you set a new password.
                    </p>
                    <button
                      onClick={() => setEditing(item)}
                      className="flex w-full items-center justify-center gap-1.5 rounded-lg bg-gradient-to-b from-rose-400 to-rose-500 py-1.5 text-[12px] font-semibold text-[#1a0508] transition hover:brightness-110"
                    >
                      <Wand2 size={12} /> Rotate now to unlock
                    </button>
                  </div>
                ) : (
                  <div className="mt-3 flex items-center gap-1.5 rounded-lg border border-[#1e293b] bg-[#070b14] px-2.5 py-2">
                    <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-[#e8eefc]">
                      {isRevealed ? item.plaintext : '•'.repeat(Math.min(18, item.plaintext?.length ?? 12))}
                    </span>
                    <button
                      onClick={() => setRevealed((r) => ({ ...r, [item.id]: !r[item.id] }))}
                      title={isRevealed ? 'Hide' : 'Reveal'}
                      className="shrink-0 text-[#4d5f7a] transition hover:text-sky-300"
                    >
                      {isRevealed ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                    <button
                      onClick={() => copy(item.plaintext, item.id, item.app)}
                      title="Copy (auto-clears)"
                      className="shrink-0 text-[#4d5f7a] transition hover:text-sky-300"
                    >
                      {copiedId === item.id ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                    </button>
                  </div>
                )}

                {!item.locked && reuseMap[item.plaintext] > 1 && (
                  <p className="mt-2 text-[11px] text-rose-300">
                    Reused across {reuseMap[item.plaintext]} accounts
                  </p>
                )}

                <div className="mt-3 flex items-center justify-between border-t border-[#1e293b] pt-2.5">
                  <span className="text-[10.5px] text-[#4d5f7a]">
                    {item.category} · {ageDays}d old
                  </span>
                  <div className="flex items-center gap-2 opacity-60 transition group-hover:opacity-100">
                    {item.url && (
                      <a
                        href={`https://${item.url.replace(/^https?:\/\//, '')}`}
                        target="_blank"
                        rel="noreferrer noopener"
                        title="Open site"
                        className="text-[#4d5f7a] transition hover:text-sky-300"
                      >
                        <ExternalLink size={13} />
                      </a>
                    )}
                    <button onClick={async () => { const result = await toggleFavorite(item.id); if (result.ok) refresh() }} title="Favourite" className="text-[#4d5f7a] transition hover:text-amber-300">
                      <Star size={13} className={item.favorite ? 'fill-amber-400 text-amber-400' : ''} />
                    </button>
                    <button onClick={() => setEditing(item)} title="Edit" className="text-[#4d5f7a] transition hover:text-sky-300">
                      <Pencil size={13} />
                    </button>
                    <button
                      onClick={() => setConfirmingDelete(item.id)}
                      title="Delete"
                      className="text-[#4d5f7a] transition hover:text-rose-300"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                </div>

                {confirmingDelete === item.id && (
                  <div className="fade-up mt-2.5 flex items-center justify-between gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 px-2.5 py-2 text-[11.5px] text-rose-300">
                    <span>Delete {item.app}?</span>
                    <span className="flex shrink-0 gap-1.5">
                      <button
                        onClick={async () => { const result = await deleteItem(item.id); if (result.ok) { setConfirmingDelete(null); refresh() } }}
                        className="rounded-md bg-rose-500 px-2 py-1 text-[10.5px] font-semibold text-white transition hover:brightness-110"
                      >
                        Delete
                      </button>
                      <button
                        onClick={() => setConfirmingDelete(null)}
                        className="rounded-md border border-rose-400/30 px-2 py-1 text-[10.5px] text-rose-300 transition hover:bg-rose-400/10"
                      >
                        Cancel
                      </button>
                    </span>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {editing && (
        <ItemModal
          item={editing.id ? editing : null}
          existingPasswords={items}
          onClose={() => setEditing(null)}
          onSaved={refresh}
        />
      )}
    </div>
  )
}
