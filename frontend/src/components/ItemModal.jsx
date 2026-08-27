import { useEffect, useState } from 'react'
import { X, Wand2, Eye, EyeOff, Loader2, ShieldCheck, ShieldX } from 'lucide-react'
import { CATEGORIES } from '../lib/config'
import { generatePassword, checkBreached } from '../lib/crypto'
import { analyze, checkPolicy } from '../lib/strength'
import { saveItem, getPolicy } from '../lib/vault'
import { StrengthReport } from './StrengthMeter'

export default function ItemModal({ item, initialPassword = '', existingPasswords = [], onClose, onSaved }) {
  const [form, setForm] = useState({
    id: item?.id, app: item?.app ?? '', username: item?.username ?? '',
    url: item?.url ?? '', category: item?.category ?? 'Other',
    password: item?.plaintext ?? initialPassword,
  })
  const [show, setShow] = useState(!item)
  const [breached, setBreached] = useState(null)
  const [checking, setChecking] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState('')

  const policy = getPolicy()
  const reusedFor = existingPasswords.find(
    (p) => p.plaintext === form.password && p.id !== form.id && form.password,
  )?.app

  const analysis = analyze(form.password, { policy, breached, reused: reusedFor })
  const verdict = checkPolicy(form.password, policy, { breached, reused: reusedFor })

  // Debounced breach lookup — k-anonymous, only 5 hash chars leave the device.
  useEffect(() => {
    if (!form.password) { setBreached(null); return }
    setChecking(true)
    const t = setTimeout(async () => {
      setBreached(await checkBreached(form.password))
      setChecking(false)
    }, 600)
    return () => { clearTimeout(t); setChecking(false) }
  }, [form.password])

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }))

  async function save() {
    if (!form.app || !form.password || saving) return
    setSaving(true)
    setSaveError('')
    const result = await saveItem(form)
    setSaving(false)
    if (!result.ok) { setSaveError(result.error); return }
    onSaved?.()
    onClose()
  }

  return (
    <div
      className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="fade-up max-h-[90vh] w-full max-w-[720px] overflow-y-auto rounded-2xl border border-[#1e293b] bg-[#0d1424] shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="sticky top-0 flex items-center justify-between border-b border-[#1e293b] bg-[#0d1424] px-5 py-3.5">
          <h3 className="text-[14px] font-semibold text-[#e8eefc]">
            {item ? `Edit — ${item.app}` : 'Add credential'}
          </h3>
          <button onClick={onClose} className="text-[#7b8aa5] transition hover:text-[#e8eefc]">
            <X size={17} />
          </button>
        </div>

        <div className="grid gap-5 p-5 md:grid-cols-2">
          <div className="space-y-3">
            <Input label="Application" value={form.app} onChange={set('app')} placeholder="Gmail" autoFocus />
            <Input label="Username / email" value={form.username} onChange={set('username')} placeholder="you@example.com" />
            <Input label="URL" value={form.url} onChange={set('url')} placeholder="mail.google.com" />

            <label className="block">
              <span className="mb-1.5 block text-[10px] font-medium uppercase tracking-wider text-[#7b8aa5]">Category</span>
              <select
                value={form.category}
                onChange={set('category')}
                className="w-full rounded-lg border border-[#1e293b] bg-[#070b14] px-3 py-2.5 text-[13px] text-[#e8eefc] outline-none focus:border-sky-400/50"
              >
                {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </label>

            <label className="block">
              <span className="mb-1.5 block text-[10px] font-medium uppercase tracking-wider text-[#7b8aa5]">Password</span>
              <div className="flex items-center gap-2 rounded-lg border border-[#1e293b] bg-[#070b14] px-3 py-2.5 focus-within:border-sky-400/50">
                <input
                  type={show ? 'text' : 'password'}
                  value={form.password}
                  onChange={set('password')}
                  placeholder="Generate or type"
                  spellCheck={false}
                  className="min-w-0 flex-1 bg-transparent font-mono text-[13px] text-[#e8eefc] outline-none placeholder:text-[#3d4d66]"
                />
                <button type="button" onClick={() => setShow(!show)} className="shrink-0 text-[#4d5f7a] transition hover:text-sky-300">
                  {show ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </label>

            <button
              type="button"
              onClick={() => { setForm((f) => ({ ...f, password: generatePassword({ length: 20 }) })); setShow(true) }}
              className="flex w-full items-center justify-center gap-2 rounded-lg border border-sky-400/30 bg-sky-400/10 py-2 text-[12.5px] font-medium text-sky-300 transition hover:bg-sky-400/15"
            >
              <Wand2 size={14} /> Generate strong password
            </button>

            <div
              className={`flex items-start gap-2 rounded-lg border px-3 py-2.5 text-[11.5px] ${
                verdict.pass
                  ? 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300'
                  : 'border-amber-400/30 bg-amber-400/10 text-amber-300'
              }`}
            >
              {verdict.pass ? <ShieldCheck size={14} className="mt-px shrink-0" /> : <ShieldX size={14} className="mt-px shrink-0" />}
              <div>
                <strong>{verdict.pass ? 'Meets org policy' : 'Fails org policy'}</strong>
                {!verdict.pass && (
                  <ul className="mt-1 space-y-0.5">
                    {verdict.fails.map((f, i) => <li key={i}>· {f}</li>)}
                  </ul>
                )}
              </div>
            </div>

            <div className="flex gap-2 pt-1">
              <button
                onClick={save}
                disabled={!form.app || !form.password || saving}
                className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-gradient-to-b from-sky-400 to-sky-500 py-2.5 text-[13px] font-semibold text-[#061019] transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-35"
              >
                {saving && <Loader2 size={14} className="animate-spin" />}
                {saving ? 'Encrypting…' : 'Encrypt & save'}
              </button>
              <button
                onClick={onClose}
                className="rounded-lg border border-[#1e293b] px-4 text-[13px] text-[#7b8aa5] transition hover:text-[#e8eefc]"
              >
                Cancel
              </button>
            </div>
            {saveError && <p className="text-[11.5px] text-rose-300">{saveError}</p>}
          </div>

          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="text-[10px] uppercase tracking-wider text-[#7b8aa5]">Live analysis</span>
              {checking && <Loader2 size={12} className="animate-spin text-sky-400" />}
            </div>
            {form.password ? (
              <StrengthReport analysis={analysis} breached={breached} dense />
            ) : (
              <div className="grid h-40 place-items-center rounded-lg border border-dashed border-[#1e293b] text-[12px] text-[#4d5f7a]">
                Analysis appears as you type
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function Input({ label, ...props }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-[10px] font-medium uppercase tracking-wider text-[#7b8aa5]">{label}</span>
      <input
        {...props}
        className="w-full rounded-lg border border-[#1e293b] bg-[#070b14] px-3 py-2.5 text-[13px] text-[#e8eefc] outline-none placeholder:text-[#3d4d66] focus:border-sky-400/50"
      />
    </label>
  )
}
