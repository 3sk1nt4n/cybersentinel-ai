'use client'
import { useState } from 'react'

interface SettingsModalProps {
  onSave: (settings: Record<string, string>) => void
  onClose: () => void
}

const SETTINGS_FIELDS = [
  { k: 'anthropic_api_key', l: 'Anthropic API Key', p: 'sk-ant-...' },
  { k: 'openai_api_key', l: 'OpenAI API Key', p: 'sk-...' },
  { k: 'openrouter_api_key', l: 'OpenRouter API Key', p: 'sk-or-...' },
  { k: 'shodan_api_key', l: 'Shodan API Key', p: 'Shodan key' },
  { k: 'virustotal_api_key', l: 'VirusTotal API Key', p: 'VT key' },
  { k: 'otx_api_key', l: 'AlienVault OTX Key', p: 'OTX key' },
  { k: 'abuseipdb_api_key', l: 'AbuseIPDB API Key', p: 'AbuseIPDB key' },
  { k: 'censys_api_id', l: 'Censys API ID', p: 'Censys ID' },
]

export default function SettingsModal({ onSave, onClose }: SettingsModalProps) {
  const [form, setForm] = useState<Record<string, string>>({})

  const handleSave = () => {
    const u: Record<string, string> = {}
    Object.entries(form).forEach(([k, v]) => { if (v) u[k] = v })
    onSave(u)
  }

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-cs-bg2 border border-cs-border rounded-2xl w-full max-w-lg max-h-[80vh] overflow-y-auto p-6" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-bold">⚙️ Settings</h2>
          <button onClick={onClose} className="text-cs-text3 hover:text-cs-red">✕</button>
        </div>
        {SETTINGS_FIELDS.map(({ k, l, p }) => (
          <div key={k} className="mb-3">
            <label className="text-xs text-cs-text2 mb-1 block">{l}</label>
            <input
              type="password"
              placeholder={p}
              value={form[k] || ''}
              onChange={e => setForm(f => ({ ...f, [k]: e.target.value }))}
              className="w-full bg-cs-bg3 border border-cs-border text-cs-text rounded-lg px-3 py-2 text-sm font-mono outline-none focus:border-cs-cyan"
            />
          </div>
        ))}
        <div className="flex gap-2 mt-4">
          <button onClick={handleSave} className="flex-1 bg-cs-cyan/20 border border-cs-cyan/30 text-cs-cyan py-2 rounded-lg text-sm font-semibold hover:bg-cs-cyan/30">Save</button>
          <button onClick={onClose} className="flex-1 bg-cs-bg3 border border-cs-border text-cs-text2 py-2 rounded-lg text-sm hover:border-cs-red">Cancel</button>
        </div>
      </div>
    </div>
  )
}
