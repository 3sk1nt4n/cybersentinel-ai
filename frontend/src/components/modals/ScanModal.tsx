'use client'
import { useState } from 'react'
import { runScan } from '@/lib/api'

const SCAN_TYPES = [
  { id: 'ping', icon: '🏓', label: 'Ping', test: '8.8.8.8' },
  { id: 'nmap', icon: '🔍', label: 'Nmap', test: 'scanme.nmap.org' },
  { id: 'dns', icon: '🌐', label: 'DNS Recon', test: 'google.com' },
  { id: 'ssl', icon: '🔒', label: 'SSL Check', test: 'google.com' },
  { id: 'whois', icon: '📋', label: 'WHOIS', test: 'google.com' },
  { id: 'headers', icon: '📡', label: 'HTTP Headers', test: 'https://example.com' },
  { id: 'traceroute', icon: '🛤️', label: 'Traceroute', test: '8.8.8.8' },
  { id: 'subfinder', icon: '🗺️', label: 'Subdomains', test: 'hackerone.com' },
  { id: 'nikto', icon: '💀', label: 'Nikto', test: 'http://testphp.vulnweb.com' },
  { id: 'nuclei', icon: '☢️', label: 'Nuclei', test: 'http://testphp.vulnweb.com' },
  { id: 'sqlmap', icon: '💉', label: 'SQLMap', test: 'http://testphp.vulnweb.com/listproducts.php?cat=1' },
  { id: 'zap', icon: '⚡', label: 'OWASP ZAP', test: 'http://testphp.vulnweb.com' },
]

interface ScanModalProps {
  onScanResult: (userMsg: string, resultMsg: string, badge: string) => void
  onClose: () => void
}

export default function ScanModal({ onScanResult, onClose }: ScanModalProps) {
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('ping')
  const [scanning, setScanning] = useState(false)
  const [timer, setTimer] = useState(0)

  const handleScan = async () => {
    if (!target.trim() || scanning) return
    setScanning(true)
    setTimer(0)
    const timerInt = setInterval(() => setTimer(p => p + 1), 1000)
    const userMsg = `🔧 Run ${scanType} scan on ${target}`
    try {
      const r = await runScan(target, scanType)
      const output = r.output || r.error || 'No output received'
      const resultMsg = `🔧 **${scanType.toUpperCase()} Scan - ${target}**\nDuration: ${r.duration || 0}s | Exit: ${r.exit_code ?? '?'}\n\n\`\`\`\n${output}\n\`\`\``
      onScanResult(userMsg, resultMsg, scanType.toUpperCase())
    } catch (e: any) {
      onScanResult(userMsg, `❌ Scan error: ${e.message}`, scanType.toUpperCase())
    }
    clearInterval(timerInt)
    setTimer(0)
    setScanning(false)
    onClose()
  }

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-cs-bg2 border border-cs-border rounded-2xl w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-bold">🎯 Live Security Scan</h2>
          <button onClick={onClose} className="text-cs-text3 hover:text-cs-red">✕</button>
        </div>
        <div className="mb-3">
          <label className="text-xs text-cs-text2 mb-1 block">Target (IP, domain, or URL)</label>
          <input type="text" placeholder="e.g., google.com or 8.8.8.8" value={target} onChange={e => setTarget(e.target.value)} className="w-full bg-cs-bg3 border border-cs-border text-cs-text rounded-lg px-3 py-2 text-sm font-mono outline-none focus:border-cs-cyan" onKeyDown={e => { if (e.key === 'Enter') handleScan() }} />
        </div>
        <div className="mb-3">
          <label className="text-xs text-cs-text2 mb-1 block">Scan Type</label>
          <div className="grid grid-cols-2 gap-2">
            {SCAN_TYPES.map(s => (
              <button key={s.id} onClick={() => { setScanType(s.id); setTarget(s.test) }} className={`text-left px-3 py-2 rounded-lg border text-[0.7rem] font-mono transition-all ${scanType === s.id ? 'bg-cs-red/10 border-cs-red/30 text-cs-red' : 'bg-cs-bg3 border-cs-border text-cs-text2 hover:border-cs-cyan'}`}>
                {s.icon} {s.label}
              </button>
            ))}
          </div>
        </div>
        <div className="bg-cs-bg3 border border-cs-border/50 rounded-lg px-3 py-2 mb-3 flex items-center justify-between">
          <span className="text-[0.6rem] text-cs-text3 font-mono">Test target:</span>
          <span className="text-[0.65rem] text-cs-cyan font-mono">{target || 'select a scan type'}</span>
        </div>
        <button onClick={handleScan} disabled={scanning || !target.trim()} className="w-full bg-gradient-to-r from-cs-red to-cs-orange text-white py-2.5 rounded-lg text-sm font-bold hover:opacity-90 disabled:opacity-50">
          {scanning ? `⏳ Scanning... ${timer}s` : '🚀 Execute Scan'}
        </button>
        {scanning && (
          <div className="mt-2">
            <div className="h-1.5 bg-cs-bg3 rounded-full overflow-hidden">
              <div className="h-full bg-gradient-to-r from-cs-red to-cs-orange rounded-full transition-all duration-1000" style={{ width: `${Math.min(timer / 120 * 100, 95)}%` }} />
            </div>
          </div>
        )}
        <div className="text-[0.55rem] text-cs-text3 font-mono mt-2 text-center">Runs in isolated Kali sandbox container</div>
        <div className="mt-3 bg-cs-bg border border-cs-orange/20 rounded-lg p-3">
          <div className="text-[0.6rem] text-cs-orange font-bold mb-1">⚠️ Legal Notice - Educational & Authorized Use Only</div>
          <div className="text-[0.5rem] text-cs-text3 leading-relaxed">These scanning tools are provided <span className="text-cs-text2">strictly for educational purposes, authorized penetration testing, and security research</span>. By executing a scan you confirm: (1) You own the target or have <span className="text-cs-text2">explicit written authorization</span> from the owner to test it. (2) You are conducting a lawful security assessment. (3) You accept full responsibility for any scans executed. Use the provided test targets (testphp.vulnweb.com, scanme.nmap.org) for safe, legal practice.</div>
        </div>
      </div>
    </div>
  )
}
