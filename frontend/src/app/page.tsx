'use client'
import { useState, useEffect, useRef, useCallback } from 'react'
import { fetchTools, fetchToolQueries, streamChat, fetchProviders, fullHealthCheck, getKBStats, getGraphSummary, seedKB, uploadToKB, getConversations, createConversation, loadConversation, saveMessage, getSettings, updateSettings, getSandboxHealth, getThreatFeedStatus, getThreatSummary, triggerThreatPull, getTopCVEs, getExploitedCVEs, getRecentIOCs, exportPDF, getElkHealth, elkSeedSampleData, getSplunkHealth, getWazuhHealth, type Tool, type ChatMessage, type Provider } from '@/lib/api'
import { detectBadges, type Badge } from '@/lib/utils'
import Header from '@/components/Header'
import Sidebar from '@/components/Sidebar'
import ChatMessages, { type DisplayMessage } from '@/components/ChatMessages'
import WelcomeScreen from '@/components/WelcomeScreen'
import HistoryModal from '@/components/modals/HistoryModal'
import SettingsModal from '@/components/modals/SettingsModal'
import ScanModal from '@/components/modals/ScanModal'
import CveDetailModal from '@/components/modals/CveDetailModal'

export default function Dashboard() {
  // ── Core state ──
  const [tools, setTools] = useState<Tool[]>([])
  const [activeTool, setActiveTool] = useState<string | null>(null)
  const [queries, setQueries] = useState<string[]>([])
  const [msgs, setMsgs] = useState<DisplayMessage[]>([])
  const [hist, setHist] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [streaming, setStreaming] = useState(false)
  const [streamText, setStreamText] = useState('')
  const [streamTimer, setStreamTimer] = useState(0)

  // ── Providers ──
  const [providers, setProviders] = useState<Provider[]>([])
  const [provider, setProvider] = useState('ollama')

  // ── UI state ──
  const [mobSidebar, setMobSidebar] = useState(false)
  const [showSettings, setShowSettings] = useState(false)
  const [showHistory, setShowHistory] = useState(false)
  const [showScan, setShowScan] = useState(false)
  const [copied, setCopied] = useState<number | null>(null)
  const [uploading, setUploading] = useState(false)

  // ── Services ──
  const [kbStats, setKbStats] = useState<any>(null)
  const [serviceHealth, setServiceHealth] = useState<any>(null)
  const [sandboxOk, setSandboxOk] = useState(false)
  const [elkOk, setElkOk] = useState(false)
  const [splunkOk, setSplunkOk] = useState(false)
  const [wazuhOk, setWazuhOk] = useState(false)

  // ── History ──
  const [conversations, setConversations] = useState<any[]>([])
  const [convId, setConvId] = useState<string | null>(null)

  // ── Threat intel ──
  const [threatData, setThreatData] = useState<any>(null)
  const [threatSummary, setThreatSummary] = useState<any>(null)
  const [cveDetail, setCveDetail] = useState<any>(null)
  const [threatPanel, setThreatPanel] = useState<string | null>(null)
  const [threatPanelData, setThreatPanelData] = useState<any[]>([])
  const [threatPanelLoading, setThreatPanelLoading] = useState(false)
  const threatCacheRef = useRef<Record<string, any[]>>({})

  // ── Refs ──
  const chatEnd = useRef<HTMLDivElement>(null)
  const abortRef = useRef(false)
  const abortCtrlRef = useRef<AbortController | null>(null)
  const genRef = useRef(0)
  const fileRef = useRef<HTMLInputElement>(null)

  // ── Init ──
  useEffect(() => {
    fetchTools().then(d => setTools(d.tools)).catch(() => {})
    fetchProviders().then(d => { setProviders(d.providers); setProvider(d.default) }).catch(() => {})
    fullHealthCheck().then(setServiceHealth).catch(() => {})
    getKBStats().then(setKbStats).catch(() => {})
    getConversations().then(d => setConversations(d.conversations || [])).catch(() => {})
    getSandboxHealth().then(d => setSandboxOk(d.status === 'connected')).catch(() => {})
    getElkHealth().then(d => setElkOk(d.status === 'connected')).catch(() => {})
    getSplunkHealth().then(d => setSplunkOk(d.status === 'connected')).catch(() => {})
    getWazuhHealth().then(d => setWazuhOk(d.status === 'connected' || d.status === 'connected_no_auth')).catch(() => {})
    getThreatFeedStatus().then(setThreatData).catch(() => {})
    getThreatSummary().then(d => { if (d?.stats) setThreatSummary(d) }).catch(() => {})

    const ti = setInterval(() => {
      getThreatFeedStatus().then(setThreatData).catch(() => {})
      getThreatSummary().then(d => { if (d?.stats) setThreatSummary(d) }).catch(() => {})
    }, 30000)
    const svc = setInterval(() => {
      getKBStats().then(setKbStats).catch(() => {})
      fullHealthCheck().then(setServiceHealth).catch(() => {})
      getSandboxHealth().then(d => setSandboxOk(d.status === 'connected')).catch(() => {})
      getElkHealth().then(d => setElkOk(d.status === 'connected')).catch(() => {})
      getSplunkHealth().then(d => setSplunkOk(d.status === 'connected')).catch(() => {})
      getWazuhHealth().then(d => setWazuhOk(d.status === 'connected' || d.status === 'connected_no_auth')).catch(() => {})
    }, 15000)
    return () => { clearInterval(ti); clearInterval(svc) }
  }, [])

  useEffect(() => { chatEnd.current?.scrollIntoView({ behavior: 'smooth' }) }, [msgs])

  // ── Actions ──
  const pickTool = useCallback(async (n: string) => {
    if (n === 'Splunk SIEM' && !splunkOk) {
      setActiveTool(null); setQueries([])
      setMsgs(p => [...p, { role: 'assistant', content: `## 🔍 Splunk SIEM - Not Connected\n\nSplunk is not running yet. Start it with Docker and the service panel will show it as 🟢 **ON** once connected.\n\nThen try: *"Check Splunk health"* or *"Query Splunk for failed logins"*` }])
      return
    }
    if (n === 'Wazuh SIEM' && !wazuhOk) {
      setActiveTool(null); setQueries([])
      setMsgs(p => [...p, { role: 'assistant', content: `## 🛡️ Wazuh SIEM - Not Connected\n\nWazuh is not running yet. Start it with Docker and the service panel will show it as 🟢 **ON** once connected.\n\nThen try: *"Check Wazuh health"* or *"Query Wazuh alerts"*` }])
      return
    }
    setActiveTool(n); setMobSidebar(false)
    setQueries(await fetchToolQueries(n).catch(() => []))
    setTimeout(() => chatEnd.current?.scrollIntoView({ behavior: 'smooth' }), 100)
  }, [splunkOk, wazuhOk])

  const copyMsg = (content: string, idx: number) => {
    navigator.clipboard.writeText(content).then(() => { setCopied(idx); setTimeout(() => setCopied(null), 2000) }).catch(() => {})
  }

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]; if (!file) return
    setUploading(true)
    try {
      const r = await uploadToKB(file, 'user_docs')
      setMsgs(p => [...p, { role: 'assistant', content: `📁 **File uploaded:** ${file.name}\n${r.success ? `✅ Added ${r.chunks_added} chunks to knowledge base` : `❌ Error: ${r.error}`}` }])
      getKBStats().then(setKbStats).catch(() => {})
    } catch { setMsgs(p => [...p, { role: 'assistant', content: `❌ Upload failed for ${file.name}` }]) }
    setUploading(false); if (fileRef.current) fileRef.current.value = ''
  }

  const send = useCallback(async (text?: string) => {
    const t = text || input.trim(); if (!t) return; setInput('')
    const lower = t.toLowerCase().trim()
    if (lower === 'clear' || lower === 'reset' || lower === 'new' || lower === 'new chat') { newChat(); return }
    if (streaming) { abortRef.current = true; abortCtrlRef.current?.abort(); setStreamText(''); setStreaming(false) }
    setActiveTool(null); setQueries([])
    setMsgs(p => [...p, { role: 'user', content: t }])
    setTimeout(() => chatEnd.current?.scrollIntoView({ behavior: 'smooth' }), 50)
    const nh = [...hist, { role: 'user' as const, content: t }]; setHist(nh); setStreaming(true); setStreamText(''); setStreamTimer(0)
    abortRef.current = false
    const thisGen = ++genRef.current
    const abortCtrl = new AbortController(); abortCtrlRef.current = abortCtrl
    const tmrId = setInterval(() => setStreamTimer(p => p + 1), 1000)
    let cid = convId
    if (!cid) { try { const c = await createConversation(t.slice(0, 60), provider); cid = c.id; setConvId(cid) } catch {} }
    if (cid) saveMessage(cid, 'user', t).catch(() => {})
    let full = ''
    try {
      for await (const ch of streamChat(nh, provider, undefined, abortCtrl.signal)) {
        if (abortRef.current || genRef.current !== thisGen) { full = ''; break }
        if (ch.error) { full = `⚠️ **Error:** ${ch.error}`; break }
        if (ch.token) { full += ch.token; setStreamText(full) }
        if (ch.done) break
      }
    } catch (e: any) {
      if (e.name === 'AbortError' || abortRef.current || genRef.current !== thisGen) { clearInterval(tmrId); setStreamTimer(0); setStreamText(''); setStreaming(false); abortRef.current = false; return }
      full = `⚠️ **Error:** ${e.message}`
    }
    clearInterval(tmrId); setStreamTimer(0)
    if (abortRef.current || genRef.current !== thisGen) { setStreamText(''); setStreaming(false); abortRef.current = false; return }
    const badges = detectBadges(t)
    setMsgs(p => [...p, { role: 'assistant', content: full, badges }]); setHist(p => [...p, { role: 'assistant', content: full }])
    setStreamText(''); setStreaming(false)
    if (cid && full) saveMessage(cid, 'assistant', full, badges).catch(() => {})
    getConversations().then(d => setConversations(d.conversations || [])).catch(() => {})
  }, [input, streaming, hist, provider, convId])

  const loadChat = useCallback(async (id: string) => {
    try {
      const d = await loadConversation(id)
      if (d?.messages) {
        setMsgs(d.messages.map((m: any) => ({ role: m.role, content: m.content, badges: m.badges })))
        setHist(d.messages.map((m: any) => ({ role: m.role, content: m.content })))
        setConvId(id); setShowHistory(false)
      }
    } catch {}
  }, [])

  const newChat = () => {
    abortRef.current = true; abortCtrlRef.current?.abort()
    setMsgs([]); setHist([]); setConvId(null); setStreamText(''); setStreaming(false); setActiveTool(null); setQueries([])
  }

  const stopStream = () => { abortRef.current = true; abortCtrlRef.current?.abort(); genRef.current++ }

  const exportMd = () => {
    const md = msgs.map(m => `## ${m.role === 'user' ? '👤 You' : '🛡️ CyberSentinel'}\n\n${m.content}`).join('\n\n---\n\n')
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([`# CyberSentinel Export\n\n${md}`], { type: 'text/markdown' })); a.download = `cybersentinel-${Date.now()}.md`; a.click()
  }

  const exportPdf = async () => {
    try { const blob = await exportPDF(msgs.map(m => ({ role: m.role, content: m.content }))); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `cybersentinel-report-${Date.now()}.pdf`; a.click() } catch { exportMd() }
  }

  const handleProviderChange = async (id: string) => {
    setProvider(id)
    try { await updateSettings({ ai_provider: id }); fullHealthCheck().then(setServiceHealth).catch(() => {}) } catch {}
  }

  const handleSaveSettings = async (updates: Record<string, string>) => {
    if (Object.keys(updates).length) {
      await updateSettings(updates).catch(() => {})
      fetchProviders().then(d => { setProviders(d.providers); setProvider(d.default) }).catch(() => {})
    }
    setShowSettings(false)
  }

  const handleScanResult = (userMsg: string, resultMsg: string, badge: string) => {
    setMsgs(p => [...p, { role: 'user', content: userMsg }, { role: 'assistant', content: resultMsg, badges: [{ name: badge, cls: 'bg-cs-red/20 text-cs-red border-cs-red/20' }] }])
  }

  const openThreatPanel = async (type: string) => {
    setThreatPanel(type); setThreatPanelLoading(true)
    const cached = threatCacheRef.current[type]
    if (cached?.length > 0) setThreatPanelData(cached)
    else if (type === 'critical' && threatSummary?.top_cves?.length > 0) setThreatPanelData(threatSummary.top_cves)
    else setThreatPanelData([])
    const fetchData = async (): Promise<any[]> => {
      try {
        if (type === 'critical') { const r = await getTopCVEs(15); return r.cves || [] }
        else if (type === 'exploited') { const r = await getExploitedCVEs(15); return r.vulns || [] }
        else if (type === 'iocs') { const r = await getRecentIOCs('ip', 15); const r2 = await getRecentIOCs('domain', 10); return [...(r.iocs || []), ...(r2.iocs || [])] }
      } catch {} return []
    }
    let data = await fetchData()
    const hasAnything = (cached?.length > 0) || (type === 'critical' && threatSummary?.top_cves?.length > 0)
    if (data.length === 0 && !hasAnything) {
      for (let i = 0; i < 4 && data.length === 0; i++) { await new Promise(r => setTimeout(r, 10000)); data = await fetchData() }
    }
    if (data.length > 0) { threatCacheRef.current[type] = data; setThreatPanelData(data) }
    setThreatPanelLoading(false)
  }

  const onKey = (e: React.KeyboardEvent) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }
  const showWelcome = msgs.length === 0 && !activeTool

  return (
    <div className="h-screen grid grid-rows-[56px_1fr] grid-cols-1 md:grid-cols-[260px_1fr] xl:grid-cols-[260px_1fr_380px]">
      <Header providers={providers} provider={provider} serviceHealth={serviceHealth} onProviderChange={handleProviderChange} onSettings={() => setShowSettings(true)} onNewChat={newChat} />

      <Sidebar tools={tools} activeTool={activeTool} mobSidebar={mobSidebar} onPickTool={pickTool} onOpenScan={() => setShowScan(true)} onCloseMobile={() => setMobSidebar(false)} />

      {/* MAIN */}
      <main className="overflow-y-auto p-4 md:p-6 flex flex-col">
        <div className="flex-1 max-w-4xl mx-auto w-full">
          {showWelcome && <WelcomeScreen toolCount={tools.length} onSend={send} onOpenScan={() => setShowScan(true)} />}
          <ChatMessages msgs={msgs} streaming={streaming} streamText={streamText} streamTimer={streamTimer} copied={copied} onCopy={copyMsg} onStop={stopStream} chatEndRef={chatEnd} />
          {activeTool && queries.length > 0 && (
            <div className="mb-2 animate-slide-in">
              <div className="flex items-center justify-between mb-3">
                <div className="text-sm font-bold text-cs-cyan">🔧 {activeTool}</div>
                <button onClick={() => { setActiveTool(null); setQueries([]) }} className="w-6 h-6 rounded border border-cs-border text-cs-text3 text-xs flex items-center justify-center hover:border-cs-red hover:text-cs-red">✕</button>
              </div>
              {queries.map((q, i) => (
                <div key={i} className="flex items-center gap-2 my-1.5">
                  <span className="font-mono text-[0.6rem] text-cs-text3 w-5 shrink-0">{String(i + 1).padStart(2, '0')}</span>
                  <div className="flex-1 bg-cs-bg3 border border-cs-border rounded-lg px-3 py-2 text-sm text-cs-text cursor-pointer hover:border-cs-cyan transition-all" onClick={() => send(q)}>{q}</div>
                  <button onClick={() => send(q)} className="w-8 h-8 rounded-lg bg-cs-bg3 border border-cs-border text-cs-cyan text-sm flex items-center justify-center hover:bg-cs-cyan/10 shrink-0">→</button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ACTION BAR */}
        <div className="max-w-4xl mx-auto w-full flex items-center gap-2 pt-1 flex-wrap">
          <button onClick={() => setShowHistory(!showHistory)} className="flex items-center gap-1.5 bg-cs-bg3 border border-cs-border text-cs-text2 text-[0.65rem] px-3 py-1.5 rounded-lg hover:border-cs-cyan hover:text-cs-cyan transition-colors font-mono">📜 History</button>
          {msgs.length > 0 && <button onClick={exportPdf} className="flex items-center gap-1.5 bg-cs-bg3 border border-cs-border text-cs-text2 text-[0.65rem] px-3 py-1.5 rounded-lg hover:border-cs-red hover:text-cs-red transition-colors font-mono">📕 Export PDF</button>}
          {msgs.length > 0 && <button onClick={exportMd} className="flex items-center gap-1.5 bg-cs-bg3 border border-cs-border text-cs-text2 text-[0.65rem] px-3 py-1.5 rounded-lg hover:border-cs-green hover:text-cs-green transition-colors font-mono">📄 Export .md</button>}
          <button onClick={() => fileRef.current?.click()} className="flex items-center gap-1.5 bg-cs-bg3 border border-cs-border text-cs-text2 text-[0.65rem] px-3 py-1.5 rounded-lg hover:border-cs-orange hover:text-cs-orange transition-colors font-mono">{uploading ? '⏳ Uploading...' : '📁 Upload'}</button>
          <input ref={fileRef} type="file" className="hidden" accept=".txt,.md,.csv,.json,.log,.pcap,.xml,.yaml,.yml,.pdf" onChange={handleUpload} />
          <button onClick={() => setShowSettings(true)} className="flex items-center gap-1.5 bg-cs-bg3 border border-cs-border text-cs-text2 text-[0.65rem] px-3 py-1.5 rounded-lg hover:border-cs-purple hover:text-cs-purple transition-colors font-mono">⚙️ Settings</button>
          <div className="flex-1" />
          <button onClick={newChat} className="flex items-center gap-1.5 bg-gradient-to-r from-cs-cyan to-cs-purple text-cs-bg text-[0.65rem] px-4 py-1.5 rounded-lg font-bold font-mono hover:opacity-90 transition-opacity shadow-[0_0_10px_rgba(0,240,255,0.15)]">✦ New Session</button>
        </div>

        {/* INPUT */}
        <div className="max-w-4xl mx-auto w-full pt-1 pb-2">
          <div className="flex gap-2 items-end">
            {sandboxOk && <button onClick={() => setShowScan(true)} className="w-12 h-12 rounded-xl bg-gradient-to-br from-cs-red to-cs-orange text-white flex items-center justify-center text-lg font-bold shrink-0 hover:scale-105 transition-transform shadow-[0_0_15px_rgba(255,51,85,0.25)]" title="Live Security Scan">🎯</button>}
            <textarea value={input} onChange={e => setInput(e.target.value)} onKeyDown={onKey} placeholder={streaming ? 'Streaming...' : 'Ask CyberSentinel anything...'} disabled={streaming} rows={1} className="flex-1 bg-cs-bg3 border border-cs-border text-cs-text rounded-xl px-4 py-3 text-sm outline-none resize-none min-h-[48px] max-h-[160px] focus:border-cs-cyan placeholder:text-cs-text3 disabled:opacity-50 font-sans" />
            <button onClick={() => send()} disabled={streaming} className="w-12 h-12 rounded-xl bg-gradient-to-br from-cs-cyan to-cs-green text-cs-bg flex items-center justify-center text-lg font-bold shrink-0 hover:scale-105 transition-transform shadow-[0_0_15px_rgba(0,240,255,0.2)] disabled:opacity-50">→</button>
          </div>
          <div className="text-[0.55rem] text-cs-text3 font-mono mt-1.5 px-1">
            ⌘ Enter to send · {tools.length} tools · {provider === 'ollama' ? '🧠' : provider === 'claude' ? '🟣' : provider === 'openai' ? '🟢' : '🌐'} {providers.find(p => p.id === provider)?.model || provider} · {provider === 'ollama' ? '🔒 Local Mode' : '☁️ Cloud Mode'}
          </div>
        </div>
      </main>

      {/* RIGHT PANEL */}
      <aside className="hidden xl:block bg-gradient-to-b from-cs-bg2 to-[#0a0e1a] border-l border-cs-border overflow-y-auto p-4">
        {/* Arsenal Stats */}
        <div className="mb-4">
          <div className="text-[0.7rem] uppercase tracking-widest text-cs-text3 font-semibold mb-2">/ Arsenal Stats</div>
          <div className="grid grid-cols-2 gap-2">
            {[{ n: '33', l: 'TOOLS', c: 'text-cs-cyan', bc: 'border-cs-cyan/20' }, { n: '6', l: 'CATEGORIES', c: 'text-cs-purple', bc: 'border-cs-purple/20' }, { n: '11', l: 'SCANNERS', c: 'text-cs-green', bc: 'border-cs-green/20' }, { n: '5', l: 'INTEL APIS', c: 'text-cs-orange', bc: 'border-cs-orange/20' }].map((s, i) => (
              <div key={i} className={`bg-cs-bg3 border ${s.bc} rounded-lg p-3 text-center`}>
                <div className={`text-xl font-extrabold font-mono ${s.c}`}>{s.n}</div>
                <div className="text-[0.5rem] text-cs-text3 uppercase tracking-wider mt-0.5">{s.l}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Threat Intel */}
        <div className="mb-4">
          <div className="flex items-center justify-between mb-2">
            <div className="text-[0.75rem] uppercase tracking-widest text-cs-text3 font-semibold">/ Live Threat Intel</div>
            <button onClick={() => triggerThreatPull().then(() => { setTimeout(() => { getThreatFeedStatus().then(setThreatData); getThreatSummary().then(d => { if (d?.stats) setThreatSummary(d) }) }, 10000) })} className="text-[0.6rem] bg-cs-red/20 text-cs-red px-2.5 py-1 rounded font-mono hover:bg-cs-red/30">Refresh</button>
          </div>
          {threatSummary?.stats ? (
            <>
              <div className="grid grid-cols-3 gap-1.5 mb-3">
                {[{ n: threatSummary.stats.critical_cves || 0, l: 'CRITICAL', c: 'text-cs-red', bc: 'hover:border-cs-red/50', t: 'critical' }, { n: threatSummary.stats.exploited_cves || 0, l: 'EXPLOITED', c: 'text-cs-orange', bc: 'hover:border-cs-orange/50', t: 'exploited' }, { n: threatSummary.stats.total_iocs || 0, l: 'IOCs', c: 'text-cs-cyan', bc: 'hover:border-cs-cyan/50', t: 'iocs' }].map((s, i) => (
                  <div key={i} onClick={() => openThreatPanel(s.t)} className={`bg-cs-bg3 border border-cs-border/30 rounded-lg p-2.5 text-center cursor-pointer transition-all ${s.bc} hover:scale-[1.02]`}>
                    <div className={`text-xl font-extrabold font-mono ${s.c}`}>{s.n}</div>
                    <div className="text-[0.55rem] text-cs-text3 uppercase tracking-wider">{s.l}</div>
                  </div>
                ))}
              </div>
              <div className="space-y-1.5 mb-3">
                {(threatSummary.top_cves || []).slice(0, 5).map((c: any, i: number) => (
                  <div key={i} onClick={() => setCveDetail(c)} className="block bg-cs-bg border border-cs-border/30 rounded-lg p-2.5 hover:border-cs-red/50 transition-colors cursor-pointer">
                    <div className="flex items-center justify-between">
                      <span className="text-cs-red font-mono text-[0.7rem] font-bold">{c.cve_id}</span>
                      <span className={`text-[0.6rem] font-mono px-1.5 py-0.5 rounded font-bold ${c.cvss_score >= 9 ? 'bg-cs-red/20 text-cs-red' : c.cvss_score >= 7 ? 'bg-cs-orange/20 text-cs-orange' : 'bg-cs-cyan/20 text-cs-cyan'}`}>{c.cvss_score}</span>
                    </div>
                    <div className="text-[0.65rem] text-cs-text3 mt-1 line-clamp-2 leading-relaxed">{c.description?.slice(0, 120)}...</div>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="bg-cs-bg3 border border-cs-border/50 rounded-lg p-4 text-center">
              <div className="text-cs-orange text-sm animate-pulse mb-1">⏳</div>
              <div className="text-[0.7rem] text-cs-text3">Pulling live threat intel...</div>
            </div>
          )}
        </div>

        {/* Services */}
        <div className="mb-4">
          <div className="text-[0.7rem] uppercase tracking-widest text-cs-text3 font-semibold mb-2">/ Services</div>
          <div className="bg-cs-bg3 border border-cs-border/50 rounded-lg p-3 space-y-2">
            {[
              { name: 'Local AI (Ollama)', icon: '🔒', id: 'ollama', ok: serviceHealth?.services?.ollama?.status === 'connected' },
              { name: 'Neo4j Graph', icon: '🕸️', id: 'neo4j', ok: serviceHealth?.services?.neo4j?.status === 'connected' },
              { name: 'ChromaDB RAG', icon: '📚', id: 'chromadb', ok: kbStats?.status === 'connected' },
              { name: 'Kali Sandbox', icon: '🐧', id: 'sandbox', ok: sandboxOk },
              { name: 'ELK Stack', icon: '📊', id: 'elk', ok: elkOk },
              { name: 'Splunk', icon: '🔍', id: 'splunk', ok: splunkOk },
              { name: 'Wazuh', icon: '🛡️', id: 'wazuh', ok: wazuhOk },
            ].map((s, i) => (
              <div key={i} className="flex items-center justify-between text-[0.75rem]">
                <span className="text-cs-text2 flex items-center gap-1.5"><span>{s.icon}</span>{s.name}</span>
                <span className={`font-mono text-[0.6rem] flex items-center gap-1 px-2 py-0.5 rounded-full ${s.ok ? 'text-cs-green bg-cs-green/10' : 'text-cs-red bg-cs-red/10'}`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${s.ok ? 'bg-cs-green shadow-[0_0_4px_#00ff88]' : 'bg-cs-red'}`} />
                  {s.ok ? 'ON' : 'OFF'}
                </span>
              </div>
            ))}
            {elkOk && <button onClick={async (e) => { const btn = e.currentTarget; btn.textContent = '⏳ Seeding...'; btn.disabled = true; try { await elkSeedSampleData(); btn.textContent = '✅ Seeded!' } catch { btn.textContent = '❌ Failed' } setTimeout(() => { btn.textContent = '📊 Seed ELK with 500+ Events'; btn.disabled = false }, 3000) }} className="w-full mt-1 bg-gradient-to-r from-cs-green/20 to-cs-cyan/20 border border-cs-green/30 text-cs-green text-[0.55rem] py-1.5 rounded-lg font-mono hover:from-cs-green/30 hover:to-cs-cyan/30 disabled:opacity-50">📊 Seed ELK with 500+ Events</button>}
          </div>
        </div>

        {/* Knowledge Base */}
        <div className="mb-4">
          <div className="text-[0.7rem] uppercase tracking-widest text-cs-text3 font-semibold mb-2">/ Knowledge Base</div>
          <div className="bg-cs-bg3 border border-cs-border/50 rounded-lg p-3">
            {kbStats?.status === 'connected' ? (
              <div className="space-y-1.5">
                {Object.entries(kbStats.collections || {}).filter(([, info]: any) => info.documents > 0).map(([n, info]: any) => (
                  <div key={n} className="flex items-center justify-between text-[0.7rem]">
                    <span className="text-cs-text2 truncate capitalize">{n.replace(/_/g, ' ')}</span>
                    <span className="text-cs-cyan font-mono text-[0.55rem] bg-cs-cyan/10 px-1.5 py-0.5 rounded">{info.documents}</span>
                  </div>
                ))}
                <button onClick={() => seedKB().then(() => getKBStats().then(setKbStats))} className="mt-2 w-full bg-gradient-to-r from-cs-purple/20 to-cs-cyan/20 border border-cs-purple/30 text-cs-purple text-[0.6rem] py-1.5 rounded-lg font-mono hover:from-cs-purple/30 hover:to-cs-cyan/30">🧠 Seed Knowledge</button>
              </div>
            ) : (
              <div className="text-cs-text3 text-[0.7rem] text-center py-2">Connecting to ChromaDB...</div>
            )}
          </div>
        </div>

        {/* Creator */}
        <div>
          <div className="text-[0.7rem] uppercase tracking-widest text-cs-text3 font-semibold mb-2">/ Creator</div>
          <div className="bg-gradient-to-br from-cs-orange/10 to-cs-purple/10 border border-cs-orange/20 rounded-lg p-3 text-center">
            <a href="https://www.credly.com/users/eskintan/badges#credly" target="_blank" className="font-bold text-cs-orange text-sm hover:text-cs-cyan transition-colors">🏅 3sk1nt4n</a>
            <div className="text-[0.5rem] text-cs-text3 font-mono mt-1">CyberSentinel AI v3.0 | Agentic</div>
          </div>
        </div>
      </aside>

      {/* MODALS */}
      {showHistory && <HistoryModal conversations={conversations} onLoadChat={loadChat} onNewChat={newChat} onClose={() => setShowHistory(false)} />}
      {showSettings && <SettingsModal onSave={handleSaveSettings} onClose={() => setShowSettings(false)} />}
      {showScan && <ScanModal onScanResult={handleScanResult} onClose={() => setShowScan(false)} />}
      {cveDetail && <CveDetailModal cve={cveDetail} onClose={() => setCveDetail(null)} />}

      {/* Threat Panel Modal */}
      {threatPanel && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={() => setThreatPanel(null)}>
          <div className="bg-cs-bg2 border border-cs-border rounded-2xl w-full max-w-2xl p-6 max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-bold">{threatPanel === 'critical' ? '🔴 Critical CVEs (CVSS ≥ 9.0)' : threatPanel === 'exploited' ? '🟠 CISA KEV - Actively Exploited' : '🔵 IOCs'}</h2>
              <button onClick={() => setThreatPanel(null)} className="text-cs-text3 hover:text-cs-red text-lg">✕</button>
            </div>
            {threatPanelLoading && threatPanelData.length === 0 ? (
              <div className="text-center py-8"><div className="text-2xl mb-2 animate-pulse">⏳</div><div className="text-sm text-cs-text3">Loading...</div></div>
            ) : threatPanelData.length === 0 ? (
              <div className="text-center py-8"><div className="text-2xl mb-2">📭</div><div className="text-sm text-cs-text3">No data available. Click Refresh and try again.</div></div>
            ) : (
              <div className="space-y-2">
                {threatPanelData.map((item: any, i: number) => (
                  <div key={i} onClick={() => item.cve_id && (setThreatPanel(null), setCveDetail(item))} className="bg-cs-bg border border-cs-border/30 rounded-lg p-3 hover:border-cs-cyan/50 cursor-pointer transition-all">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-cs-cyan font-mono text-sm font-bold">{item.cve_id || item.indicator}</span>
                      {item.cvss_score && <span className={`text-[0.6rem] font-mono px-2 py-0.5 rounded font-bold ${item.cvss_score >= 9 ? 'bg-cs-red/20 text-cs-red' : 'bg-cs-orange/20 text-cs-orange'}`}>CVSS {item.cvss_score}</span>}
                      {item.confidence && <span className={`text-[0.6rem] font-mono px-2 py-0.5 rounded ${item.confidence >= 80 ? 'bg-cs-red/20 text-cs-red' : 'bg-cs-cyan/20 text-cs-cyan'}`}>{item.confidence}% conf</span>}
                    </div>
                    <div className="text-[0.65rem] text-cs-text2 leading-relaxed">{(item.description || item.name || item.threat_type || '')?.slice(0, 200)}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {mobSidebar && <div className="fixed inset-0 bg-black/50 z-40 md:hidden" onClick={() => setMobSidebar(false)} />}
    </div>
  )
}
