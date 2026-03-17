'use client'

interface WelcomeScreenProps {
  toolCount: number
  onSend: (text: string) => void
  onOpenScan: () => void
}

const QUICK_ACTIONS = [
  { icon: '🎯', title: 'Full Domain Scan', desc: 'Nmap + SSL + DNS + Headers - real results, not suggestions', q: 'Scan solventcyber.com - run nmap, ssl check, dns recon, and http headers', scan: false },
  { icon: '🔍', title: 'Threat Intel Lookup', desc: 'Shodan + VirusTotal + AbuseIPDB + OTX on any indicator', q: 'Look up 8.8.8.8 on all threat intel sources', scan: false },
  { icon: '📋', title: 'Compliance Audit', desc: 'CIS v8, FedRAMP, HIPAA, PCI-DSS, SOC 2', q: 'Assess ALL compliance frameworks for access control and encryption', scan: false },
  { icon: '💉', title: 'SQL Injection Test', desc: 'Run sqlmap against a target URL with parameters', q: 'Run sqlmap against http://testphp.vulnweb.com/listproducts.php?cat=1', scan: false },
  { icon: '💀', title: 'Vuln Scan', desc: 'Nuclei + Nikto - real CVE & misconfiguration detection', q: '', scan: true },
  { icon: '⚡', title: 'Rule Generator', desc: 'Multi-format detection rules in one shot', q: 'Generate Sigma + YARA + Snort rules for detecting Cobalt Strike', scan: false },
]

export default function WelcomeScreen({ toolCount, onSend, onOpenScan }: WelcomeScreenProps) {
  return (
    <div className="text-center py-10 animate-slide-in">
      <div className="text-6xl mb-4 drop-shadow-[0_0_30px_rgba(255,51,85,0.5)] cursor-pointer hover:scale-110 transition-transform" onClick={onOpenScan} title="Open Vulnerability Scanner">🛡️</div>
      <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight mb-1">
        Welcome to <span className="bg-gradient-to-r from-cs-cyan to-cs-purple bg-clip-text text-transparent">CyberSentinel AI</span>
      </h1>
      <p className="text-[0.55rem] text-cs-text3 font-mono mb-1">powered by <span className="text-cs-cyan/70">SolventCyber.com</span></p>
      <p className="text-cs-text2 mb-6 max-w-xl mx-auto text-sm">
        Your Agentic Security Platform. {toolCount} real tools - every scanner executes, every API is live, every result is real. <span className="text-cs-cyan font-semibold">No fakes.</span>
      </p>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3 max-w-2xl mx-auto">
        {QUICK_ACTIONS.map((b, i) => (
          <button
            key={i}
            onClick={() => b.scan ? onOpenScan() : onSend(b.q)}
            className={`rounded-xl p-4 text-left transition-all hover:-translate-y-0.5 group ${
              b.scan
                ? 'bg-gradient-to-br from-[#ff3355]/20 to-[#ff6600]/20 border border-[#ff3355]/40 shadow-[0_0_20px_rgba(255,51,85,0.2)] hover:shadow-[0_0_30px_rgba(255,51,85,0.35)] hover:border-[#ff3355]/60'
                : 'bg-cs-bg3 border border-cs-border hover:border-cs-cyan hover:bg-cs-cyan/5'
            }`}
          >
            <div className={`text-xl mb-1 ${b.scan ? 'drop-shadow-[0_0_12px_rgba(255,51,85,0.7)]' : ''}`}>{b.icon}</div>
            <div className={`font-semibold text-sm mb-1 transition-colors ${b.scan ? 'text-[#ff3355] group-hover:text-[#ff6600]' : 'group-hover:text-cs-cyan'}`}>{b.title}</div>
            <div className="text-[0.65rem] text-cs-text3 leading-relaxed">{b.desc}</div>
          </button>
        ))}
      </div>
    </div>
  )
}
