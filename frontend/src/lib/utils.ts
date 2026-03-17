/**
 * CyberSentinel v3.0 — Shared utilities and constants
 */

// Category display labels
export const CAT_LABELS: Record<string, string> = {
  scan: '🎯 Live Scanners',
  intel: '🌐 Threat Intel APIs',
  siem: '📊 SIEM Integration',
  detect: '🔍 AI Detection & Analysis',
  rule: '🎯 Threat Hunting & Rules',
  framework: '🗺️ Frameworks & Compliance',
}

export const CAT_COLORS: Record<string, string> = {
  scan: 'border-l-[#ff3355]',
  intel: 'border-l-[#00f0ff]',
  siem: 'border-l-[#00ff88]',
  detect: 'border-l-[#a855f7]',
  rule: 'border-l-[#ffd000]',
  framework: 'border-l-[#ff9500]',
}

export const CAT_BG: Record<string, string> = {
  scan: 'bg-gradient-to-r from-[#ff3355]/20 to-[#ff6600]/20 shadow-[0_0_15px_rgba(255,51,85,0.15)]',
  intel: 'bg-[#00f0ff]/5',
  siem: 'bg-[#00ff88]/5',
  detect: 'bg-[#a855f7]/5',
  rule: 'bg-[#ffd000]/5',
  framework: 'bg-[#ff9500]/5',
}

export interface Badge {
  name: string
  cls: string
}

/** Detect context badges from a message */
export function detectBadges(t: string): Badge[] {
  const l = t.toLowerCase()
  const o: Badge[] = []
  const m = [
    { k: ['threat hunt', 'sweep'], n: 'Threat Hunt', c: 'bg-cs-cyan/20 text-cs-cyan border-cs-cyan/20' },
    { k: ['siem', 'splunk', 'elastic'], n: 'SIEM', c: 'bg-cs-green/20 text-cs-green border-cs-green/20' },
    { k: ['mitre', 'att&ck'], n: 'MITRE', c: 'bg-cs-cyan/20 text-cs-cyan border-cs-cyan/20' },
    { k: ['yara'], n: 'YARA', c: 'bg-cs-green/20 text-cs-green border-cs-green/20' },
    { k: ['sigma'], n: 'Sigma', c: 'bg-cs-green/20 text-cs-green border-cs-green/20' },
    { k: ['nmap'], n: 'Nmap', c: 'bg-cs-red/20 text-cs-red border-cs-red/20' },
    { k: ['ssl', 'tls'], n: 'SSL/TLS', c: 'bg-cs-green/20 text-cs-green border-cs-green/20' },
    { k: ['dns'], n: 'DNS', c: 'bg-cs-green/20 text-cs-green border-cs-green/20' },
    { k: ['compliance', 'nist', 'hipaa', 'pci'], n: 'Compliance', c: 'bg-cs-orange/20 text-cs-orange border-cs-orange/20' },
    { k: ['cve', 'cvss', 'vuln'], n: 'Vuln', c: 'bg-cs-orange/20 text-cs-orange border-cs-orange/20' },
    { k: ['incident'], n: 'IR', c: 'bg-cs-red/20 text-cs-red border-cs-red/20' },
    { k: ['cloud', 'aws', 'azure'], n: 'Cloud', c: 'bg-cs-purple/20 text-cs-purple border-cs-purple/20' },
  ]
  for (const i of m) {
    if (i.k.some(k => l.includes(k))) o.push({ name: i.n, cls: i.c })
  }
  return o.slice(0, 4)
}

/** Escape HTML entities */
export function escHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/** Format a message with markdown-like syntax to HTML */
export function fmtMsg(t: string): string {
  const cb: string[] = []
  let s = t.replace(/```(\w*)\n?([\s\S]*?)```/g, (_, l, c) => {
    const i = cb.length
    cb.push(
      `<div class="relative my-2 rounded-lg overflow-hidden border border-cs-border"><pre class="bg-cs-bg p-3 overflow-x-auto font-mono text-[0.8rem] leading-relaxed text-cs-cyan whitespace-pre-wrap ${l ? 'pt-7' : ''}">${l ? `<span class="text-[0.55rem] text-cs-text3 bg-cs-border2 px-2 py-0.5 rounded-br font-mono uppercase absolute top-0 left-0">${escHtml(l)}</span>` : ''}${escHtml(c.trim())}</pre></div>`
    )
    return `%%CB${i}%%`
  })

  const ic: string[] = []
  s = s.replace(/`([^`]+)`/g, (_, c) => {
    const i = ic.length
    ic.push(`<code class="bg-cs-bg px-1.5 py-0.5 rounded text-cs-cyan font-mono text-[0.8rem]">${escHtml(c)}</code>`)
    return `%%IC${i}%%`
  })

  const lk: string[] = []
  s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g, (_, text, url) => {
    const i = lk.length
    lk.push(`<a href="${escHtml(url)}" target="_blank" rel="noopener noreferrer" class="text-cs-cyan hover:text-cs-green underline underline-offset-2">${escHtml(text)}</a>`)
    return `%%LK${i}%%`
  })

  s = escHtml(s)
  cb.forEach((b, i) => { s = s.replace(`%%CB${i}%%`, b) })
  ic.forEach((c, i) => { s = s.replace(`%%IC${i}%%`, c) })
  lk.forEach((l, i) => { s = s.replace(`%%LK${i}%%`, l) })

  return s
    .replace(/\*\*(.+?)\*\*/g, '<strong class="text-white/90 font-semibold">$1</strong>')
    .replace(/\n/g, '<br/>')
}
