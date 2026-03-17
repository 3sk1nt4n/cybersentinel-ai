'use client'
import { type Provider } from '@/lib/api'

interface HeaderProps {
  providers: Provider[]
  provider: string
  serviceHealth: any
  onProviderChange: (id: string) => void
  onSettings: () => void
  onNewChat: () => void
}

export default function Header({ providers, provider, serviceHealth, onProviderChange, onSettings, onNewChat }: HeaderProps) {
  const aiButtons = [
    { id: 'ollama', label: 'Local AI', icon: '🔒', color: 'text-yellow-400 border-yellow-400/40 bg-yellow-400/10' },
    { id: 'claude', label: 'Claude', icon: '🟣', color: 'text-purple-400 border-purple-400/40 bg-purple-400/10' },
    { id: 'openai', label: 'GPT', icon: '🟢', color: 'text-green-400 border-green-400/40 bg-green-400/10' },
    { id: 'openrouter', label: 'Router', icon: '🌐', color: 'text-cyan-400 border-cyan-400/40 bg-cyan-400/10' },
  ]

  return (
    <header className="col-span-full bg-cs-bg2 border-b border-cs-border flex items-center justify-between px-4 z-10">
      <div className="flex items-center gap-3 cursor-pointer select-none" onClick={onNewChat}>
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cs-cyan to-cs-purple flex items-center justify-center text-sm font-extrabold text-cs-bg font-mono">CS</div>
        <div className="leading-tight">
          <div className="font-bold text-sm tracking-tight">Cyber<span className="text-cs-cyan">Sentinel</span> AI <span className="text-[0.6rem] text-cs-text3 bg-cs-bg3 px-1.5 py-0.5 rounded font-mono ml-1">33 TOOLS</span></div>
          <div className="text-[0.5rem] text-cs-text3 font-mono">powered by <span className="text-cs-cyan/70">SolventCyber.com</span></div>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <a href="https://solventcyber.com" target="_blank" className="text-[0.6rem] text-cs-orange font-mono font-bold hidden lg:block hover:text-cs-cyan">SOLVENTCYBER.COM</a>
        <div className="flex items-center gap-1 bg-cs-bg/60 border border-cs-border rounded-lg px-1.5 py-1">
          {aiButtons.map(ai => {
            const prov = providers.find(p => p.id === ai.id)
            const isActive = provider === ai.id
            const isAvail = prov?.configured || ai.id === 'ollama'
            return (
              <button
                key={ai.id}
                onClick={() => isAvail && onProviderChange(ai.id)}
                title={isActive ? `Active: ${prov?.model || ai.id}` : isAvail ? `Switch to ${ai.label}` : `${ai.label} - no API key configured`}
                className={`flex items-center gap-1 px-2 py-0.5 rounded-md text-[0.6rem] font-mono font-semibold transition-all duration-200 border ${
                  isActive
                    ? ai.color + ' shadow-[0_0_8px_rgba(0,255,136,0.15)]'
                    : isAvail
                      ? 'text-cs-text3 border-cs-border hover:border-cs-cyan/40 hover:text-cs-text2 cursor-pointer'
                      : 'text-cs-text3/40 border-transparent cursor-not-allowed opacity-40'
                }`}
              >
                <span className="text-[0.7rem]">{ai.icon}</span>
                <span className="hidden sm:inline">{ai.label}</span>
                {isActive && <span className="w-1.5 h-1.5 rounded-full bg-cs-green shadow-[0_0_4px_#00ff88] animate-pulse" />}
              </button>
            )
          })}
        </div>
        <button onClick={onSettings} title="Settings" className="flex items-center justify-center w-8 h-8 bg-cs-bg3 border border-cs-border text-cs-text2 rounded-lg hover:border-cs-purple hover:text-cs-purple transition-colors text-sm">⚙️</button>
        <button onClick={onNewChat} className="bg-gradient-to-r from-cs-cyan to-cs-purple text-cs-bg text-[0.65rem] font-bold px-3 py-1.5 rounded-lg hover:opacity-90 transition-opacity font-mono">New Session</button>
      </div>
    </header>
  )
}
