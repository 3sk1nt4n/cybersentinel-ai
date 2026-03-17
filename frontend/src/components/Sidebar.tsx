'use client'
import { type Tool } from '@/lib/api'
import { CAT_LABELS, CAT_COLORS, CAT_BG } from '@/lib/utils'

interface SidebarProps {
  tools: Tool[]
  activeTool: string | null
  mobSidebar: boolean
  onPickTool: (name: string) => void
  onOpenScan: () => void
  onCloseMobile: () => void
}

export default function Sidebar({ tools, activeTool, mobSidebar, onPickTool, onOpenScan, onCloseMobile }: SidebarProps) {
  const grouped: Record<string, Tool[]> = {}
  tools.forEach(t => {
    if (!grouped[t.cat]) grouped[t.cat] = []
    grouped[t.cat].push(t)
  })

  return (
    <aside className={`bg-cs-bg2 border-r border-cs-border overflow-y-auto py-1 ${mobSidebar ? 'fixed inset-y-14 left-0 w-72 z-50 block shadow-xl' : 'hidden md:block'}`}>
      {Object.entries(grouped).map(([cat, catTools]) => (
        <div key={cat} className="mb-1">
          <div
            onClick={() => cat === 'scan' ? onOpenScan() : undefined}
            className={`flex items-center justify-between mx-2 mt-2 mb-1 px-2 py-1.5 rounded-lg ${CAT_BG[cat] || ''} border-l-2 ${CAT_COLORS[cat] || 'border-l-cs-text3'} ${cat === 'scan' ? 'cursor-pointer hover:scale-[1.02] transition-transform' : ''}`}
          >
            <span className="text-[0.7rem] uppercase tracking-wider font-bold text-cs-text">{CAT_LABELS[cat] || cat}</span>
            <span className="text-[0.55rem] font-mono text-cs-text3 bg-cs-bg3 px-1.5 py-0.5 rounded">{catTools.length}</span>
          </div>
          {catTools.map(tool => (
            <div
              key={tool.id}
              onClick={() => { onPickTool(tool.name); onCloseMobile() }}
              className={`flex items-center gap-2 px-3 py-2 mx-1 rounded cursor-pointer text-[0.85rem] transition-all truncate ${activeTool === tool.name ? 'bg-cs-cyan/10 text-cs-cyan border-l-2 border-cs-cyan' : 'text-cs-text2 hover:bg-cs-bg3 hover:text-cs-text'}`}
            >
              <span className="font-mono text-[0.6rem] text-cs-text3 w-5 shrink-0">{String(tool.id).padStart(2, '0')}</span>
              <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: tool.color }} />
              <span className="truncate">{tool.name}</span>
            </div>
          ))}
        </div>
      ))}
      <div className="flex items-center gap-2 px-3 py-2 mt-2 border-t border-cs-border text-[0.65rem] text-cs-text3 font-mono">
        <strong className="text-cs-cyan text-lg">{tools.length}</strong> tools across <strong>{Object.keys(grouped).length}</strong> categories
      </div>
      <div className="px-3 pb-2 text-[0.5rem] text-cs-text3 font-mono">CyberSentinel AI v3.0 | Agentic</div>
    </aside>
  )
}
