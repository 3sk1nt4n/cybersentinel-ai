'use client'

interface HistoryModalProps {
  conversations: any[]
  onLoadChat: (id: string) => void
  onNewChat: () => void
  onClose: () => void
}

export default function HistoryModal({ conversations, onLoadChat, onNewChat, onClose }: HistoryModalProps) {
  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex" onClick={onClose}>
      <div className="w-80 bg-cs-bg2 border-r border-cs-border h-full overflow-y-auto p-4" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-bold">📜 Chat History</h2>
          <button onClick={onClose} className="text-cs-text3 hover:text-cs-red text-sm">✕</button>
        </div>
        <button onClick={() => { onNewChat(); onClose() }} className="w-full bg-cs-cyan/10 border border-cs-cyan/20 text-cs-cyan text-xs py-2 rounded-lg mb-3 hover:bg-cs-cyan/20">+ New Chat</button>
        {conversations.length === 0 ? (
          <div className="text-cs-text3 text-xs text-center py-4">No conversations yet</div>
        ) : (
          conversations.map((c: any) => (
            <div key={c.id} className="bg-cs-bg3 border border-cs-border rounded-lg p-3 mb-2 cursor-pointer hover:border-cs-cyan transition-colors" onClick={() => onLoadChat(c.id)}>
              <div className="text-sm text-cs-text truncate">{c.title}</div>
              <div className="text-[0.6rem] text-cs-text3 font-mono mt-1">{c.message_count} msgs · {c.provider}</div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
