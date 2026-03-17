'use client'
import { fmtMsg, type Badge } from '@/lib/utils'

export interface DisplayMessage {
  role: string
  content: string
  badges?: Badge[]
}

interface ChatMessagesProps {
  msgs: DisplayMessage[]
  streaming: boolean
  streamText: string
  streamTimer: number
  copied: number | null
  onCopy: (content: string, idx: number) => void
  onStop: () => void
  chatEndRef: React.RefObject<HTMLDivElement>
}

export default function ChatMessages({ msgs, streaming, streamText, streamTimer, copied, onCopy, onStop, chatEndRef }: ChatMessagesProps) {
  return (
    <>
      {msgs.map((msg, i) => (
        <div key={i} className="flex gap-3 my-3 animate-slide-in group/msg">
          <div className={`w-8 h-8 rounded-lg shrink-0 flex items-center justify-center text-xs font-bold ${msg.role === 'user' ? 'bg-cs-bg3 text-cs-text2' : 'bg-gradient-to-br from-cs-cyan to-cs-purple text-cs-bg'}`}>
            {msg.role === 'user' ? '👤' : 'CS'}
          </div>
          <div className="bg-cs-bg3 border border-cs-border rounded-xl px-4 py-3 max-w-[85%] text-sm leading-relaxed relative">
            <div className="chat-content select-text" dangerouslySetInnerHTML={{ __html: fmtMsg(msg.content) }} />
            {msg.badges && msg.badges.length > 0 && (
              <div className="flex gap-1.5 flex-wrap mt-2">
                {msg.badges.map((b, j) => (
                  <span key={j} className={`text-[0.65rem] px-2 py-0.5 rounded border font-mono font-medium ${b.cls}`}>{b.name}</span>
                ))}
              </div>
            )}
            <button
              onClick={() => onCopy(msg.content, i)}
              className={`absolute top-2 right-2 w-7 h-7 rounded-md border text-[0.65rem] flex items-center justify-center transition-all ${copied === i ? 'bg-cs-green/20 border-cs-green/30 text-cs-green' : 'bg-cs-bg border-cs-border text-cs-text3 hover:border-cs-cyan hover:text-cs-cyan'} ${msg.role === 'assistant' ? 'opacity-100' : 'opacity-0 group-hover/msg:opacity-100'}`}
              title="Copy"
            >
              {copied === i ? '✓' : '📋'}
            </button>
          </div>
        </div>
      ))}

      {streaming && (
        <div className="flex gap-3 my-3 animate-slide-in">
          <div className="w-8 h-8 rounded-lg shrink-0 flex items-center justify-center text-xs font-bold bg-gradient-to-br from-cs-cyan to-cs-purple text-cs-bg">CS</div>
          <div className="bg-cs-bg3 border border-cs-border2 rounded-xl px-4 py-3 max-w-[85%] text-sm leading-relaxed w-full">
            {streamText ? (
              <div className="chat-content select-text" dangerouslySetInnerHTML={{ __html: fmtMsg(streamText) }} />
            ) : (
              <div className="flex items-center gap-3">
                <div className="flex gap-1.5 py-1">
                  <span className="w-2 h-2 rounded-full bg-cs-cyan animate-[typing_1.4s_infinite]" />
                  <span className="w-2 h-2 rounded-full bg-cs-cyan animate-[typing_1.4s_infinite_0.2s]" />
                  <span className="w-2 h-2 rounded-full bg-cs-cyan animate-[typing_1.4s_infinite_0.4s]" />
                </div>
                <span className="text-[0.65rem] text-cs-text3 font-mono">
                  {streamTimer > 0 ? `Thinking... ${streamTimer}s` : 'Connecting...'}
                </span>
              </div>
            )}
            <div className="mt-2 flex items-center gap-2">
              <div className="flex-1 h-1.5 bg-cs-bg rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-cs-cyan to-cs-purple rounded-full transition-all duration-1000 ease-out" style={{ width: `${Math.min(streamTimer / 90 * 100, 95)}%` }} />
              </div>
              <span className="text-[0.55rem] text-cs-text3 font-mono shrink-0">{streamTimer}s</span>
              <button onClick={onStop} className="text-[0.55rem] text-cs-red font-mono hover:underline shrink-0">⏹ Stop</button>
            </div>
          </div>
        </div>
      )}

      <div ref={chatEndRef} />
    </>
  )
}
