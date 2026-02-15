/**
 * CyberSentinel v2.0 — API Client
 * Communicates with the FastAPI backend.
 */

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
const API_KEY = process.env.NEXT_PUBLIC_API_KEY || '';

function apiHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return API_KEY ? { ...extra, 'X-API-Key': API_KEY } : extra;
}

export interface Tool {
  id: number;
  name: string;
  cat: string;
  color: string;
}

export interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface Provider {
  id: string;
  name: string;
  model: string;
  configured: boolean;
  cost: string;
}

/** Fetch all 43 tools */
export async function fetchTools(): Promise<{ tools: Tool[]; total: number }> {
  const res = await fetch(`${API_URL}/api/tools/`, { headers: apiHeaders() });
  return res.json();
}

/** Fetch sample queries for a tool */
export async function fetchToolQueries(toolName: string): Promise<string[]> {
  const res = await fetch(`${API_URL}/api/tools/queries?name=${encodeURIComponent(toolName)}`, { headers: apiHeaders() });
  const data = await res.json();
  return data.queries || [];
}

/** Fetch available AI providers */
export async function fetchProviders(): Promise<{ default: string; providers: Provider[] }> {
  const res = await fetch(`${API_URL}/api/chat/providers`, { headers: apiHeaders() });
  return res.json();
}

/** Stream a chat response — returns an async iterator of tokens */
export async function* streamChat(
  messages: ChatMessage[],
  provider?: string,
  model?: string,
  signal?: AbortSignal,
): AsyncGenerator<{ token?: string; error?: string; done?: boolean }> {
  const res = await fetch(`${API_URL}/api/chat/stream`, {
    method: 'POST',
    headers: apiHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ messages, provider, model }),
    signal,
  });

  if (!res.ok) {
    yield { error: `API error: ${res.status}` };
    return;
  }

  const reader = res.body?.getReader();
  if (!reader) {
    yield { error: 'No response body' };
    return;
  }

  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';

    for (const line of lines) {
      if (line.startsWith('data: ')) {
        try {
          const data = JSON.parse(line.slice(6));
          yield data;
          if (data.done) return;
        } catch { /* skip malformed lines */ }
      }
    }
  }
}

/** Quick health check */
export async function healthCheck(): Promise<any> {
  const res = await fetch(`${API_URL}/health`);
  return res.json();
}

/** Full health check with all services */
export async function fullHealthCheck(): Promise<any> {
  const res = await fetch(`${API_URL}/health/full`);
  return res.json();
}

// ═══════════════════════════════════════════════
// PHASE 2: Graph Intelligence
// ═══════════════════════════════════════════════

/** Get attack surface summary from Neo4j */
export async function getGraphSummary(): Promise<any> {
  const res = await fetch(`${API_URL}/api/graph/summary`, { headers: apiHeaders() });
  return res.json();
}

/** Initialize graph schema */
export async function initGraph(): Promise<any> {
  const res = await fetch(`${API_URL}/api/graph/init`, { method: 'POST', headers: apiHeaders() });
  return res.json();
}

// ═══════════════════════════════════════════════
// PHASE 2: Knowledge Base (RAG)
// ═══════════════════════════════════════════════

/** Get knowledge base stats */
export async function getKBStats(): Promise<any> {
  const res = await fetch(`${API_URL}/api/knowledge/stats`, { headers: apiHeaders() });
  return res.json();
}

/** Search knowledge base */
export async function searchKB(query: string, collection?: string): Promise<any> {
  const res = await fetch(`${API_URL}/api/knowledge/search`, {
    method: 'POST',
    headers: apiHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ query, collection: collection || 'security_kb', n_results: 5 }),
  });
  return res.json();
}

/** Seed knowledge base with built-in security data */
export async function seedKB(): Promise<any> {
  const res = await fetch(`${API_URL}/api/knowledge/seed`, { method: 'POST', headers: apiHeaders() });
  return res.json();
}

/** Upload a file to the knowledge base */
export async function uploadToKB(file: File, collection?: string): Promise<any> {
  const form = new FormData();
  form.append('file', file);
  if (collection) form.append('collection', collection);
  const res = await fetch(`${API_URL}/api/knowledge/upload`, { method: 'POST', body: form, headers: apiHeaders() });
  return res.json();
}

// ═══════════════════════════════════════════════
// PHASE 3: Live Scans
// ═══════════════════════════════════════════════

export async function runScan(target: string, scanType: string, options?: string): Promise<any> {
  const res = await fetch(`${API_URL}/api/scan/run`, {
    method: 'POST',
    headers: apiHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ target, scan_type: scanType, options: options || '' }),
  });
  return res.json();
}

export async function getScanTypes(): Promise<any> {
  const res = await fetch(`${API_URL}/api/scan/types`, { headers: apiHeaders() });
  return res.json();
}

export async function getSandboxHealth(): Promise<any> {
  const res = await fetch(`${API_URL}/api/scan/health`, { headers: apiHeaders() });
  return res.json();
}

// ═══════════════════════════════════════════════
// PHASE 3: Threat Intelligence
// ═══════════════════════════════════════════════

export async function intelLookup(indicator: string, source?: string): Promise<any> {
  const res = await fetch(`${API_URL}/api/intel/lookup`, {
    method: 'POST',
    headers: apiHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ indicator, source }),
  });
  return res.json();
}

export async function getIntelSources(): Promise<any> {
  const res = await fetch(`${API_URL}/api/intel/sources`, { headers: apiHeaders() });
  return res.json();
}

// ═══════════════════════════════════════════════
// PHASE 3: Chat History
// ═══════════════════════════════════════════════

export async function getConversations(limit?: number): Promise<any> {
  const res = await fetch(`${API_URL}/api/history/conversations?limit=${limit || 30}`, { headers: apiHeaders() });
  return res.json();
}

export async function createConversation(title?: string, provider?: string): Promise<any> {
  const res = await fetch(`${API_URL}/api/history/conversations`, {
    method: 'POST',
    headers: apiHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ title: title || 'New Chat', provider: provider || 'ollama' }),
  });
  return res.json();
}

export async function loadConversation(id: string): Promise<any> {
  const res = await fetch(`${API_URL}/api/history/conversations/${id}`, { headers: apiHeaders() });
  return res.json();
}

export async function saveMessage(conversationId: string, role: string, content: string, badges?: any[]): Promise<any> {
  const res = await fetch(`${API_URL}/api/history/messages`, {
    method: 'POST',
    headers: apiHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ conversation_id: conversationId, role, content, badges }),
  });
  return res.json();
}

export async function deleteConversation(id: string): Promise<any> {
  const res = await fetch(`${API_URL}/api/history/conversations/${id}`, { method: 'DELETE', headers: apiHeaders() });
  return res.json();
}

// ═══════════════════════════════════════════════
// PHASE 3: Settings
// ═══════════════════════════════════════════════

export async function getSettings(): Promise<any> {
  const res = await fetch(`${API_URL}/api/settings/`, { headers: apiHeaders() });
  return res.json();
}

export async function updateSettings(updates: Record<string, string>): Promise<any> {
  const res = await fetch(`${API_URL}/api/settings/update`, {
    method: 'POST',
    headers: apiHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(updates),
  });
  return res.json();
}

// ═══════════════════════════════════════════════
// Live Threat Intel Feed
// ═══════════════════════════════════════════════

export async function getThreatFeedStatus(): Promise<any> {
  const res = await fetch(`${API_URL}/api/threat-feed/status`, { headers: apiHeaders() });
  return res.json();
}

export async function getThreatSummary(): Promise<any> {
  const res = await fetch(`${API_URL}/api/threat-feed/summary`, { headers: apiHeaders() });
  return res.json();
}

export async function getTopCVEs(limit: number = 10): Promise<any> {
  const res = await fetch(`${API_URL}/api/threat-feed/cves/top?limit=${limit}`, { headers: apiHeaders() });
  return res.json();
}

export async function getExploitedCVEs(limit: number = 10): Promise<any> {
  const res = await fetch(`${API_URL}/api/threat-feed/cves/exploited?limit=${limit}`, { headers: apiHeaders() });
  return res.json();
}

export async function getRecentIOCs(type: string = 'ip', limit: number = 10): Promise<any> {
  const res = await fetch(`${API_URL}/api/threat-feed/iocs/recent?ioc_type=${type}&limit=${limit}`, { headers: apiHeaders() });
  return res.json();
}

export async function getC2Servers(limit: number = 10): Promise<any> {
  const res = await fetch(`${API_URL}/api/threat-feed/c2?limit=${limit}`, { headers: apiHeaders() });
  return res.json();
}

export async function getFeedCounts(): Promise<any> {
  const res = await fetch(`${API_URL}/api/threat-feed/feed-counts`, { headers: apiHeaders() });
  return res.json();
}

export async function triggerThreatPull(): Promise<any> {
  const res = await fetch(`${API_URL}/api/threat-feed/pull`, { method: 'POST', headers: apiHeaders() });
  return res.json();
}

// ═══════════════════════════════════════════════
// PHASE 3: PDF Export
// ═══════════════════════════════════════════════

export async function exportPDF(messages: {role: string; content: string}[], title?: string): Promise<Blob> {
  const res = await fetch(`${API_URL}/api/export/pdf`, {
    method: 'POST',
    headers: apiHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ messages, title: title || 'CyberSentinel Security Report', format: 'pdf' }),
  });
  return res.blob();
}

// ═══════════════════════════════════════════════
// PHASE 3: ELK Stack SIEM
// ═══════════════════════════════════════════════

export async function getElkHealth(): Promise<any> {
  const res = await fetch(`${API_URL}/api/elk/health`, { headers: apiHeaders() });
  return res.json();
}

export async function getElkIndices(): Promise<any> {
  const res = await fetch(`${API_URL}/api/elk/indices`, { headers: apiHeaders() });
  return res.json();
}

export async function elkFailedLogins(hours: number = 24): Promise<any> {
  const res = await fetch(`${API_URL}/api/elk/failed-logins`, {
    method: 'POST',
    headers: apiHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ hours, size: 50 }),
  });
  return res.json();
}

export async function elkLateralMovement(hours: number = 24): Promise<any> {
  const res = await fetch(`${API_URL}/api/elk/lateral-movement`, {
    method: 'POST',
    headers: apiHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ hours, size: 50 }),
  });
  return res.json();
}

export async function elkAlerts(hours: number = 24): Promise<any> {
  const res = await fetch(`${API_URL}/api/elk/alerts`, {
    method: 'POST',
    headers: apiHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ hours, size: 50 }),
  });
  return res.json();
}

export async function seedElk(): Promise<any> {
  const res = await fetch(`${API_URL}/api/elk/seed`, { method: 'POST', headers: apiHeaders() });
  return res.json();
}

export async function getSplunkHealth(): Promise<any> {
  const res = await fetch(`${API_URL}/api/splunk/health`, { headers: apiHeaders() });
  return res.json();
}

export async function getWazuhHealth(): Promise<any> {
  const res = await fetch(`${API_URL}/api/wazuh/health`, { headers: apiHeaders() });
  return res.json();
}

export async function elkSeedSampleData(): Promise<any> {
  const res = await fetch(`${API_URL}/api/elk/seed`, { method: 'POST', headers: apiHeaders() });
  return res.json();
}
