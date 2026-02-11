# 🏗️ CyberSentinel v2.0 — Architecture

## Overview

```
┌──────────────────────────────────────────────────────┐
│                    USER BROWSER                       
│              http://localhost:3000                    
└────────────────────┬─────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────┐
│              FRONTEND (Next.js)                       │
│  - React Dashboard                                    │
│  - 43 Tool Sidebar                                    │
│  - Streaming Chat UI                                  │
│  - Provider Selector                                  │
│  Port: 3000                                           │
└────────────────────┬─────────────────────────────────┘
                     │ HTTP/SSE
┌────────────────────▼─────────────────────────────────┐
│              BACKEND (FastAPI)                        
│  - AI Router (provider-agnostic)                      │
│  - Chat Streaming (SSE)                               │
│  - Tool Definitions API                               │
│  - Health Checks                                      │
│  Port: 8000                                           │
└───┬──────────┬──────────┬──────────┬─────────────────┘
    │          │          │          │
┌───▼───┐ ┌───▼───┐ ┌───▼───┐ ┌───▼───┐
│OLLAMA │ │CLAUDE │ │OPENAI │ │OPENR. │  ← AI Providers
│ Local │ │  API  │ │  API  │ │  API  │
│:11434 │ │ Cloud │ │ Cloud │ │ Cloud │
└───────┘ └───────┘ └───────┘ └───────┘

┌─────────────┐  ┌─────────────┐
│   NEO4J     │  │  CHROMADB   │  ← Data Stores
│ Graph DB    │  │ Vector RAG  │
│ :7474/:7687 │  │ :8100       │
└─────────────┘  └─────────────┘
```

## Services

| Service | Technology | Purpose | Port |
|---------|-----------|---------|------|
| Frontend | Next.js 14 + Tailwind | Dashboard UI | 3000 |
| Backend | FastAPI + Python 3.12 | API + AI Router | 8000 |
| Ollama | ollama/ollama | Local AI models | 11434 |
| Neo4j | Neo4j 5 Community | Graph database | 7474, 7687 |
| ChromaDB | chromadb/chroma | RAG vector store | 8100 |

## AI Router Architecture

The AI Router is the core abstraction that makes CyberSentinel provider-agnostic:

```python
# All providers implement the same interface:
async def stream_PROVIDER(messages, model) -> AsyncGenerator[str, None]:
    """Yields SSE-formatted chunks: data: {"token": "..."}\n\n"""
```

The router selects the provider based on:
1. User's dashboard selection (real-time switching)
2. `.env` default (`AI_PROVIDER=ollama`)
3. API request override (`provider` parameter)

## Key Improvements over v1.0

| v1.0 (single HTML file) | v2.0 (Docker architecture) |
|-------------------------|---------------------------|
| 493 hardcoded cached responses | Real AI streaming + RAG grounding |
| Works on one machine only | `docker compose up` anywhere |
| Ollama-only + basic cloud | 4 providers, any model |
| No database | Neo4j graph + ChromaDB RAG |
| Manual nginx setup | Docker handles networking |
| No API | Full REST API at /docs |
| All 33 tools with queries |
| No knowledge base | Seeded security KB (MITRE, CIS, NIST) |

## Phase 2 Features

- **Neo4j Graph Intelligence**: Attack surface mapping — assets, vulnerabilities, techniques, IOCs as a connected graph. API for adding nodes, creating relationships, and querying attack paths.
- **ChromaDB RAG Engine**: 5 knowledge base collections (security_kb, mitre_attack, cve_data, compliance, user_docs). Document chunking with overlap, multi-collection search, automatic context injection into AI prompts.
- **Seed Knowledge Base**: Pre-built security knowledge covering MITRE ATT&CK techniques, CIS Controls, NIST 800-53, PCI-DSS, HIPAA, incident response procedures, and vulnerability prioritization.
- **All 43 Tool Queries**: Every tool now has 5-10 sample queries (up from 8 tools in Phase 1).
- **Service Health Dashboard**: Real-time status of all 5 services (Ollama, Neo4j, ChromaDB, Claude, OpenAI).
- **File Upload to KB**: Upload text files directly into the RAG knowledge base.

## Roadmap

- **v2.4:** MCP protocol for tool integration

- **v2.5:** Multi-user auth and role-based access
