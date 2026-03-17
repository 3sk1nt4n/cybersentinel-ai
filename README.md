# CyberSentinel AI v3.0

### Agentic Multi-Tool Cybersecurity Platform

**33 real security tools. Provider-agnostic AI. Production-ready Docker stack. 100% local by default.**

[![Tools](https://img.shields.io/badge/Security_Tools-33-00f0ff?style=for-the-badge&logo=hackthebox&logoColor=white)](https://github.com/3sk1nt4n/cybersentinel-ai)
[![Docker](https://img.shields.io/badge/Docker-Production-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://github.com/3sk1nt4n/cybersentinel-ai)
[![AI](https://img.shields.io/badge/AI-Agentic-a855f7?style=for-the-badge&logo=openai&logoColor=white)](https://github.com/3sk1nt4n/cybersentinel-ai)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

<br>

<p align="center">
  <img src="https://img.shields.io/badge/Nmap-Scanner-00f0ff?style=flat-square" />
  <img src="https://img.shields.io/badge/Nuclei-CVE_Detection-ff3355?style=flat-square" />
  <img src="https://img.shields.io/badge/SQLMap-Injection-ff6600?style=flat-square" />
  <img src="https://img.shields.io/badge/Nikto-Web_Scan-a855f7?style=flat-square" />
  <img src="https://img.shields.io/badge/Shodan-Intel-00ff88?style=flat-square" />
  <img src="https://img.shields.io/badge/MITRE_ATT&CK-Framework-yellow?style=flat-square" />
  <img src="https://img.shields.io/badge/ELK-SIEM-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/Neo4j-Graph-008CC1?style=flat-square" />
</p>

---

## What Is This?

CyberSentinel AI is an **agentic cybersecurity platform** that runs entirely on your local machine through Docker. Unlike typical AI chatbots that just suggest commands, CyberSentinel **actually executes** security tools like Nmap, Nikto, Nuclei, SQLMap, and ZAP inside an isolated sandbox container, then uses AI to analyze the results in real time.

- Every scanner runs live. Every API call is real. Every result is verified.
- Switch between **4 AI providers** mid-conversation (Ollama, Claude, GPT, OpenRouter)
- **Neo4j knowledge graph** maps attack surfaces, MITRE techniques, and threat relationships
- **ChromaDB RAG engine** grounds AI responses in real security knowledge (MITRE, CIS, NIST)
- **ELK Stack SIEM** integration with pre-seeded security events for log analysis
- **Live threat intel** pulled from NVD, CISA KEV, EPSS, OTX, and Abuse.ch

No cloud dependencies required. No subscriptions. No fake outputs.

---

## Quick Start

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- 8GB+ RAM recommended

### 1. Clone and configure
```bash
git clone https://github.com/3sk1nt4n/cybersentinel-ai.git
cd cybersentinel-ai
cp .env.example .env    # Windows: copy .env.example .env
```

### 2. Launch the stack
```bash
docker compose up -d --build
```
First run pulls all images (~5-10 min). After that, startup takes ~30 seconds.

### 3. Pull the AI model
```bash
docker exec -it cybersentinel-v2-ollama-1 ollama pull qwen2.5:7b
```
Downloads the local AI model (~4GB). One-time only.

### 4. Open the dashboard
```
http://localhost:3000
```

All 33 tools are loaded and ready. Start scanning.

---

## The Full Arsenal - 33 Tools

| Category | Tools | Count |
|----------|-------|-------|
| **Live Scanners** | Nmap, SSL/TLS, DNS Recon, Nikto, Nuclei, SQLMap, Subfinder, WHOIS, HTTP Headers, Ping/Traceroute, OWASP ZAP | 11 |
| **Threat Intel APIs** | Shodan, VirusTotal, AbuseIPDB, AlienVault OTX, NVD/CISA KEV | 5 |
| **SIEM Integration** | ELK Stack, Splunk, Wazuh | 3 |
| **AI Detection** | Zeek Analyzer, Threat Detection, Log Analyzer, IOC Extractor, Email Phishing Analyzer | 5 |
| **Threat Hunting** | SIEM Query Generator, YARA Rules, Sigma Rules, Snort/Suricata Rules | 4 |
| **Compliance** | MITRE ATT&CK, MITRE ATLAS, NIST/CIS, HIPAA/PCI-DSS, SOC 2/FedRAMP | 5 |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Docker Compose                       │
├───────────┬───────────┬───────────┬─────────────────────┤
│ Frontend  │  Backend  │   Kali    │      Ollama         │
│ Next.js   │  FastAPI  │  Sandbox  │    Local AI         │
│ :3000     │  :8000    │  (scans)  │    :11434           │
├───────────┴───────────┼───────────┼─────────────────────┤
│    Elasticsearch      │   Neo4j   │     ChromaDB        │
│    (ELK SIEM)         │  (Graph)  │     (RAG/KB)        │
│    :9200              │   :7687   │                     │
└───────────────────────┴───────────┴─────────────────────┘
```

| Container | Purpose | Port |
|-----------|---------|------|
| **Frontend** | Next.js dashboard with streaming chat UI | 3000 |
| **Backend** | FastAPI agent engine, AI router, tool orchestration | 8000 |
| **Sandbox** | Isolated Kali container for running all scans | - |
| **Ollama** | Local AI model inference (qwen2.5:7b default) | 11434 |
| **Neo4j** | Knowledge graph - attack surfaces, MITRE mappings | 7474, 7687 |
| **Elasticsearch** | ELK SIEM - security event storage and analysis | 9200 |
| **Kibana** | ELK visualization dashboard | 5601 |

### Key Design Decisions

- **Agentic execution** - AI classifies intent, selects tools, executes up to 5 concurrently, then analyzes real results
- **Provider-agnostic** - Swap AI providers mid-conversation without losing context
- **Multi-stage Docker builds** - Production-optimized images with non-root users
- **Streaming SSE** - Results stream back in real time with stop/cancel support
- **RAG-grounded responses** - ChromaDB injects relevant security knowledge into every AI prompt
- **Input/output guardrails** - Blocks prompt injection, SSRF, and system prompt leakage

---

## API Keys (All Optional)

The platform works fully offline with Ollama. API keys unlock additional capabilities:

| Key | Source | Unlocks |
|-----|--------|---------|
| `ANTHROPIC_API_KEY` | [console.anthropic.com](https://console.anthropic.com) | Claude AI (cloud) |
| `OPENAI_API_KEY` | [platform.openai.com](https://platform.openai.com) | GPT-4o (cloud) |
| `OPENROUTER_API_KEY` | [openrouter.ai](https://openrouter.ai) | 100+ AI models |
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io) | Shodan threat intel |
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://www.virustotal.com/gui/my-apikey) | File and IP scanning |
| `ABUSEIPDB_API_KEY` | [abuseipdb.com](https://www.abuseipdb.com/account/api) | IP reputation checks |
| `OTX_API_KEY` | [otx.alienvault.com](https://otx.alienvault.com/settings) | AlienVault OTX feeds |

### Production Auth

For deployment, enable API key authentication:

```env
API_AUTH_ENABLED=true
API_KEY=your-long-random-secret
NEXT_PUBLIC_API_KEY=same-value-as-API_KEY
```

---

## Commands

```bash
docker compose up -d --build          # Start everything
docker compose down                    # Stop everything
docker compose down -v                 # Stop and wipe all data
docker compose logs -f backend         # Tail backend logs
docker compose ps                      # Check container status
docker compose up -d --build --force-recreate  # Full rebuild
```

---

## Security

- All scans execute inside an isolated Docker container
- The `.env.example` file contains only empty placeholders
- Never commit real API keys to any repository
- Only scan targets you own or have explicit written permission to test
- Unauthorized scanning is illegal under the CFAA
- Safe test targets: `scanme.nmap.org`, `testphp.vulnweb.com`

---

## Contributing

Contributions welcome. Fork, improve, submit a PR.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add your feature"`
4. Push: `git push origin feature/your-feature`
5. Open a Pull Request

---

## License

MIT License - use it, fork it, make it better.

---

<p align="center">
  Built by <a href="https://www.credly.com/users/eskintan/badges#credly"><strong>3sk1nt4n</strong></a> | Powered by <a href="https://solventcyber.com"><strong>SolventCyber.com</strong></a>
</p>
