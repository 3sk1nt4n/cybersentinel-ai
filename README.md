# 🛡️ CyberSentinel AI - Agentic CyberSecurity Arsenal

**33 real security tools. One AI brain. Runs 100% locally on your machine. Free.**

![CyberSentinel AI Dashboard](https://img.shields.io/badge/Tools-33-00f0ff?style=for-the-badge&logo=hackthebox&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![AI](https://img.shields.io/badge/AI-Agentic-a855f7?style=for-the-badge&logo=openai&logoColor=white)

---

## What Is This?

CyberSentinel AI is an agentic cybersecurity platform that runs entirely on your local machine through Docker. Unlike typical AI chatbots that just suggest commands, CyberSentinel actually executes security tools like Nmap, Nikto, Nuclei, SQLMap, and ZAP inside an isolated Kali Linux sandbox, then uses AI to break down the results for you.

No cloud dependencies. No subscriptions. No fake outputs. Everything you see is real.

---

## ⚡ Quick Start (5 Minutes)

### What You Need
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- [Git](https://git-scm.com/downloads)
- 8GB or more RAM recommended

### Step 1 - Clone the Repo
```bash
git clone https://github.com/3sk1nt4n/cybersentinel-ai.git
cd cybersentinel-ai
```

### Step 2 - Set Up Your Environment
```bash
# Windows:
copy .env.example .env
notepad .env

# Mac/Linux:
cp .env.example .env
nano .env
```

### 🔑 API Keys Setup

The platform works fully offline with Ollama, which is a free local AI model. All API keys below are optional. Add them if you want to unlock extra features.

| Key | Where to Get It (Free Tier) | What It Unlocks |
|-----|---------------------------|-----------------|
| `ANTHROPIC_API_KEY` | [console.anthropic.com](https://console.anthropic.com) | Claude AI model (cloud) |
| `OPENAI_API_KEY` | [platform.openai.com](https://platform.openai.com) | GPT-4o model (cloud) |
| `OPENROUTER_API_KEY` | [openrouter.ai](https://openrouter.ai) | Access to 100+ AI models |
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io) | Shodan threat intel lookups |
| `VIRUSTOTAL_API_KEY` | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | VirusTotal file and IP scanning |
| `ABUSEIPDB_API_KEY` | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) | IP reputation checks |
| `OTX_API_KEY` | [otx.alienvault.com/settings](https://otx.alienvault.com/settings) | AlienVault OTX threat feeds |

For production, set internal app auth keys in `.env`:
- `API_AUTH_ENABLED=true`
- `API_KEY=<long-random-value>`
- `NEXT_PUBLIC_API_KEY=<same-value-as-API_KEY>`

For local/dev quick start, you can leave `API_AUTH_ENABLED=false`.

> **Note:** The `.env.example` file only has placeholders. You need to set your own keys and never commit real secrets to a public repository.

### Step 3 - Launch Everything
```bash
docker compose up -d --build
```
The first run pulls all the Docker images, which takes about 5-10 minutes depending on your internet speed. After that, startup takes around 30 seconds.

### Step 4 - Pull the AI Model
```bash
docker exec -it cybersentinel-ollama ollama pull qwen2.5:7b
```
You do not need to install Ollama separately. It is already included in the Docker stack. This command downloads the AI model (about 4GB) into the Ollama container. You only need to do this once. After that, the model stays cached and loads automatically every time you start the stack.

### Step 5 - Open the Dashboard
```
http://localhost:3000
```

All 33 tools are loaded and ready to go. Start scanning.

---

## 🎯 The Full Arsenal - 33 Tools Across 6 Categories

### 🔴 Live Scanners (11)
Nmap Scanner, SSL/TLS Checker, DNS Recon, Nikto Scanner, Nuclei Scanner, SQLMap Scanner, Subfinder, WHOIS Lookup, HTTP Headers, Ping/Traceroute, OWASP ZAP

### 🔵 Threat Intel APIs (5)
Shodan API, VirusTotal API, AbuseIPDB API, OTX AlienVault, NVD / CISA KEV

### 🟢 SIEM Integration (3)
ELK Stack SIEM, Splunk SIEM, Wazuh SIEM

### 🟣 AI Detection and Analysis (5)
Zeek Analyzer, Threat Detection, Log Analyzer, IOC Extractor, Email Phishing Analyzer

### 🟡 Threat Hunting and Rules (4)
SIEM Query Generator, YARA Rules, Sigma Rules, Snort/Suricata Rules

### 🟠 Frameworks and Compliance (5)
MITRE ATT&CK, MITRE ATLAS, NIST/CIS, HIPAA/PCI-DSS, SOC 2/FedRAMP

---

## 🏗️ How It's Built

```
┌──────────────────────────────────────────────────
│                  Docker Compose                  
├──────────┬──────────┬──────────┬────────────────┤
│ Frontend │ Backend  │  Kali    │    Ollama      │
│ Next.js  │ FastAPI  │ Sandbox  │  Local AI      │
│ :3000    │ :8000    │ (scans)  │  :11434        │
├──────────┴──────────┼──────────┼────────────────┤
│   Elasticsearch     │  Neo4j   │   ChromaDB     │
│   (ELK SIEM)        │ (Graph)  │   (RAG/KB)     │
│   :9200             │  :7687   │   :8001        │
└─────────────────────┴──────────┴────────────────┘
```

**What makes it fast and reliable:**
- **Concurrent execution** - The agent can fire up to 5 tools at the same time
- **508 pre-cached responses** - Common queries come back in under 50ms with no AI inference needed
- **Streaming responses** - Results stream back in real time with the ability to stop mid-generation
- **Multi-AI router** - Switch between Ollama, Claude, OpenAI, or OpenRouter mid-conversation
- **Smart intent classifier** - Figures out which tool to use before the AI even responds
- **Live threat feeds** - Pulls from NVD, CISA KEV, EPSS, OTX, and Abuse.ch every 30 seconds
- **Knowledge graph** - Neo4j maps out MITRE ATT&CK techniques and how threats connect to each other
- **RAG pipeline** - ChromaDB stores and searches through uploaded documents, logs, and security knowledge

---

## 🐋 Container Stack

| Container | What It Does | Port |
|-----------|-------------|------|
| Frontend | Next.js dashboard | 3000 |
| Backend | FastAPI and agent engine | 8000 |
| Kali Sandbox | Runs all scans in isolation | - |
| Ollama | Local AI model inference | 11434 |
| Elasticsearch | ELK SIEM for log analysis | 9200 |
| Neo4j | Knowledge graph database | 7474, 7687 |
| ChromaDB | Vector store for RAG | 8001 |

---

## 📋 Useful Commands

```bash
# Start everything
docker compose up -d --build

# Stop everything
docker compose down

# Stop and wipe all data (clean slate)
docker compose down -v

# Check the logs
docker compose logs -f backend

# Rebuild after making code changes
docker compose up -d --build --force-recreate
```

---

## 🔒 Security Notice

- The `.env.example` file only contains empty placeholders, not real API keys
- Never commit your actual API keys to any repository
- All scans run inside an isolated Docker container for safety
- Only scan targets you own or have explicit written permission to test
- Unauthorized scanning is illegal under the Computer Fraud and Abuse Act (CFAA)
- Use the safe test targets for practice: `scanme.nmap.org` and `testphp.vulnweb.com`

---

## 🤝 Want to Contribute?

Contributions are welcome. Fork it, improve it, and submit a PR.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add your feature"`
4. Push it up: `git push origin feature/your-feature`
5. Open a Pull Request

---

## 📄 License

MIT License - use it, fork it, break it, make it better.

---

Built by [🏅 3sk1nt4n](https://www.credly.com/users/eskintan/badges#credly)
