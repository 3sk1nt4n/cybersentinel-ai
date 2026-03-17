# 📖 CyberSentinel v3.0 — Detailed Setup Guide

This guide assumes **zero coding knowledge**. Every step is explained.

---

## What is This?

CyberSentinel AI is a cybersecurity platform with 33 security tools powered by AI. Think of it as having a senior security engineer available 24/7 that can:
- Generate detection rules (SIEM, YARA, Sigma, Snort)
- Analyze threats and vulnerabilities
- Run compliance audits (CIS, NIST, HIPAA, PCI-DSS)
- Map attacks to MITRE ATT&CK
- And much more

## How it Works

Everything runs in **Docker containers** — like isolated mini-computers inside your computer. You don't need to install Python, Node.js, or anything else.

```
Your Computer
├── Docker Container: Frontend (the website you see)
├── Docker Container: Backend (the brain/API)
├── Docker Container: Ollama (local AI model)
├── Docker Container: Neo4j (graph database)
└── Docker Container: ChromaDB (knowledge base)
```

---

## Step-by-Step Setup

### 1. Install Docker Desktop

**What is Docker?** It's software that runs applications in isolated containers.

- Go to [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/)
- Download for your OS (Windows/Mac/Linux)
- Install it (just click Next/Install through the wizard)
- **Open Docker Desktop** after installation
- Wait until the whale icon in your system tray shows "Docker Desktop is running"

### 2. Install Git

**What is Git?** It's a tool for downloading and managing code.

- Go to [git-scm.com](https://git-scm.com/)
- Download and install (use all default settings)

### 3. Download CyberSentinel

Open a **terminal**:
- **Windows:** Press `Win + R`, type `cmd`, press Enter
- **Mac:** Press `Cmd + Space`, type `Terminal`, press Enter
- **Linux:** Press `Ctrl + Alt + T`

Type these commands (copy-paste each line):

```bash
git clone https://github.com/YOUR_USERNAME/cybersentinel-v2.git
cd cybersentinel-v2
```

### 4. Configure (Optional)

```bash
# Windows:
copy .env.example .env

# Mac/Linux:
cp .env.example .env
```

**Default settings work out of the box** — Ollama local AI needs no API keys.

If you want to add cloud AI providers, open `.env` in a text editor and add your keys:
- `ANTHROPIC_API_KEY=sk-ant-...` (for Claude)
- `OPENAI_API_KEY=sk-...` (for GPT-4o)
- `OPENROUTER_API_KEY=sk-or-...` (for 100+ models)

### 5. Launch!

```bash
docker compose up -d
```

**What this does:**
- Downloads all needed software (first time only, ~5 minutes)
- Starts all 5 services
- `-d` means "run in background"

### 6. Open the Dashboard

Go to **[http://localhost:3000](http://localhost:3000)** in your browser.

That's it! 🎉

---

## Daily Usage

| Action | Command |
|--------|---------|
| Start CyberSentinel | `docker compose up -d` |
| Stop CyberSentinel | `docker compose down` |
| View live logs | `docker compose logs -f` |
| Rebuild after changes | `docker compose up -d --build` |
| Check status | `docker compose ps` |

---

## Troubleshooting

### "docker compose" not found
- Make sure Docker Desktop is installed and running
- Try `docker-compose` (with a hyphen) instead

### "Cannot connect to Ollama"
- Ollama needs time to download the AI model (~4GB) on first run
- Check: `docker compose logs ollama`
- Wait a few minutes and try again

### Port already in use
- Another app is using port 3000, 8000, or 7474
- Stop the other app, or change ports in `docker-compose.yml`

### Everything is slow
- Ollama AI runs on your CPU by default
- For faster responses, use cloud providers (Claude/GPT) by adding API keys to `.env`
- If you have an NVIDIA GPU, uncomment the GPU section in `docker-compose.yml`

---

## Uploading to GitHub

### First Time Setup

1. Go to [github.com](https://github.com/) and create an account (if you don't have one)
2. Click the **+** button → **New repository**
3. Name: `cybersentinel-v2`
4. Select **Private** (keep your code private)
5. Click **Create repository**
6. In your terminal:

```bash
cd cybersentinel-v2
git init
git add .
git commit -m "CyberSentinel AI v3.0 — Initial release"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/cybersentinel-v2.git
git push -u origin main
```

Replace `YOUR_USERNAME` with your actual GitHub username.

### After Making Changes

```bash
git add .
git commit -m "describe what you changed"
git push
```
