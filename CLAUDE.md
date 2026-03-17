# CyberSentinel AI v3.0 - Project Rules

## Style Rules
- NEVER use em-dashes (the long dash). Always use regular hyphens/dashes (-).
- Keep responses concise and direct. No trailing summaries.
- No emojis unless explicitly requested.

## Code Rules
- Read files before editing them.
- Prefer editing existing files over creating new ones.
- Do not add unnecessary comments, docstrings, or type annotations to unchanged code.
- Do not over-engineer - only make changes that are directly requested.

## Git Rules
- Only commit when explicitly asked.
- Never force push without explicit permission.
- Use regular dashes in commit messages, never em-dashes.
- Never commit .env files (contains real API keys).

## Project Context
- Stack: Next.js 14 frontend, FastAPI backend, Docker Compose orchestration
- 33 security tools across 6 categories
- AI providers: Ollama (local default), Claude, OpenAI, OpenRouter
- Data stores: Neo4j (graph), ChromaDB (RAG), Elasticsearch (SIEM)
- Sandbox: Isolated Kali container for scan execution
- GitHub repo: https://github.com/3sk1nt4n/cybersentinel-ai
- GitHub token lacks `workflow` scope (can't push .github/workflows/)
