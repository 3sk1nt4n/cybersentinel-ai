# ══════════════════════════════════════════════════════
# CyberSentinel AI v3.0 — Backend (FastAPI)
# Multi-stage production build with non-root user
# ══════════════════════════════════════════════════════

# ── Stage 1: Dependencies ─────────────────────────────
FROM python:3.12-slim AS deps

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Stage 2: Production ──────────────────────────────
FROM python:3.12-slim

LABEL maintainer="CyberSentinel AI — SolventCyber.com"

WORKDIR /app

# Install only runtime deps + Docker CLI (for sandbox exec)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl && \
    curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.4.1.tgz | tar xz --strip-components=1 -C /usr/local/bin docker/docker && \
    rm -rf /var/lib/apt/lists/*

# Copy Python packages from deps stage
COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin

# Create non-root user
RUN groupadd -r sentinel && useradd -r -g sentinel -d /app sentinel

# Copy application code
COPY . .

# Create data directory with correct ownership
RUN mkdir -p /app/data && chown -R sentinel:sentinel /app/data

EXPOSE 8000

# Run as non-root (except docker exec needs docker group access)
# The docker socket is mounted read-only; we add sentinel to docker group at runtime
# For now, run as root since docker exec requires it
USER root

# Production: no --reload, with access logging
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--access-log", "--log-level", "info"]
