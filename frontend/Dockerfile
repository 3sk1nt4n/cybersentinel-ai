# ══════════════════════════════════════════════════════
# CyberSentinel AI v3.0 — Frontend (Next.js)
# Multi-stage production build with standalone output
# ══════════════════════════════════════════════════════

# ── Stage 1: Dependencies ─────────────────────────────
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci 2>/dev/null || npm install

# ── Stage 2: Build ────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build-time env vars (Next.js inlines these at build)
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ARG NEXT_PUBLIC_API_KEY=
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_API_KEY=$NEXT_PUBLIC_API_KEY

RUN npm run build

# ── Stage 3: Production ──────────────────────────────
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production

# Create non-root user
RUN addgroup --system --gid 1001 sentinel && \
    adduser --system --uid 1001 sentinel

# Copy standalone build output
COPY --from=builder /app/public ./public
COPY --from=builder --chown=sentinel:sentinel /app/.next/standalone ./
COPY --from=builder --chown=sentinel:sentinel /app/.next/static ./.next/static

USER sentinel

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

CMD ["node", "server.js"]
