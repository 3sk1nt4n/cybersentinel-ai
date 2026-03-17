#!/bin/bash
# ══════════════════════════════════════════════════════
# CyberSentinel AI v2.0 - Auto Setup
# Creates .env from .env.example if it doesn't exist
# ══════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$SCRIPT_DIR/.env" ]; then
    if [ -f "$SCRIPT_DIR/.env.example" ]; then
        cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
        echo "✅ Created .env from .env.example"
        echo "   Edit .env to add your API keys if needed."
    else
        echo "❌ No .env.example found. Cannot create .env"
        exit 1
    fi
else
    echo "✅ .env already exists"
fi

echo ""
echo "🚀 Starting CyberSentinel AI v2.0..."
echo "   Dashboard: http://localhost:3000"
echo "   API:       http://localhost:8000"
echo ""

docker compose up -d --build "$@"
