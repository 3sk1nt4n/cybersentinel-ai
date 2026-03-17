#!/bin/bash
echo "═══════════════════════════════════════════════"
echo "  CyberSentinel AI v2.0 - Setup"
echo "═══════════════════════════════════════════════"
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "[ERROR] Docker is not installed!"
    echo "Install from: https://www.docker.com/products/docker-desktop/"
    exit 1
fi
echo "[OK] Docker found"

# Check Docker running
if ! docker info &> /dev/null; then
    echo "[ERROR] Docker is not running! Start Docker Desktop and try again."
    exit 1
fi
echo "[OK] Docker is running"

# Create .env
if [ ! -f .env ]; then
    cp .env.example .env
    echo "[OK] Created .env from template"
else
    echo "[OK] .env already exists"
fi

# Build and start
echo ""
echo "Starting CyberSentinel v2.0..."
echo "This may take 3-5 minutes on first run."
echo ""
docker compose up -d --build

if [ $? -eq 0 ]; then
    echo ""
    echo "═══════════════════════════════════════════════"
    echo "  CyberSentinel AI v2.0 is RUNNING!"
    echo ""
    echo "  Dashboard:  http://localhost:3000"
    echo "  API:        http://localhost:8000"
    echo "  API Docs:   http://localhost:8000/docs"
    echo "  Neo4j:      http://localhost:7474"
    echo "═══════════════════════════════════════════════"
else
    echo ""
    echo "[ERROR] Something went wrong. Check the errors above."
fi
