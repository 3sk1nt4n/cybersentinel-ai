@echo off
echo ═══════════════════════════════════════════════
echo   CyberSentinel AI v2.0 - Windows Setup
echo ═══════════════════════════════════════════════
echo.

:: Check Docker
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not installed!
    echo Please install Docker Desktop from:
    echo   https://www.docker.com/products/docker-desktop/
    echo.
    echo After installing, restart this script.
    pause
    exit /b 1
)
echo [OK] Docker found

:: Check Docker is running
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker Desktop is not running!
    echo Please start Docker Desktop and try again.
    pause
    exit /b 1
)
echo [OK] Docker is running

:: Create .env if it doesn't exist
if not exist .env (
    copy .env.example .env
    echo [OK] Created .env from template
    echo.
    echo ════════════════════════════════════════
    echo   OPTIONAL: Edit .env to add API keys
    echo   (CyberSentinel works without them -
    echo    Ollama local mode is the default)
    echo ════════════════════════════════════════
    echo.
) else (
    echo [OK] .env already exists
)

:: Build and start
echo.
echo Starting CyberSentinel v2.0...
echo This may take 3-5 minutes on first run.
echo.
docker compose up -d --build

if %errorlevel% equ 0 (
    echo.
    echo ═══════════════════════════════════════════════
    echo   CyberSentinel AI v2.0 is RUNNING!
    echo.
    echo   Dashboard:  http://localhost:3000
    echo   API:        http://localhost:8000
    echo   API Docs:   http://localhost:8000/docs
    echo   Neo4j:      http://localhost:7474
    echo ═══════════════════════════════════════════════
    echo.
    echo To stop:    docker compose down
    echo To restart: docker compose up -d
    echo To logs:    docker compose logs -f
) else (
    echo.
    echo [ERROR] Something went wrong. Check the errors above.
)

pause
