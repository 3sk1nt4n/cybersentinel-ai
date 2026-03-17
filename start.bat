@echo off
REM ══════════════════════════════════════════════════════
REM CyberSentinel AI v2.0 - Auto Setup (Windows)
REM Creates .env from .env.example if it doesn't exist
REM ══════════════════════════════════════════════════════

if not exist ".env" (
    if exist ".env.example" (
        copy .env.example .env >nul
        echo ✅ Created .env from .env.example
        echo    Edit .env to add your API keys if needed.
    ) else (
        echo ❌ No .env.example found. Cannot create .env
        exit /b 1
    )
) else (
    echo ✅ .env already exists
)

echo.
echo 🚀 Starting CyberSentinel AI v2.0...
echo    Dashboard: http://localhost:3000
echo    API:       http://localhost:8000
echo.

docker compose up -d --build %*
