"""
CyberSentinel v2.0 - Settings Router (Phase 3)
Manage configuration from the UI - API keys, provider, model.
Changes persist to .env file so they survive container restarts.
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from app.core.config import settings
import os

router = APIRouter(prefix="/settings", tags=["settings"])

# Map settings field names to .env variable names
_FIELD_TO_ENV = {
    "ai_provider": "AI_PROVIDER",
    "ollama_model": "OLLAMA_MODEL",
    "anthropic_api_key": "ANTHROPIC_API_KEY",
    "claude_model": "CLAUDE_MODEL",
    "openai_api_key": "OPENAI_API_KEY",
    "openai_model": "OPENAI_MODEL",
    "openrouter_api_key": "OPENROUTER_API_KEY",
    "openrouter_model": "OPENROUTER_MODEL",
    "shodan_api_key": "SHODAN_API_KEY",
    "virustotal_api_key": "VIRUSTOTAL_API_KEY",
    "otx_api_key": "OTX_API_KEY",
    "abuseipdb_api_key": "ABUSEIPDB_API_KEY",
    "censys_api_id": "CENSYS_API_ID",
    "censys_api_secret": "CENSYS_API_SECRET",
}

# Path to persistent config (uses the backend_data volume that already works)
_CONFIG_DIR = "/app/data"
_ENV_FILE_PERSISTENT = os.path.join(_CONFIG_DIR, "settings.env")
_ENV_FILE_DEFAULT = "/app/.env"
_SECRET_FIELDS = {
    "anthropic_api_key", "openai_api_key", "openrouter_api_key",
    "shodan_api_key", "virustotal_api_key", "otx_api_key",
    "abuseipdb_api_key", "censys_api_secret"
}


def _get_env_path() -> str:
    """Get the best config file path - persistent data dir if writable, else default."""
    if os.path.exists(_CONFIG_DIR) and os.access(_CONFIG_DIR, os.W_OK):
        return _ENV_FILE_PERSISTENT
    return _ENV_FILE_DEFAULT


def _load_persistent_settings():
    """Load settings from persistent config file on startup (if it exists)."""
    env_path = _get_env_path()
    if not os.path.exists(env_path):
        return

    try:
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()

                # Map ENV_KEY to settings field
                env_to_field = {v: k for k, v in _FIELD_TO_ENV.items()}
                field = env_to_field.get(key)
                if field and value:
                    setattr(settings, field, value)

        print(f"[Settings] Loaded persistent config from {env_path}")
    except Exception as e:
        print(f"[Settings] Warning: Could not load persistent config: {e}")


# Load persistent settings on import (backend startup)
_load_persistent_settings()


def _persist_to_env(updates: dict[str, str]):
    """Write updated non-secret settings to persistent config file."""
    try:
        filtered = {k: v for k, v in updates.items() if settings.allow_plaintext_secret_persistence or k not in _SECRET_FIELDS}
        if not filtered and updates:
            print("[Settings] Secret updates applied in-memory only (plaintext persistence disabled)")
            return
        env_path = _get_env_path()

        # Read current file
        if os.path.exists(env_path):
            with open(env_path, "r") as f:
                lines = f.readlines()
        else:
            lines = ["# CyberSentinel persistent settings\n"]

        # For each update, find and replace the line, or append if not found
        for field_name, value in filtered.items():
            env_key = _FIELD_TO_ENV.get(field_name)
            if not env_key:
                continue

            found = False
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith(f"{env_key}=") or stripped.startswith(f"# {env_key}="):
                    lines[i] = f"{env_key}={value}\n"
                    found = True
                    break

            if not found:
                lines.append(f"{env_key}={value}\n")

        # Write back
        with open(env_path, "w") as f:
            f.writelines(lines)
        try:
            os.chmod(env_path, 0o600)
        except Exception:
            pass

        print(f"[Settings] Persisted {len(filtered)} setting(s) to {env_path}")

    except Exception as e:
        print(f"[Settings] Warning: Could not persist: {e}")


class UpdateSettings(BaseModel):
    ai_provider: Optional[str] = None
    ollama_model: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    claude_model: Optional[str] = None
    openai_api_key: Optional[str] = None
    openai_model: Optional[str] = None
    openrouter_api_key: Optional[str] = None
    openrouter_model: Optional[str] = None
    shodan_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None


@router.get("/")
async def get_settings():
    """Get current settings (API keys are masked)."""
    def mask(key: Optional[str]) -> str:
        if not key:
            return ""
        if len(key) <= 8:
            return "****"
        return key[:4] + "..." + key[-4:]

    return {
        "ai_provider": settings.ai_provider,
        "ollama_model": settings.ollama_model,
        "claude_model": settings.claude_model,
        "openai_model": settings.openai_model,
        "openrouter_model": settings.openrouter_model,
        "keys": {
            "anthropic": mask(settings.anthropic_api_key),
            "openai": mask(settings.openai_api_key),
            "openrouter": mask(settings.openrouter_api_key),
            "shodan": mask(settings.shodan_api_key),
            "virustotal": mask(settings.virustotal_api_key),
            "otx": mask(settings.otx_api_key),
            "abuseipdb": mask(settings.abuseipdb_api_key),
            "censys_id": mask(settings.censys_api_id),
        },
    }


@router.post("/update")
async def update_settings(req: UpdateSettings):
    """Update settings at runtime AND persist to .env file."""
    updated = []
    env_updates = {}

    # Apply each field if provided
    fields = [
        ("ai_provider", "ai_provider"),
        ("ollama_model", "ollama_model"),
        ("anthropic_api_key", "anthropic_api_key"),
        ("claude_model", "claude_model"),
        ("openai_api_key", "openai_api_key"),
        ("openai_model", "openai_model"),
        ("openrouter_api_key", "openrouter_api_key"),
        ("openrouter_model", "openrouter_model"),
        ("shodan_api_key", "shodan_api_key"),
        ("virustotal_api_key", "virustotal_api_key"),
        ("otx_api_key", "otx_api_key"),
        ("abuseipdb_api_key", "abuseipdb_api_key"),
        ("censys_api_id", "censys_api_id"),
        ("censys_api_secret", "censys_api_secret"),
    ]

    for req_field, settings_field in fields:
        value = getattr(req, req_field, None)
        if value is not None:
            setattr(settings, settings_field, value)
            updated.append(settings_field)
            env_updates[settings_field] = value

    # Persist to .env file
    if env_updates:
        _persist_to_env(env_updates)

    return {"success": True, "updated": updated, "persisted": bool(env_updates)}
