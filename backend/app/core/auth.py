"""Simple API key auth dependency for protecting control-plane endpoints."""
import logging
from fastapi import Header, HTTPException
from app.core.config import settings, is_api_auth_active

logger = logging.getLogger("cybersentinel")


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Require X-API-Key header when API auth is fully active."""
    if not is_api_auth_active():
        if settings.api_auth_enabled and not settings.api_key:
            logger.warning("API_AUTH_ENABLED=true but API_KEY is missing; auth checks are bypassed in non-production")
        return
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Unauthorized")
