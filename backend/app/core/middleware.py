"""
CyberSentinel v3.0 - Security Middleware
API key authentication and rate limiting.
"""
import time
from collections import defaultdict
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.config import settings


# ═══════════════════════════════════════════════
# RATE LIMITER — In-memory sliding window
# ═══════════════════════════════════════════════

class RateLimitStore:
    """Simple in-memory rate limiter using sliding window."""

    def __init__(self):
        self._requests: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str, max_requests: int, window_seconds: int = 60) -> bool:
        now = time.time()
        cutoff = now - window_seconds
        # Prune old entries
        self._requests[key] = [t for t in self._requests[key] if t > cutoff]
        if len(self._requests[key]) >= max_requests:
            return False
        self._requests[key].append(now)
        return True

    def remaining(self, key: str, max_requests: int, window_seconds: int = 60) -> int:
        now = time.time()
        cutoff = now - window_seconds
        self._requests[key] = [t for t in self._requests[key] if t > cutoff]
        return max(0, max_requests - len(self._requests[key]))


_rate_store = RateLimitStore()

# Paths that skip auth (health checks, docs)
PUBLIC_PATHS = {"/health", "/docs", "/openapi.json", "/redoc", "/"}

# Paths with stricter rate limits (scans, tool execution)
SCAN_PATHS = {"/api/scan/", "/api/chat/stream"}


def _get_client_ip(request: Request) -> str:
    """Extract client IP, respecting X-Forwarded-For behind reverse proxy."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class AuthMiddleware(BaseHTTPMiddleware):
    """API key authentication middleware.

    If CYBERSENTINEL_API_KEY is set in .env, all non-public endpoints
    require the key via X-API-Key header or ?api_key= query param.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Always allow public paths
        if path in PUBLIC_PATHS:
            return await call_next(request)

        # Allow CORS preflight
        if request.method == "OPTIONS":
            return await call_next(request)

        # If no API key configured, skip auth (open mode)
        if not settings.cybersentinel_api_key:
            return await call_next(request)

        # Check for API key
        api_key = (
            request.headers.get("x-api-key")
            or request.query_params.get("api_key")
        )

        if not api_key or api_key != settings.cybersentinel_api_key:
            return JSONResponse(
                status_code=401,
                content={
                    "error": "Unauthorized",
                    "detail": "Valid API key required. Set X-API-Key header or ?api_key= param.",
                },
            )

        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware — per-IP sliding window."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip rate limiting for health checks
        if path in PUBLIC_PATHS:
            return await call_next(request)

        # Allow CORS preflight
        if request.method == "OPTIONS":
            return await call_next(request)

        client_ip = _get_client_ip(request)

        # Determine rate limit tier
        is_scan = any(path.startswith(p) for p in SCAN_PATHS)
        if is_scan:
            limit = settings.rate_limit_scan_rpm
            key = f"scan:{client_ip}"
        else:
            limit = settings.rate_limit_rpm
            key = f"api:{client_ip}"

        if not _rate_store.is_allowed(key, limit):
            remaining = 0
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "detail": f"Maximum {limit} requests per minute. Try again shortly.",
                },
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)

        # Add rate limit headers
        remaining = _rate_store.remaining(key, limit)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)

        return response
