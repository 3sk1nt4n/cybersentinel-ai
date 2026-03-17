"""
CyberSentinel v3.0 - Response Cache Service
Serves 493 pre-built expert responses for sample queries.
Falls through to AI for free-form questions.
"""
import json
import os
import re
from app.core.logging import get_logger

logger = get_logger(__name__)

_cache: dict[str, str] = {}


def _normalize(text: str) -> str:
    """Normalize query text for fuzzy matching."""
    t = text.lower().strip()
    t = re.sub(r'[^a-z0-9\s]', '', t)
    t = re.sub(r'\s+', ' ', t)
    return t


def load_cache():
    """Load cached responses from JSON file."""
    global _cache
    if _cache:
        return
    path = os.path.join(os.path.dirname(__file__), '..', 'data', 'cached_responses.json')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            raw = json.load(f)
        # Build normalized lookup
        for key, value in raw.items():
            _cache[_normalize(key)] = value
    except Exception as e:
        logger.error(f"Failed to load: {e}")


def get_cached_response(query: str) -> str | None:
    """
    Look up a query in the cache. Returns the response text or None.
    Only matches on exact normalized match or very close substring.
    Short greetings like 'hi', 'hey', 'hello' are never cached.
    """
    load_cache()
    if not _cache:
        return None

    norm = _normalize(query)

    # Never cache match for very short queries (greetings, single words)
    if len(norm) < 12:
        return None

    # Exact match
    if norm in _cache:
        return _cache[norm]

    # Strict fuzzy: query must match at least 80% of a cached key
    for key, value in _cache.items():
        if len(key) < 15:
            continue
        # Check if the cached key is almost entirely contained in the query
        if key in norm and len(key) >= len(norm) * 0.7:
            return value
        # Check if the query is almost entirely contained in the cached key
        if norm in key and len(norm) >= len(key) * 0.7:
            return value

    return None


def get_cache_stats() -> dict:
    """Return cache statistics."""
    load_cache()
    return {
        "total_cached": len(_cache),
        "status": "loaded" if _cache else "empty",
    }
