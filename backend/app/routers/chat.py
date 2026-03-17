"""
CyberSentinel v3.0 - Chat Router (Phase 3)
Cache-first: serves 493 pre-built responses instantly.
Falls through to live AI for free-form questions.
"""
import json
import asyncio
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from app.core.ai_router import stream_ai_response
from app.core.config import settings
from app.services.cache import get_cached_response, get_cache_stats

router = APIRouter(prefix="/chat", tags=["chat"])


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    provider: str | None = None
    model: str | None = None


async def _stream_cached(text: str):
    """Stream a cached response token-by-token to match the SSE format."""
    # Add source indicator
    full = text + "\n\n---\n*⚡ Instant response from CyberSentinel knowledge base (493 cached)*"
    # Stream in chunks for smooth animation
    chunk_size = 12
    for i in range(0, len(full), chunk_size):
        chunk = full[i:i + chunk_size]
        yield f"data: {json.dumps({'token': chunk})}\n\n"
        await asyncio.sleep(0.008)  # Smooth streaming effect
    yield f"data: {json.dumps({'done': True, 'source': 'cache'})}\n\n"


@router.post("/stream")
async def chat_stream(req: ChatRequest):
    """
    Stream a chat response. Checks cache first for instant responses,
    then falls through to live AI provider.
    """
    messages = [{"role": m.role, "content": m.content} for m in req.messages]

    # Check cache for the last user message
    last_user = None
    for m in reversed(messages):
        if m["role"] == "user":
            last_user = m["content"]
            break

    if last_user:
        cached = get_cached_response(last_user)
        if cached:
            return StreamingResponse(
                _stream_cached(cached),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
            )

    # No cache hit - use live AI
    return StreamingResponse(
        stream_ai_response(messages, provider=req.provider, model=req.model),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@router.get("/providers")
async def list_providers():
    """Return available AI providers and their status."""
    providers = [
        {"id": "ollama", "name": "Ollama (Local)", "model": settings.ollama_model, "configured": True, "cost": "Free"},
        {"id": "claude", "name": "Anthropic Claude", "model": settings.claude_model, "configured": bool(settings.anthropic_api_key), "cost": "~$3/M tokens"},
        {"id": "openai", "name": "OpenAI GPT", "model": settings.openai_model, "configured": bool(settings.openai_api_key), "cost": "~$5/M tokens"},
        {"id": "openrouter", "name": "OpenRouter", "model": settings.openrouter_model, "configured": bool(settings.openrouter_api_key), "cost": "Varies"},
    ]
    return {"default": settings.ai_provider, "providers": providers}


@router.get("/cache/stats")
async def cache_stats():
    """Return cache statistics."""
    return get_cache_stats()
