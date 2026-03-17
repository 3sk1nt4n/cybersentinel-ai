"""
CyberSentinel v3.0 - Claude Service
Handles streaming chat with Anthropic Claude API.
"""
import json
from typing import AsyncGenerator
import httpx
from app.core.config import settings


async def stream_claude(messages: list[dict], model: str) -> AsyncGenerator[str, None]:
    """Stream response from Anthropic Claude API."""
    url = "https://api.anthropic.com/v1/messages"

    # Separate system prompt from messages (Claude API requires it separately)
    system_prompt = ""
    chat_messages = []
    for msg in messages:
        if msg["role"] == "system":
            system_prompt = msg["content"]
        else:
            chat_messages.append({"role": msg["role"], "content": msg["content"]})

    # Ensure messages start with user role
    if not chat_messages or chat_messages[0]["role"] != "user":
        chat_messages.insert(0, {"role": "user", "content": "Hello"})

    headers = {
        "Content-Type": "application/json",
        "x-api-key": settings.anthropic_api_key,
        "anthropic-version": "2023-06-01",
    }

    payload = {
        "model": model,
        "max_tokens": 4096,
        "stream": True,
        "system": system_prompt,
        "messages": chat_messages,
    }

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream("POST", url, headers=headers, json=payload) as response:
                if response.status_code != 200:
                    body = await response.aread()
                    body_text = body.decode()[:300]
                    # User-friendly error messages
                    if "credit balance" in body_text or "billing" in body_text.lower():
                        error_msg = "⚠️ **Claude API - No Credits**\n\nYour Claude API account has insufficient credits. Options:\n1. Add credits at [console.anthropic.com](https://console.anthropic.com/settings/billing)\n2. Switch provider in `.env`: `AI_PROVIDER=openai` or `AI_PROVIDER=openrouter`\n3. Restart: `docker compose restart backend`"
                    elif response.status_code == 401:
                        error_msg = "⚠️ **Claude API - Invalid Key**\n\nYour ANTHROPIC_API_KEY is invalid or expired. Check your key at [console.anthropic.com](https://console.anthropic.com/)"
                    elif response.status_code == 429:
                        error_msg = "⚠️ **Claude API - Rate Limited**\n\nToo many requests. Please wait a moment and try again."
                    else:
                        error_msg = f"⚠️ **Claude API Error {response.status_code}**\n\nPlease try again or switch to another provider in Settings."
                    yield f'data: {json.dumps({"token": error_msg})}\n\n'
                    yield f'data: {json.dumps({"done": True})}\n\n'
                    return

                async for line in response.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    if data_str == "[DONE]":
                        yield f'data: {json.dumps({"done": True})}\n\n'
                        return
                    try:
                        data = json.loads(data_str)
                        if data.get("type") == "content_block_delta":
                            token = data.get("delta", {}).get("text", "")
                            if token:
                                yield f'data: {json.dumps({"token": token})}\n\n'
                        elif data.get("type") == "message_stop":
                            yield f'data: {json.dumps({"done": True})}\n\n'
                    except json.JSONDecodeError:
                        continue

    except Exception as e:
        yield f'data: {json.dumps({"error": str(e)})}\n\n'
