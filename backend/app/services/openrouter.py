"""
CyberSentinel v3.0 - OpenRouter Service
Handles streaming chat via OpenRouter (100+ models).
"""
import json
from typing import AsyncGenerator
import httpx
from app.core.config import settings


async def stream_openrouter(messages: list[dict], model: str) -> AsyncGenerator[str, None]:
    """Stream response from OpenRouter API (OpenAI-compatible)."""
    url = "https://openrouter.ai/api/v1/chat/completions"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {settings.openrouter_api_key}",
        "HTTP-Referer": "https://cybersentinel.ai",
        "X-Title": "CyberSentinel AI",
    }

    payload = {
        "model": model,
        "messages": messages,
        "stream": True,
    }

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream("POST", url, headers=headers, json=payload) as response:
                if response.status_code != 200:
                    body = await response.aread()
                    body_text = body.decode()[:500]
                    if "credit" in body_text.lower() or "billing" in body_text.lower() or "insufficient" in body_text.lower() or "payment" in body_text.lower():
                        error_msg = "⚠️ **OpenRouter - No Credits**\n\nYour OpenRouter account needs credits to use paid models. Options:\n1. Add credits at [openrouter.ai/credits](https://openrouter.ai/credits)\n2. Switch to a free model in `.env`: `OPENROUTER_MODEL=meta-llama/llama-3.1-8b-instruct:free`\n3. Switch provider: `AI_PROVIDER=ollama` then `docker compose restart backend`"
                    elif response.status_code == 401:
                        error_msg = "⚠️ **OpenRouter - Invalid Key**\n\nYour OPENROUTER_API_KEY is invalid or expired."
                    elif response.status_code == 429:
                        error_msg = "⚠️ **OpenRouter - Rate Limited**\n\nToo many requests. Please wait and try again."
                    elif response.status_code == 400:
                        # Parse actual error for better message
                        try:
                            err_data = json.loads(body_text)
                            err_msg = err_data.get("error", {}).get("message", body_text[:200])
                        except Exception:
                            err_msg = body_text[:200]
                        error_msg = f"⚠️ **OpenRouter Error 400**\n\n{err_msg}\n\nTry adding credits at [openrouter.ai/credits](https://openrouter.ai/credits) or switch to `AI_PROVIDER=ollama`."
                    else:
                        error_msg = f"⚠️ **OpenRouter Error {response.status_code}**\n\nPlease try again or switch provider."
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
                        token = data.get("choices", [{}])[0].get("delta", {}).get("content", "")
                        if token:
                            yield f'data: {json.dumps({"token": token})}\n\n'
                    except (json.JSONDecodeError, IndexError):
                        continue

    except Exception as e:
        yield f'data: {json.dumps({"error": str(e)})}\n\n'
