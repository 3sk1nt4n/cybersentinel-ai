"""
CyberSentinel v3.0 - OpenAI Service
Handles streaming chat with OpenAI GPT API.
"""
import json
from typing import AsyncGenerator
import httpx
from app.core.config import settings


async def stream_openai(messages: list[dict], model: str) -> AsyncGenerator[str, None]:
    """Stream response from OpenAI API."""
    url = "https://api.openai.com/v1/chat/completions"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {settings.openai_api_key}",
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
                    body_text = body.decode()[:300]
                    if "insufficient_quota" in body_text or "billing" in body_text.lower():
                        error_msg = "⚠️ **OpenAI API - No Credits**\n\nYour OpenAI account has insufficient credits. Add credits at [platform.openai.com](https://platform.openai.com/settings/organization/billing) or switch provider in `.env`."
                    elif response.status_code == 401:
                        error_msg = "⚠️ **OpenAI API - Invalid Key**\n\nYour OPENAI_API_KEY is invalid or expired."
                    elif response.status_code == 429:
                        error_msg = "⚠️ **OpenAI API - Rate Limited**\n\nToo many requests. Please wait and try again."
                    else:
                        error_msg = f"⚠️ **OpenAI API Error {response.status_code}**\n\nPlease try again or switch provider."
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
