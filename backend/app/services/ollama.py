"""
CyberSentinel v3.0 - Ollama Service
Handles streaming chat with local Ollama models.
"""
import json
from typing import AsyncGenerator
import httpx
from app.core.config import settings


async def stream_ollama(messages: list[dict], model: str) -> AsyncGenerator[str, None]:
    """Stream response from Ollama API."""
    url = f"{settings.ollama_base_url}/api/chat"
    payload = {
        "model": model,
        "messages": messages,
        "stream": True,
    }

    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            async with client.stream("POST", url, json=payload) as response:
                if response.status_code != 200:
                    body = await response.aread()
                    yield f'data: {json.dumps({"error": f"Ollama error {response.status_code}: {body.decode()[:200]}"})}\n\n'
                    return

                async for line in response.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        token = data.get("message", {}).get("content", "")
                        done = data.get("done", False)
                        if token:
                            yield f'data: {json.dumps({"token": token})}\n\n'
                        if done:
                            yield f'data: {json.dumps({"done": True})}\n\n'
                    except json.JSONDecodeError:
                        continue

    except httpx.ConnectError:
        yield f'data: {json.dumps({"error": "Cannot connect to Ollama. Make sure it is running."})}\n\n'
    except Exception as e:
        yield f'data: {json.dumps({"error": str(e)})}\n\n'


async def check_ollama_health() -> dict:
    """Check if Ollama is running and what models are available."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.ollama_base_url}/api/tags")
            if resp.status_code == 200:
                data = resp.json()
                models = [m["name"] for m in data.get("models", [])]
                return {"status": "connected", "models": models}
    except Exception:
        pass
    return {"status": "disconnected", "models": []}


async def pull_model(model: str) -> AsyncGenerator[str, None]:
    """Pull/download an Ollama model with progress updates."""
    url = f"{settings.ollama_base_url}/api/pull"
    try:
        async with httpx.AsyncClient(timeout=600.0) as client:
            async with client.stream("POST", url, json={"name": model}) as response:
                async for line in response.aiter_lines():
                    if line.strip():
                        yield f"data: {line}\n\n"
    except Exception as e:
        yield f'data: {json.dumps({"error": str(e)})}\n\n'
