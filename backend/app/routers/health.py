"""
CyberSentinel v2.0 - Health Router (Phase 2)
System health checks for all services including Neo4j and ChromaDB.
"""
from fastapi import APIRouter
from app.core.config import settings, validate_security_settings
from app.services.ollama import check_ollama_health

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check():
    """Quick health check for Docker."""
    return {"status": "ok", "version": settings.app_version}


@router.get("/health/full")
async def full_health_check():
    """Full health check of all connected services."""
    ollama = await check_ollama_health()

    security_errors = validate_security_settings()

    overall = "ok"
    if security_errors:
        overall = "degraded"
    # Neo4j
    try:
        from app.services.graph import check_neo4j_health
        neo4j = await check_neo4j_health()
    except Exception:
        neo4j = {"status": "unavailable"}

    # ChromaDB / RAG (embedded - always available)
    try:
        from app.services.rag import get_collection_stats
        rag = await get_collection_stats()
    except Exception:
        rag = {"status": "unavailable"}

    return {
        "status": overall,
        "version": settings.app_version,
        "ai_provider": settings.ai_provider,
        "services": {
            "ollama": ollama,
            "claude": {"configured": bool(settings.anthropic_api_key)},
            "openai": {"configured": bool(settings.openai_api_key)},
            "openrouter": {"configured": bool(settings.openrouter_api_key)},
            "neo4j": neo4j,
            "chromadb_rag": rag,
        },
        "security": {"status": "ok" if not security_errors else "error", "errors": security_errors},
    }
