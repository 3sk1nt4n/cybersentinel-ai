"""
CyberSentinel AI v2.0 - Main Application
FastAPI backend with provider-agnostic AI, 43 security tools,
Neo4j graph intelligence, and ChromaDB RAG engine.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
import logging
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings, validate_security_settings
from app.core.auth import require_api_key
from app.routers import chat, tools, health, graph, knowledge, scan, intel, history, settings as settings_router, threat_feed, export, elk, splunk, wazuh


logger = logging.getLogger("cybersentinel")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: initialize graph schema, seed KB, pull threat intel."""
    try:
        from app.services.graph import init_schema
        await init_schema()
    except Exception as e:
        logger.exception("Startup init_schema failed: %s", e)
    try:
        from app.services.rag import seed_knowledge_base
        await seed_knowledge_base()
    except Exception as e:
        logger.exception("Startup seed_knowledge_base failed: %s", e)
    # Auto-pull threat intel on startup (background thread)
    try:
        import threading
        def _pull_intel():
            try:
                from app.services.threat_intel_puller import main
                main()
            except Exception as e:
                print(f"[ThreatIntel] Startup pull error: {e}")
        threading.Thread(target=_pull_intel, daemon=True).start()
    except Exception as e:
        logger.exception("Threat intel startup thread failed: %s", e)
    # Seed ELK with sample security logs (waits for ES to be ready)
    try:
        import threading, time
        def _seed_elk():
            time.sleep(30)  # Wait for Elasticsearch to start
            try:
                import asyncio
                from app.services.elk_seeder import seed_elk_logs
                asyncio.run(seed_elk_logs())
            except Exception as e:
                print(f"[ELK Seeder] Startup error: {e}")
        threading.Thread(target=_seed_elk, daemon=True).start()
    except Exception as e:
        logger.exception("ELK seeder startup thread failed: %s", e)

    security_errors = validate_security_settings()
    if security_errors:
        logger.error("Security configuration errors: %s", "; ".join(security_errors))
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Agentic Multi-Tool Security Platform - 43 tools, provider-agnostic AI, graph intelligence, RAG engine",
    lifespan=lifespan,
)

# CORS - allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(health.router)
app.include_router(chat.router, prefix="/api", dependencies=[Depends(require_api_key)])
app.include_router(tools.router, prefix="/api", dependencies=[Depends(require_api_key)])
app.include_router(graph.router, prefix="/api", dependencies=[Depends(require_api_key)])
app.include_router(knowledge.router, prefix="/api", dependencies=[Depends(require_api_key)])
app.include_router(scan.router, prefix="/api", dependencies=[Depends(require_api_key)])
app.include_router(intel.router, prefix="/api", dependencies=[Depends(require_api_key)])
app.include_router(history.router, prefix="/api", dependencies=[Depends(require_api_key)])
app.include_router(settings_router.router, prefix="/api", dependencies=[Depends(require_api_key)])
app.include_router(threat_feed.router, prefix="/api", dependencies=[Depends(require_api_key)])
app.include_router(export.router, prefix="/api", dependencies=[Depends(require_api_key)])
app.include_router(elk.router, prefix="/api", dependencies=[Depends(require_api_key)])
app.include_router(splunk.router, prefix="/api", dependencies=[Depends(require_api_key)])
app.include_router(wazuh.router, prefix="/api", dependencies=[Depends(require_api_key)])


@app.get("/")
async def root():
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "tools": 43,
        "features": ["streaming-ai", "agentic-tools", "neo4j-graph", "chromadb-rag", "multi-provider", "live-scans", "threat-intel", "chat-history", "pdf-export", "sqlmap", "elk-siem", "splunk-siem", "wazuh-siem"],
        "docs": "/docs",
    }
