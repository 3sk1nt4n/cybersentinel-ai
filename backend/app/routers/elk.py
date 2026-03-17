"""
CyberSentinel v3.0 - ELK Stack SIEM Router (Phase 3)
Real Elasticsearch / ELK integration API endpoints.

Setup: Add to .env:
  ELASTICSEARCH_URL=http://elasticsearch:9200
  ELASTICSEARCH_USER=elastic
  ELASTICSEARCH_PASSWORD=changeme
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from app.services.elk import (
    elk_health, elk_indices, elk_search,
    elk_failed_logins, elk_lateral_movement,
    elk_powershell_events, elk_high_severity_alerts,
    elk_dns_queries, elk_process_creation,
    elk_ingest_event, elk_ingest_bulk,
)

router = APIRouter(prefix="/elk", tags=["elk-siem"])


class ElkSearchRequest(BaseModel):
    index: str = "logs-*"
    query: dict = {}
    size: int = 50


class ElkQueryRequest(BaseModel):
    hours: int = 24
    size: int = 50
    filter: Optional[str] = None


class ElkIngestRequest(BaseModel):
    index: str = "cybersentinel-events"
    event: dict = {}


class ElkBulkIngestRequest(BaseModel):
    index: str = "cybersentinel-events"
    events: list[dict] = []


# ═══════════════════════════════════════════════
# CLUSTER
# ═══════════════════════════════════════════════

@router.get("/health")
async def check_elk_health():
    """Check Elasticsearch cluster health & connection."""
    return await elk_health()


@router.get("/indices")
async def list_elk_indices():
    """List all Elasticsearch indices."""
    return await elk_indices()


# ═══════════════════════════════════════════════
# SECURITY QUERIES
# ═══════════════════════════════════════════════

@router.post("/search")
async def search_elk(req: ElkSearchRequest):
    """Run a raw Elasticsearch query."""
    return await elk_search(req.index, req.query, req.size)


@router.post("/failed-logins")
async def query_failed_logins(req: ElkQueryRequest):
    """Query for failed login attempts."""
    return await elk_failed_logins(req.hours, req.size)


@router.post("/lateral-movement")
async def query_lateral_movement(req: ElkQueryRequest):
    """Query for lateral movement indicators (4648, 4624 Type 3)."""
    return await elk_lateral_movement(req.hours, req.size)


@router.post("/powershell")
async def query_powershell(req: ElkQueryRequest):
    """Query for PowerShell execution events."""
    return await elk_powershell_events(req.hours, req.size)


@router.post("/alerts")
async def query_alerts(req: ElkQueryRequest):
    """Query for high/critical severity alerts."""
    return await elk_high_severity_alerts(req.hours, req.size)


@router.post("/dns")
async def query_dns(req: ElkQueryRequest):
    """Query for DNS events, optionally filtered by domain."""
    return await elk_dns_queries(req.filter, req.hours, req.size)


@router.post("/processes")
async def query_processes(req: ElkQueryRequest):
    """Query for process creation events."""
    return await elk_process_creation(req.filter, req.hours, req.size)


# ═══════════════════════════════════════════════
# INGEST
# ═══════════════════════════════════════════════

@router.post("/ingest")
async def ingest_event(req: ElkIngestRequest):
    """Index a single event into Elasticsearch."""
    return await elk_ingest_event(req.index, req.event)


@router.post("/ingest/bulk")
async def ingest_bulk(req: ElkBulkIngestRequest):
    """Bulk index events into Elasticsearch."""
    return await elk_ingest_bulk(req.index, req.events)


@router.post("/seed")
async def seed_elk_data():
    """Seed Elasticsearch with ~500 sample security events for testing."""
    from app.services.elk_seeder import seed_elk_logs
    await seed_elk_logs()
    return {"success": True, "message": "ELK seeded with sample security events"}


@router.post("/seed-sample-data")
async def seed_sample_data():
    """Seed Elasticsearch with realistic Windows security events for demo/testing."""
    from app.services.elk_seeder import generate_sample_events

    # Check health first
    health = await elk_health()
    if health.get("status") != "connected":
        return {"success": False, "error": "Elasticsearch not connected. Start it first.", "details": health}

    events = generate_sample_events(300)
    result = await elk_ingest_bulk("winlogbeat-cybersentinel", events)
    return {
        "success": result.get("success", False),
        "message": f"Seeded {len(events)} realistic security events into winlogbeat-cybersentinel index",
        "details": result,
    }
