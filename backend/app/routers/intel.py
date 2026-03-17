"""
CyberSentinel v3.0 - Threat Intel Router (Phase 3)
Live threat intelligence lookup API.
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from app.services.threat_intel import (
    shodan_lookup, virustotal_lookup, abuseipdb_lookup,
    otx_lookup, multi_intel_lookup,
)

router = APIRouter(prefix="/intel", tags=["threat-intel"])


class IntelRequest(BaseModel):
    indicator: str  # IP, domain, or hash
    source: Optional[str] = None  # shodan, virustotal, abuseipdb, otx, or None for all


@router.post("/lookup")
async def lookup_indicator(req: IntelRequest):
    """Look up an indicator against threat intelligence sources."""
    if req.source:
        source_map = {
            "shodan": shodan_lookup,
            "virustotal": virustotal_lookup,
            "abuseipdb": abuseipdb_lookup,
            "otx": otx_lookup,
        }
        fn = source_map.get(req.source)
        if not fn:
            return {"error": f"Unknown source: {req.source}. Available: {list(source_map.keys())}"}
        result = await fn(req.indicator)
        return {"indicator": req.indicator, "source": req.source, "result": result}

    # Run against all sources
    return await multi_intel_lookup(req.indicator)


@router.get("/sources")
async def list_intel_sources():
    """List available threat intel sources and their API key status."""
    from app.core.config import settings
    return {
        "sources": [
            {"id": "shodan", "name": "Shodan", "configured": bool(settings.shodan_api_key), "description": "Internet-wide scanning & host discovery"},
            {"id": "virustotal", "name": "VirusTotal", "configured": bool(settings.virustotal_api_key), "description": "Multi-AV scanning & threat analysis"},
            {"id": "abuseipdb", "name": "AbuseIPDB", "configured": bool(settings.abuseipdb_api_key), "description": "IP abuse & reputation database"},
            {"id": "otx", "name": "AlienVault OTX", "configured": bool(settings.otx_api_key), "description": "Open threat intelligence exchange"},
            {"id": "censys", "name": "Censys", "configured": bool(settings.censys_api_id), "description": "Internet asset discovery"},
        ]
    }
