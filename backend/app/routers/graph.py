"""
CyberSentinel v3.0 - Graph Router (Phase 2)
Neo4j attack surface graph intelligence API.
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from app.services.graph import (
    check_neo4j_health, init_schema, add_asset, add_vulnerability,
    link_asset_to_vuln, add_technique, add_ioc,
    get_attack_surface_summary, query_graph,
)

router = APIRouter(prefix="/graph", tags=["graph"])


class AssetInput(BaseModel):
    asset_id: str
    asset_type: str  # host, service, domain, cloud_resource, user
    name: str
    properties: Optional[dict] = None


class VulnInput(BaseModel):
    cve_id: str
    cvss_score: float
    epss_score: float = 0
    description: str = ""
    exploited: bool = False


class LinkInput(BaseModel):
    asset_id: str
    cve_id: str


class TechniqueInput(BaseModel):
    technique_id: str
    name: str
    tactic: str = ""


class IOCInput(BaseModel):
    value: str
    ioc_type: str  # ip, domain, hash, url, email
    source: str = ""
    malicious: bool = True


class CypherQuery(BaseModel):
    query: str
    params: Optional[dict] = None


@router.get("/health")
async def graph_health():
    return await check_neo4j_health()


@router.post("/init")
async def initialize_schema():
    ok = await init_schema()
    return {"success": ok, "message": "Schema initialized" if ok else "Failed to connect to Neo4j"}


@router.get("/summary")
async def attack_surface_summary():
    return await get_attack_surface_summary()


@router.post("/assets")
async def create_asset(data: AssetInput):
    result = await add_asset(data.asset_id, data.asset_type, data.name, data.properties)
    return {"success": result is not None, "asset": result}


@router.post("/vulnerabilities")
async def create_vulnerability(data: VulnInput):
    result = await add_vulnerability(data.cve_id, data.cvss_score, data.epss_score, data.description, data.exploited)
    return {"success": result is not None, "vulnerability": result}


@router.post("/link")
async def link_asset_vulnerability(data: LinkInput):
    ok = await link_asset_to_vuln(data.asset_id, data.cve_id)
    return {"success": ok}


@router.post("/techniques")
async def create_technique(data: TechniqueInput):
    result = await add_technique(data.technique_id, data.name, data.tactic)
    return {"success": result is not None, "technique": result}


@router.post("/iocs")
async def create_ioc(data: IOCInput):
    result = await add_ioc(data.value, data.ioc_type, data.source, data.malicious)
    return {"success": result is not None, "ioc": result}


@router.post("/query")
async def run_cypher(data: CypherQuery):
    results = await query_graph(data.query, data.params)
    return {"results": results, "count": len(results)}
