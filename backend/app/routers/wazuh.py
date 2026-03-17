"""CyberSentinel v3.0 - Wazuh SIEM Router (Phase 3)"""
from fastapi import APIRouter
from pydantic import BaseModel
from app.services.wazuh import (
    wazuh_health, wazuh_agents, wazuh_agent_summary,
    wazuh_alerts, wazuh_failed_logins, wazuh_fim_changes,
    wazuh_vulnerabilities, wazuh_sca, wazuh_rootcheck,
    wazuh_mitre_alerts,
)

router = APIRouter(prefix="/wazuh", tags=["wazuh-siem"])


class WazuhQueryRequest(BaseModel):
    hours: int = 24

class WazuhAgentRequest(BaseModel):
    agent_id: str = "001"


@router.get("/health")
async def check_wazuh_health():
    return await wazuh_health()

@router.get("/agents")
async def list_agents():
    return await wazuh_agents()

@router.get("/agents/summary")
async def agent_summary():
    return await wazuh_agent_summary()

@router.post("/alerts")
async def get_alerts(req: WazuhQueryRequest):
    return await wazuh_alerts(req.hours)

@router.post("/failed-logins")
async def get_failed_logins(req: WazuhQueryRequest):
    return await wazuh_failed_logins(req.hours)

@router.post("/fim")
async def get_fim(req: WazuhQueryRequest):
    return await wazuh_fim_changes(req.hours)

@router.post("/vulnerabilities")
async def get_vulns(req: WazuhAgentRequest):
    return await wazuh_vulnerabilities(req.agent_id)

@router.post("/sca")
async def get_sca(req: WazuhAgentRequest):
    return await wazuh_sca(req.agent_id)

@router.post("/rootcheck")
async def get_rootcheck(req: WazuhAgentRequest):
    return await wazuh_rootcheck(req.agent_id)

@router.post("/mitre")
async def get_mitre_alerts():
    return await wazuh_mitre_alerts()
