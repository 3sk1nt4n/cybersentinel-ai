"""
CyberSentinel v3.0 - Splunk SIEM Router (Phase 3)
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from app.services.splunk import (
    splunk_health, splunk_indexes, splunk_search,
    splunk_failed_logins, splunk_lateral_movement,
    splunk_powershell, splunk_alerts, splunk_dns,
)

router = APIRouter(prefix="/splunk", tags=["splunk-siem"])


class SplunkSearchRequest(BaseModel):
    query: str = 'search index=* earliest=-1h | stats count by sourcetype'
    max_results: int = 50


class SplunkQueryRequest(BaseModel):
    hours: int = 24


@router.get("/health")
async def check_splunk_health():
    return await splunk_health()


@router.get("/indexes")
async def list_splunk_indexes():
    return await splunk_indexes()


@router.post("/search")
async def search_splunk(req: SplunkSearchRequest):
    return await splunk_search(req.query, req.max_results)


@router.post("/failed-logins")
async def query_failed_logins(req: SplunkQueryRequest):
    return await splunk_failed_logins(req.hours)


@router.post("/lateral-movement")
async def query_lateral_movement(req: SplunkQueryRequest):
    return await splunk_lateral_movement(req.hours)


@router.post("/powershell")
async def query_powershell(req: SplunkQueryRequest):
    return await splunk_powershell(req.hours)


@router.post("/alerts")
async def query_alerts(req: SplunkQueryRequest):
    return await splunk_alerts(req.hours)


@router.post("/dns")
async def query_dns(req: SplunkQueryRequest):
    return await splunk_dns(req.hours)
