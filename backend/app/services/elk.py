"""
CyberSentinel v3.0 - ELK Stack SIEM Integration (Phase 3)
Real Elasticsearch integration for querying security logs.
Connects to any Elasticsearch instance (local Docker, Elastic Cloud, etc.)

Setup: Add to .env:
  ELASTICSEARCH_URL=http://elasticsearch:9200
  ELASTICSEARCH_API_KEY=your-api-key  (optional - for Elastic Cloud)
  ELASTICSEARCH_USER=elastic           (optional - for basic auth)
  ELASTICSEARCH_PASSWORD=changeme      (optional - for basic auth)
"""
import httpx
import json
from typing import Optional
from datetime import datetime, timedelta
from app.core.config import settings


TIMEOUT = 30


def _get_auth_headers() -> dict:
    """Build auth headers for Elasticsearch."""
    headers = {"Content-Type": "application/json"}
    if hasattr(settings, 'elasticsearch_api_key') and settings.elasticsearch_api_key:
        headers["Authorization"] = f"ApiKey {settings.elasticsearch_api_key}"
    return headers


def _get_auth() -> Optional[tuple]:
    """Get basic auth tuple if configured."""
    user = getattr(settings, 'elasticsearch_user', None)
    pwd = getattr(settings, 'elasticsearch_password', None)
    if user and pwd:
        return (user, pwd)
    return None


async def _es_request(method: str, path: str, body: dict = None) -> dict:
    """Make a request to Elasticsearch."""
    base_url = getattr(settings, 'elasticsearch_url', None) or "http://elasticsearch:9200"
    url = f"{base_url}{path}"

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
            kwargs = {
                "headers": _get_auth_headers(),
                "auth": _get_auth(),
            }
            if method == "GET":
                r = await client.get(url, **kwargs)
            elif method == "POST":
                r = await client.post(url, json=body, **kwargs)
            else:
                r = await client.request(method, url, json=body, **kwargs)

            if r.status_code == 200:
                return {"success": True, "data": r.json()}
            else:
                return {"success": False, "error": f"HTTP {r.status_code}: {r.text[:500]}"}
    except httpx.ConnectError:
        return {"success": False, "error": f"Cannot connect to Elasticsearch at {base_url}. Make sure ELK stack is running."}
    except Exception as e:
        return {"success": False, "error": str(e)[:500]}


# ═══════════════════════════════════════════════
# HEALTH & CLUSTER INFO
# ═══════════════════════════════════════════════

async def elk_health() -> dict:
    """Check Elasticsearch cluster health."""
    result = await _es_request("GET", "/_cluster/health")
    if result["success"]:
        d = result["data"]
        return {
            "status": "connected",
            "cluster_name": d.get("cluster_name"),
            "cluster_status": d.get("status"),  # green/yellow/red
            "nodes": d.get("number_of_nodes"),
            "data_nodes": d.get("number_of_data_nodes"),
            "active_shards": d.get("active_shards"),
            "indices": d.get("active_primary_shards"),
        }
    return {"status": "disconnected", "error": result.get("error")}


async def elk_indices() -> dict:
    """List all indices in Elasticsearch."""
    result = await _es_request("GET", "/_cat/indices?format=json&h=index,docs.count,store.size,status")
    if result["success"]:
        indices = [
            {
                "index": idx.get("index"),
                "docs": idx.get("docs.count"),
                "size": idx.get("store.size"),
                "status": idx.get("status"),
            }
            for idx in result["data"]
            if not idx.get("index", "").startswith(".")  # Skip system indices
        ]
        return {"success": True, "indices": indices, "total": len(indices)}
    return result


# ═══════════════════════════════════════════════
# SECURITY LOG QUERIES
# ═══════════════════════════════════════════════

async def elk_search(index: str, query: dict, size: int = 50) -> dict:
    """Run a raw Elasticsearch query."""
    body = {
        "query": query,
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
    }
    result = await _es_request("POST", f"/{index}/_search", body)
    if result["success"]:
        hits = result["data"].get("hits", {})
        return {
            "success": True,
            "total": hits.get("total", {}).get("value", 0),
            "hits": [
                {
                    "id": h.get("_id"),
                    "index": h.get("_index"),
                    "source": h.get("_source", {}),
                }
                for h in hits.get("hits", [])
            ],
        }
    return result


async def elk_failed_logins(hours: int = 24, size: int = 50) -> dict:
    """Query for failed login attempts in the last N hours."""
    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            ],
            "should": [
                # Windows Event ID 4625 - Failed login
                {"match": {"event.code": "4625"}},
                {"match": {"winlog.event_id": "4625"}},
                # Linux auth failures
                {"match_phrase": {"message": "authentication failure"}},
                {"match_phrase": {"message": "Failed password"}},
                # Generic
                {"match": {"event.outcome": "failure"}},
                {"match": {"event.action": "logon-failed"}},
            ],
            "minimum_should_match": 1,
        }
    }
    # Try common security index patterns
    for idx in ["winlogbeat-*", "filebeat-*", "logs-*", "security-*", ".ds-logs-*"]:
        result = await elk_search(idx, query, size)
        if result.get("success") and result.get("total", 0) > 0:
            result["index_searched"] = idx
            return result

    # Try with wildcard
    return await elk_search("*", query, size)


async def elk_lateral_movement(hours: int = 24, size: int = 50) -> dict:
    """Query for lateral movement indicators - Event IDs 4648 (explicit creds), 4624 Type 3 (network logon)."""
    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            ],
            "should": [
                {"match": {"event.code": "4648"}},
                {"match": {"winlog.event_id": "4648"}},
                {
                    "bool": {
                        "must": [
                            {"match": {"event.code": "4624"}},
                            {"match": {"winlog.event_data.LogonType": "3"}},
                        ]
                    }
                },
                {"match_phrase": {"message": "explicit credentials"}},
                {"match": {"event.action": "explicit-credential-logon"}},
            ],
            "minimum_should_match": 1,
        }
    }
    for idx in ["winlogbeat-*", "logs-*", "security-*"]:
        result = await elk_search(idx, query, size)
        if result.get("success") and result.get("total", 0) > 0:
            result["index_searched"] = idx
            return result
    return await elk_search("*", query, size)


async def elk_powershell_events(hours: int = 24, size: int = 50) -> dict:
    """Query for PowerShell execution events - potential living-off-the-land."""
    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            ],
            "should": [
                # Sysmon Event ID 1 with PowerShell
                {"match_phrase": {"process.name": "powershell.exe"}},
                {"match_phrase": {"process.name": "pwsh.exe"}},
                {"match": {"event.code": "4104"}},  # Script block logging
                {"match": {"winlog.event_id": "4104"}},
                {"match_phrase": {"message": "powershell"}},
            ],
            "minimum_should_match": 1,
        }
    }
    for idx in ["winlogbeat-*", "logs-*", "security-*"]:
        result = await elk_search(idx, query, size)
        if result.get("success") and result.get("total", 0) > 0:
            result["index_searched"] = idx
            return result
    return await elk_search("*", query, size)


async def elk_high_severity_alerts(hours: int = 24, size: int = 50) -> dict:
    """Query for high/critical severity alerts from any detection engine."""
    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            ],
            "should": [
                {"match": {"event.severity": "critical"}},
                {"match": {"event.severity": "high"}},
                {"range": {"event.risk_score": {"gte": 70}}},
                {"match": {"signal.rule.severity": "critical"}},
                {"match": {"signal.rule.severity": "high"}},
                {"match": {"kibana.alert.severity": "critical"}},
                {"match": {"kibana.alert.severity": "high"}},
            ],
            "minimum_should_match": 1,
        }
    }
    for idx in [".alerts-security*", ".siem-signals-*", "logs-*", "security-*"]:
        result = await elk_search(idx, query, size)
        if result.get("success") and result.get("total", 0) > 0:
            result["index_searched"] = idx
            return result
    return await elk_search("*", query, size)


async def elk_dns_queries(domain_filter: str = None, hours: int = 24, size: int = 50) -> dict:
    """Query for DNS events - optionally filter by domain."""
    must = [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}}]
    should = [
        {"exists": {"field": "dns.question.name"}},
        {"match": {"event.category": "dns"}},
    ]
    if domain_filter:
        must.append({"wildcard": {"dns.question.name": f"*{domain_filter}*"}})

    query = {"bool": {"must": must, "should": should, "minimum_should_match": 1}}
    for idx in ["packetbeat-*", "filebeat-*", "logs-*"]:
        result = await elk_search(idx, query, size)
        if result.get("success") and result.get("total", 0) > 0:
            result["index_searched"] = idx
            return result
    return await elk_search("*", query, size)


async def elk_process_creation(process_name: str = None, hours: int = 24, size: int = 50) -> dict:
    """Query for process creation events (Sysmon EID 1, Windows EID 4688)."""
    must = [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}}]
    should = [
        {"match": {"event.code": "1"}},    # Sysmon process create
        {"match": {"event.code": "4688"}},  # Windows process create
        {"match": {"event.category": "process"}},
        {"match": {"event.action": "Process Create"}},
    ]
    if process_name:
        must.append({"wildcard": {"process.name": f"*{process_name}*"}})

    query = {"bool": {"must": must, "should": should, "minimum_should_match": 1}}
    for idx in ["winlogbeat-*", "logs-*", "sysmon-*"]:
        result = await elk_search(idx, query, size)
        if result.get("success") and result.get("total", 0) > 0:
            result["index_searched"] = idx
            return result
    return await elk_search("*", query, size)


# ═══════════════════════════════════════════════
# INGEST - Send events to Elasticsearch
# ═══════════════════════════════════════════════

async def elk_ingest_event(index: str, event: dict) -> dict:
    """Index a single event into Elasticsearch."""
    if "@timestamp" not in event:
        event["@timestamp"] = datetime.utcnow().isoformat() + "Z"
    return await _es_request("POST", f"/{index}/_doc", event)


async def elk_ingest_bulk(index: str, events: list[dict]) -> dict:
    """Bulk index events into Elasticsearch."""
    lines = []
    for event in events:
        if "@timestamp" not in event:
            event["@timestamp"] = datetime.utcnow().isoformat() + "Z"
        lines.append(json.dumps({"index": {"_index": index}}))
        lines.append(json.dumps(event))
    body = "\n".join(lines) + "\n"

    base_url = getattr(settings, 'elasticsearch_url', None) or "http://elasticsearch:9200"
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
            r = await client.post(
                f"{base_url}/_bulk",
                content=body,
                headers={**_get_auth_headers(), "Content-Type": "application/x-ndjson"},
                auth=_get_auth(),
            )
            if r.status_code == 200:
                data = r.json()
                return {
                    "success": True,
                    "took": data.get("took"),
                    "errors": data.get("errors"),
                    "indexed": len(events),
                }
            return {"success": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)[:500]}
