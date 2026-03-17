"""
CyberSentinel v3.0 - Splunk SIEM Integration (Phase 3)
Real Splunk REST API integration for running SPL queries and pulling alerts.

Setup: Add to .env:
  SPLUNK_URL=https://splunk:8089           (or https://localhost:8089)
  SPLUNK_TOKEN=your-bearer-token           (preferred auth)
  SPLUNK_USER=admin                        (basic auth fallback)
  SPLUNK_PASSWORD=your-password            (basic auth fallback)

Splunk Free Docker:
  docker run -d -p 8000:8000 -p 8089:8089 -e SPLUNK_START_ARGS=--accept-license
    -e SPLUNK_PASSWORD=CyberSentinel2024 splunk/splunk:latest
"""
import json
import httpx
import urllib.parse
from typing import Optional
from app.core.config import settings

TIMEOUT = 30


def _get_splunk_url() -> str:
    return getattr(settings, 'splunk_url', None) or "https://splunk:8089"


def _get_auth_headers() -> dict:
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token = getattr(settings, 'splunk_token', None)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _get_auth() -> Optional[tuple]:
    user = getattr(settings, 'splunk_user', None)
    pwd = getattr(settings, 'splunk_password', None)
    if user and pwd:
        return (user, pwd)
    return None


async def _splunk_request(method: str, path: str, data: dict = None) -> dict:
    url = f"{_get_splunk_url()}{path}"
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
            kwargs = {"headers": _get_auth_headers()}
            auth = _get_auth()
            if auth and "Authorization" not in kwargs["headers"]:
                kwargs["auth"] = auth
            kwargs["params"] = {"output_mode": "json"}
            if method == "GET":
                r = await client.get(url, **kwargs)
            elif method == "POST":
                r = await client.post(url, data=data, **kwargs)
            else:
                r = await client.request(method, url, data=data, **kwargs)

            if r.status_code in (200, 201):
                try:
                    return {"success": True, "data": r.json()}
                except Exception:
                    return {"success": True, "data": r.text[:2000]}
            elif r.status_code == 401:
                return {"success": False, "error": "Authentication failed. Check SPLUNK_TOKEN or SPLUNK_USER/SPLUNK_PASSWORD in .env"}
            else:
                return {"success": False, "error": f"HTTP {r.status_code}: {r.text[:500]}"}
    except httpx.ConnectError:
        return {"success": False, "error": f"Cannot connect to Splunk at {_get_splunk_url()}. Make sure Splunk is running. See docker-compose.yml to enable."}
    except Exception as e:
        return {"success": False, "error": str(e)[:500]}


# ═══════════════════════════════════════════════
# HEALTH & INFO
# ═══════════════════════════════════════════════

async def splunk_health() -> dict:
    result = await _splunk_request("GET", "/services/server/info")
    if result["success"]:
        d = result["data"]
        entry = d.get("entry", [{}])[0].get("content", {}) if isinstance(d, dict) else {}
        return {
            "status": "connected",
            "server_name": entry.get("serverName", "unknown"),
            "version": entry.get("version", "unknown"),
            "os": entry.get("os_name", "unknown"),
            "cpu_arch": entry.get("cpu_arch", "unknown"),
            "license": entry.get("activeLicenseGroup", "unknown"),
        }
    return {"status": "disconnected", "error": result.get("error")}


async def splunk_indexes() -> dict:
    result = await _splunk_request("GET", "/services/data/indexes")
    if result["success"]:
        d = result["data"]
        indexes = []
        for entry in d.get("entry", []):
            name = entry.get("name", "")
            content = entry.get("content", {})
            if not name.startswith("_"):
                indexes.append({
                    "name": name,
                    "totalEventCount": content.get("totalEventCount", 0),
                    "currentDBSizeMB": content.get("currentDBSizeMB", 0),
                })
        return {"success": True, "indexes": indexes, "total": len(indexes)}
    return result


# ═══════════════════════════════════════════════
# SEARCH - Run SPL queries
# ═══════════════════════════════════════════════

async def splunk_search(spl_query: str, max_results: int = 50) -> dict:
    """Run a one-shot SPL search and return results."""
    if not spl_query.strip().startswith("search"):
        spl_query = f"search {spl_query}"

    data = {
        "search": spl_query,
        "exec_mode": "oneshot",
        "count": max_results,
        "output_mode": "json",
    }
    result = await _splunk_request("POST", "/services/search/jobs/export", data)
    if result["success"]:
        raw = result["data"]
        if isinstance(raw, dict):
            results = raw.get("results", [])
            return {"success": True, "total": len(results), "results": results[:max_results]}
        elif isinstance(raw, str):
            # Parse NDJSON
            lines = [l.strip() for l in raw.strip().split("\n") if l.strip()]
            results = []
            for line in lines:
                try:
                    obj = json.loads(line)
                    if "result" in obj:
                        results.append(obj["result"])
                    elif "_raw" in obj:
                        results.append(obj)
                except Exception:
                    pass
            return {"success": True, "total": len(results), "results": results[:max_results]}
    return result


# ═══════════════════════════════════════════════
# PRE-BUILT SECURITY QUERIES
# ═══════════════════════════════════════════════

async def splunk_failed_logins(hours: int = 24) -> dict:
    spl = f'search index=* earliest=-{hours}h (EventCode=4625 OR "Failed password" OR "authentication failure") | stats count by src_ip, user, host | sort -count | head 50'
    return await splunk_search(spl)


async def splunk_lateral_movement(hours: int = 24) -> dict:
    spl = f'search index=* earliest=-{hours}h (EventCode=4648 OR (EventCode=4624 LogonType=3)) | stats count by src_ip, dest, user | sort -count | head 50'
    return await splunk_search(spl)


async def splunk_powershell(hours: int = 24) -> dict:
    spl = f'search index=* earliest=-{hours}h (EventCode=4104 OR process_name="powershell.exe" OR process_name="pwsh.exe") | stats count by host, user, ScriptBlockText | sort -count | head 50'
    return await splunk_search(spl)


async def splunk_alerts(hours: int = 24) -> dict:
    spl = f'search index=* earliest=-{hours}h severity=critical OR severity=high | stats count by rule_name, severity, src_ip, dest | sort -count | head 50'
    return await splunk_search(spl)


async def splunk_dns(hours: int = 24) -> dict:
    spl = f'search index=* earliest=-{hours}h sourcetype=dns OR tag=dns | stats count by query, src_ip | sort -count | head 50'
    return await splunk_search(spl)
