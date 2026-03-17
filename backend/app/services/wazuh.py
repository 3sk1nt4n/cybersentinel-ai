"""
CyberSentinel v3.0 - Wazuh SIEM Integration (Phase 3)
Real Wazuh Manager REST API integration.

Setup: Add to .env:
  WAZUH_URL=https://wazuh:55000              (Wazuh Manager API)
  WAZUH_USER=wazuh-wui                       (API user)
  WAZUH_PASSWORD=MyS3cr3tP4ssw0rd*           (API password)

Wazuh Docker (all-in-one):
  git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
  cd wazuh-docker/single-node
  docker-compose up -d
  # Dashboard: https://localhost:443  (admin / SecretPassword)
  # API: https://localhost:55000      (wazuh-wui / MyS3cr3tP4ssw0rd*)
"""
import json
import httpx
from typing import Optional
from app.core.config import settings

TIMEOUT = 30
_token_cache: dict = {"token": None}


def _get_wazuh_url() -> str:
    return getattr(settings, 'wazuh_url', None) or "https://wazuh:55000"


async def _get_token() -> Optional[str]:
    """Authenticate and get JWT token from Wazuh API."""
    if _token_cache["token"]:
        return _token_cache["token"]
    user = getattr(settings, 'wazuh_user', None) or "wazuh-wui"
    pwd = getattr(settings, 'wazuh_password', None)
    if not pwd:
        return None
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as c:
            r = await c.post(
                f"{_get_wazuh_url()}/security/user/authenticate",
                auth=(user, pwd),
            )
            if r.status_code == 200:
                token = r.json().get("data", {}).get("token")
                _token_cache["token"] = token
                return token
    except Exception:
        pass
    return None


async def _wazuh_get(path: str, params: dict = None) -> dict:
    """Make authenticated GET request to Wazuh API."""
    token = await _get_token()
    url = f"{_get_wazuh_url()}{path}"
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as c:
            headers = {}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            r = await c.get(url, headers=headers, params=params or {})
            if r.status_code == 200:
                return {"success": True, "data": r.json().get("data", r.json())}
            elif r.status_code == 401:
                _token_cache["token"] = None
                return {"success": False, "error": "Auth failed. Check WAZUH_USER/WAZUH_PASSWORD in .env"}
            else:
                return {"success": False, "error": f"HTTP {r.status_code}: {r.text[:500]}"}
    except httpx.ConnectError:
        return {"success": False, "error": f"Cannot connect to Wazuh at {_get_wazuh_url()}. See docker-compose.yml to enable."}
    except Exception as e:
        return {"success": False, "error": str(e)[:500]}


# ═══════════════════════════════════════════════
# HEALTH & INFO
# ═══════════════════════════════════════════════

async def wazuh_health() -> dict:
    result = await _wazuh_get("/")
    if result["success"]:
        d = result["data"]
        return {
            "status": "connected",
            "title": d.get("title", "Wazuh"),
            "api_version": d.get("api_version", "unknown"),
            "revision": d.get("revision", "unknown"),
            "hostname": d.get("hostname", "unknown"),
        }
    # Try unauthenticated info endpoint
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as c:
            r = await c.get(f"{_get_wazuh_url()}/")
            if r.status_code == 200:
                d = r.json().get("data", {})
                return {"status": "connected_no_auth", "api_version": d.get("api_version", "unknown")}
    except Exception:
        pass
    return {"status": "disconnected", "error": result.get("error")}


async def wazuh_agents() -> dict:
    """List all registered Wazuh agents."""
    return await _wazuh_get("/agents", {"limit": 100, "select": "id,name,ip,os.name,os.version,status,lastKeepAlive"})


async def wazuh_agent_summary() -> dict:
    """Get agent status summary."""
    return await _wazuh_get("/agents/summary/status")


# ═══════════════════════════════════════════════
# ALERTS & SECURITY EVENTS
# ═══════════════════════════════════════════════

async def wazuh_alerts(hours: int = 24, limit: int = 50) -> dict:
    """Get recent alerts from Wazuh."""
    return await _wazuh_get("/alerts", {"limit": limit, "sort": "-timestamp"})


async def wazuh_failed_logins(hours: int = 24) -> dict:
    """Get failed authentication alerts (rule groups: authentication_failed, sshd, pam)."""
    return await _wazuh_get("/alerts", {
        "limit": 50,
        "sort": "-timestamp",
        "q": "rule.groups=authentication_failed,sshd;rule.level>5",
    })


async def wazuh_fim_changes(hours: int = 24) -> dict:
    """Get File Integrity Monitoring changes."""
    return await _wazuh_get("/fim", {"limit": 50, "sort": "-date"})


async def wazuh_vulnerabilities(agent_id: str = "001") -> dict:
    """Get vulnerability detection results for an agent."""
    return await _wazuh_get(f"/vulnerability/{agent_id}", {"limit": 50, "sort": "-severity"})


async def wazuh_sca(agent_id: str = "001") -> dict:
    """Get Security Configuration Assessment results."""
    return await _wazuh_get(f"/sca/{agent_id}", {"limit": 50})


async def wazuh_rootcheck(agent_id: str = "001") -> dict:
    """Get rootcheck/rootkit detection results."""
    return await _wazuh_get(f"/rootcheck/{agent_id}", {"limit": 50})


async def wazuh_rules(level_min: int = 10) -> dict:
    """Get high-level rules that have triggered."""
    return await _wazuh_get("/rules", {"limit": 50, "level": f"{level_min}-15"})


async def wazuh_mitre_alerts() -> dict:
    """Get alerts mapped to MITRE ATT&CK techniques."""
    return await _wazuh_get("/alerts", {
        "limit": 50,
        "sort": "-timestamp",
        "q": "rule.mitre.id!=''",
    })
