"""
CyberSentinel v3.0 - Threat Intelligence Service (Phase 3)
Live lookups against Shodan, VirusTotal, AbuseIPDB, and AlienVault OTX.
Works with or without API keys - degrades gracefully.
"""
import httpx
from typing import Optional
from app.core.config import settings

TIMEOUT = 15


async def shodan_lookup(target: str) -> dict:
    """Look up IP/domain on Shodan (free tier compatible).
    
    Free tier supports: /shodan/host/{ip}, /dns/resolve, /api-info
    Free tier does NOT support: /shodan/host/search (requires membership)
    """
    if not settings.shodan_api_key:
        return {"source": "shodan", "error": "No API key configured. Add SHODAN_API_KEY to .env"}
    key = settings.shodan_api_key
    try:
        import re
        async with httpx.AsyncClient(timeout=TIMEOUT) as c:
            target = target.strip()
            is_ip = bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', target))

            if is_ip:
                ip = target
            else:
                # Step 1: Resolve domain → IP via Shodan DNS (free tier OK)
                dns_r = await c.get(f"https://api.shodan.io/dns/resolve?hostnames={target}&key={key}")
                if dns_r.status_code != 200:
                    return {"source": "shodan", "error": f"DNS resolve failed: HTTP {dns_r.status_code} - {dns_r.text[:200]}"}
                dns_data = dns_r.json()
                ip = dns_data.get(target)
                if not ip:
                    return {"source": "shodan", "target": target, "info": "Could not resolve domain to IP address"}

            # Step 2: Host lookup by IP (free tier OK)
            r = await c.get(f"https://api.shodan.io/shodan/host/{ip}?key={key}")
            if r.status_code == 200:
                data = r.json()
                return {
                    "source": "shodan",
                    "target": target,
                    "ip": data.get("ip_str"),
                    "org": data.get("org"),
                    "os": data.get("os"),
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", []),
                    "hostnames": data.get("hostnames", []),
                    "country": data.get("country_name"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "asn": data.get("asn"),
                    "last_update": data.get("last_update"),
                    "services": [
                        {
                            "port": s.get("port"),
                            "transport": s.get("transport"),
                            "product": s.get("product", ""),
                            "version": s.get("version", ""),
                            "banner": (s.get("data", "")[:200] if s.get("data") else ""),
                        }
                        for s in data.get("data", [])[:15]
                    ],
                }
            elif r.status_code == 404:
                return {"source": "shodan", "target": target, "ip": ip,
                        "info": "No Shodan data for this IP (not yet scanned or no open ports detected)"}
            elif r.status_code == 401:
                return {"source": "shodan", "error": "API key invalid or expired. Check SHODAN_API_KEY in .env"}
            return {"source": "shodan", "error": f"HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"source": "shodan", "error": str(e)[:200]}


async def virustotal_lookup(indicator: str, indicator_type: str = "auto") -> dict:
    """Look up IP/domain/hash on VirusTotal."""
    if not settings.virustotal_api_key:
        return {"source": "virustotal", "error": "No API key configured. Add VIRUSTOTAL_API_KEY to .env"}

    # Auto-detect type
    if indicator_type == "auto":
        if all(c in "0123456789abcdefABCDEF" for c in indicator) and len(indicator) in (32, 40, 64):
            indicator_type = "files"
        elif indicator.replace(".", "").isdigit():
            indicator_type = "ip_addresses"
        else:
            indicator_type = "domains"

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as c:
            r = await c.get(
                f"https://www.virustotal.com/api/v3/{indicator_type}/{indicator}",
                headers={"x-apikey": settings.virustotal_api_key},
            )
            if r.status_code == 200:
                data = r.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "source": "virustotal",
                    "indicator": indicator,
                    "type": indicator_type,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": data.get("reputation"),
                    "tags": data.get("tags", []),
                    "last_analysis_date": data.get("last_analysis_date"),
                }
            return {"source": "virustotal", "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "virustotal", "error": str(e)[:200]}


async def abuseipdb_lookup(ip: str) -> dict:
    """Check IP reputation on AbuseIPDB."""
    if not settings.abuseipdb_api_key:
        return {"source": "abuseipdb", "error": "No API key configured. Add ABUSEIPDB_API_KEY to .env"}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as c:
            r = await c.get(
                f"https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": settings.abuseipdb_api_key or "", "Accept": "application/json"},
            )
            if r.status_code == 200:
                data = r.json().get("data", {})
                return {
                    "source": "abuseipdb",
                    "ip": ip,
                    "abuse_score": data.get("abuseConfidenceScore"),
                    "country": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "usage_type": data.get("usageType"),
                    "total_reports": data.get("totalReports"),
                    "last_reported": data.get("lastReportedAt"),
                    "is_public": data.get("isPublic"),
                }
            return {"source": "abuseipdb", "error": f"HTTP {r.status_code} - add ABUSEIPDB_API_KEY to .env for AbuseIPDB lookups"}
    except Exception as e:
        return {"source": "abuseipdb", "error": str(e)[:200]}


async def otx_lookup(indicator: str, indicator_type: str = "IPv4") -> dict:
    """Look up indicator on AlienVault OTX."""
    # If no specific indicator, fetch latest pulses/IOCs
    if not indicator or indicator.lower() in ("latest", "malware", "iocs", "recent", "all", "pulses", "threats"):
        return await otx_latest_pulses()

    if not settings.otx_api_key:
        return {"source": "otx", "error": "No API key configured. Add OTX_API_KEY to .env"}

    type_map = {"ip": "IPv4", "domain": "domain", "hash": "file", "url": "url"}
    otx_type = type_map.get(indicator_type.lower(), indicator_type)

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as c:
            r = await c.get(
                f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator}/general",
                headers={"X-OTX-API-KEY": settings.otx_api_key},
            )
            if r.status_code == 200:
                data = r.json()
                return {
                    "source": "otx",
                    "indicator": indicator,
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "pulses": [p.get("name") for p in data.get("pulse_info", {}).get("pulses", [])[:5]],
                    "reputation": data.get("reputation"),
                    "country": data.get("country_name"),
                    "validation": data.get("validation", []),
                }
            return {"source": "otx", "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "otx", "error": str(e)[:200]}


async def otx_latest_pulses() -> dict:
    """Fetch latest threat pulses/IOCs from OTX - no specific target needed."""
    if not settings.otx_api_key:
        return {"source": "otx", "error": "No API key configured. Add OTX_API_KEY to .env"}

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as c:
            r = await c.get(
                "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10&page=1",
                headers={"X-OTX-API-KEY": settings.otx_api_key},
            )
            if r.status_code == 200:
                data = r.json()
                pulses = []
                for p in data.get("results", [])[:10]:
                    indicators = p.get("indicators", [])[:5]
                    pulses.append({
                        "name": p.get("name"),
                        "description": (p.get("description") or "")[:200],
                        "created": p.get("created"),
                        "tags": p.get("tags", [])[:5],
                        "adversary": p.get("adversary"),
                        "targeted_countries": p.get("targeted_countries", [])[:3],
                        "indicator_count": len(p.get("indicators", [])),
                        "sample_iocs": [{"type": i.get("type"), "indicator": i.get("indicator")} for i in indicators],
                    })
                return {
                    "source": "otx",
                    "type": "latest_pulses",
                    "total_pulses": data.get("count", 0),
                    "pulses": pulses,
                }
            return {"source": "otx", "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "otx", "error": str(e)[:200]}


async def multi_intel_lookup(indicator: str) -> dict:
    """Run indicator against ALL available threat intel sources."""
    results = {}

    # Detect type
    is_ip = indicator.replace(".", "").isdigit() and indicator.count(".") == 3
    is_hash = all(c in "0123456789abcdefABCDEF" for c in indicator) and len(indicator) in (32, 40, 64)

    if is_ip:
        results["shodan"] = await shodan_lookup(indicator)
        results["virustotal"] = await virustotal_lookup(indicator, "ip_addresses")
        results["abuseipdb"] = await abuseipdb_lookup(indicator)
        results["otx"] = await otx_lookup(indicator, "IPv4")
    elif is_hash:
        results["virustotal"] = await virustotal_lookup(indicator, "files")
        results["otx"] = await otx_lookup(indicator, "file")
    else:
        # Assume domain
        results["virustotal"] = await virustotal_lookup(indicator, "domains")
        results["otx"] = await otx_lookup(indicator, "domain")

    return {"indicator": indicator, "results": results}
