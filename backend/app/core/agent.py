"""
CyberSentinel v3.0 - Agentic Tool Execution Engine (Phase 3)
MCP-style: AI decides when to run tools → executes in sandbox → returns real results.

Flow:
  1. User asks a question
  2. AI router adds tool definitions to system prompt
  3. AI responds with <tool_call> tags when it wants to run something
  4. Agent intercepts, executes the tool, injects results back
  5. AI generates final response with real data
"""
import json
import re
import asyncio
from typing import Optional
from app.services.scanner import SCAN_REGISTRY, _run_in_sandbox, _sanitize, _strip_url
from app.services.threat_intel import (
    shodan_lookup, virustotal_lookup, abuseipdb_lookup, otx_lookup, multi_intel_lookup,
)


# ═══════════════════════════════════════════════
# TOOL DEFINITIONS - What the AI can call
# ═══════════════════════════════════════════════

AGENT_TOOLS = {
    "nmap_scan": {
        "description": "Run nmap port scan and service detection against a target IP or domain",
        "params": {"target": "IP or domain to scan", "options": "nmap flags (default: -sV --top-ports 100)"},
        "example": '<tool_call>{"tool":"nmap_scan","args":{"target":"10.0.0.1","options":"-sV --top-ports 100"}}</tool_call>',
    },
    "dns_recon": {
        "description": "DNS reconnaissance - A, MX, NS, TXT, SPF, DKIM, DMARC records",
        "params": {"target": "Domain to query"},
        "example": '<tool_call>{"tool":"dns_recon","args":{"target":"example.com"}}</tool_call>',
    },
    "ssl_check": {
        "description": "Check SSL/TLS certificate, protocols, and chain for a domain",
        "params": {"target": "Domain or IP:port"},
        "example": '<tool_call>{"tool":"ssl_check","args":{"target":"example.com"}}</tool_call>',
    },
    "whois_lookup": {
        "description": "WHOIS registration lookup for a domain or IP",
        "params": {"target": "Domain or IP"},
        "example": '<tool_call>{"tool":"whois_lookup","args":{"target":"example.com"}}</tool_call>',
    },
    "ping": {
        "description": "ICMP ping to check if a host is alive",
        "params": {"target": "IP or domain"},
        "example": '<tool_call>{"tool":"ping","args":{"target":"8.8.8.8"}}</tool_call>',
    },
    "traceroute": {
        "description": "Trace network path to a target",
        "params": {"target": "IP or domain"},
        "example": '<tool_call>{"tool":"traceroute","args":{"target":"8.8.8.8"}}</tool_call>',
    },
    "http_headers": {
        "description": "Fetch HTTP response headers from a URL to check security headers",
        "params": {"target": "URL to check"},
        "example": '<tool_call>{"tool":"http_headers","args":{"target":"https://example.com"}}</tool_call>',
    },
    "nikto_scan": {
        "description": "Run Nikto web vulnerability scanner against a web server",
        "params": {"target": "URL to scan (http://...)"},
        "example": '<tool_call>{"tool":"nikto_scan","args":{"target":"http://testphp.vulnweb.com"}}</tool_call>',
    },
    "nuclei_scan": {
        "description": "Run Nuclei vulnerability scanner to find CVEs and misconfigurations",
        "params": {"target": "URL to scan", "templates": "template filter (default: critical,high severity)"},
        "example": '<tool_call>{"tool":"nuclei_scan","args":{"target":"https://example.com"}}</tool_call>',
    },
    "subfinder": {
        "description": "Enumerate subdomains for a domain",
        "params": {"target": "Domain to enumerate"},
        "example": '<tool_call>{"tool":"subfinder","args":{"target":"example.com"}}</tool_call>',
    },
    "zeek_analyze": {
        "description": "Zeek network traffic analysis - captures and analyzes connections, DNS, HTTP, SSL",
        "params": {"target": "IP, domain, or PCAP file path"},
        "example": '<tool_call>{"tool":"zeek_analyze","args":{"target":"example.com"}}</tool_call>',
    },
    "zap_scan": {
        "description": "OWASP ZAP web application security scan - checks for vulnerabilities, misconfigs, exposed paths",
        "params": {"target": "URL to scan"},
        "example": '<tool_call>{"tool":"zap_scan","args":{"target":"http://testphp.vulnweb.com"}}</tool_call>',
    },
    "sqlmap_scan": {
        "description": "Run sqlmap SQL injection scanner against a URL with parameters",
        "params": {"target": "URL with parameters (e.g., http://site.com/page?id=1)"},
        "example": '<tool_call>{"tool":"sqlmap_scan","args":{"target":"http://testphp.vulnweb.com/listproducts.php?cat=1"}}</tool_call>',
    },
    "shodan_lookup": {
        "description": "Look up an IP on Shodan for open ports, services, vulnerabilities, and geolocation",
        "params": {"target": "IP address"},
        "example": '<tool_call>{"tool":"shodan_lookup","args":{"target":"8.8.8.8"}}</tool_call>',
    },
    "virustotal_lookup": {
        "description": "Check an IP, domain, or file hash on VirusTotal for malware detections",
        "params": {"target": "IP, domain, or file hash"},
        "example": '<tool_call>{"tool":"virustotal_lookup","args":{"target":"example.com"}}</tool_call>',
    },
    "abuseipdb_lookup": {
        "description": "Check IP reputation and abuse reports on AbuseIPDB",
        "params": {"target": "IP address"},
        "example": '<tool_call>{"tool":"abuseipdb_lookup","args":{"target":"1.2.3.4"}}</tool_call>',
    },
    "otx_lookup": {
        "description": "Look up threat intel on AlienVault OTX - pulses, reputation, related indicators",
        "params": {"target": "IP, domain, or hash"},
        "example": '<tool_call>{"tool":"otx_lookup","args":{"target":"1.2.3.4"}}</tool_call>',
    },
    "multi_intel": {
        "description": "Run an indicator against ALL threat intel sources (Shodan + VT + AbuseIPDB + OTX)",
        "params": {"target": "IP, domain, or hash"},
        "example": '<tool_call>{"tool":"multi_intel","args":{"target":"1.2.3.4"}}</tool_call>',
    },
    "elk_failed_logins": {
        "description": "Query Elasticsearch/ELK for failed login attempts (Windows 4625, Linux auth failures)",
        "params": {"hours": "How many hours back to search (default: 24)"},
        "example": '<tool_call>{"tool":"elk_failed_logins","args":{"hours":24}}</tool_call>',
    },
    "elk_lateral_movement": {
        "description": "Query ELK for lateral movement indicators (Windows Event 4648, 4624 Type 3 network logon)",
        "params": {"hours": "How many hours back to search (default: 24)"},
        "example": '<tool_call>{"tool":"elk_lateral_movement","args":{"hours":24}}</tool_call>',
    },
    "elk_powershell": {
        "description": "Query ELK for PowerShell execution events (Script block logging, process creation)",
        "params": {"hours": "How many hours back to search (default: 24)"},
        "example": '<tool_call>{"tool":"elk_powershell","args":{"hours":24}}</tool_call>',
    },
    "elk_alerts": {
        "description": "Query ELK for high/critical severity security alerts",
        "params": {"hours": "How many hours back to search (default: 24)"},
        "example": '<tool_call>{"tool":"elk_alerts","args":{"hours":24}}</tool_call>',
    },
    "elk_health": {
        "description": "Check Elasticsearch cluster health, node count, and status",
        "params": {},
        "example": '<tool_call>{"tool":"elk_health","args":{}}</tool_call>',
    },
    "splunk_health": {
        "description": "Check Splunk connection health and server info",
        "params": {},
        "example": '<tool_call>{"tool":"splunk_health","args":{}}</tool_call>',
    },
    "splunk_failed_logins": {
        "description": "Query Splunk for failed login attempts",
        "params": {"hours": "How many hours back to search (default: 24)"},
        "example": '<tool_call>{"tool":"splunk_failed_logins","args":{"hours":24}}</tool_call>',
    },
    "splunk_search": {
        "description": "Run a custom SPL query on Splunk",
        "params": {"query": "SPL search query string"},
        "example": '<tool_call>{"tool":"splunk_search","args":{"query":"search index=* earliest=-1h | stats count by sourcetype"}}</tool_call>',
    },
    "wazuh_health": {
        "description": "Check Wazuh manager health and API status",
        "params": {},
        "example": '<tool_call>{"tool":"wazuh_health","args":{}}</tool_call>',
    },
    "wazuh_alerts": {
        "description": "Query Wazuh for recent security alerts",
        "params": {"hours": "How many hours back to search (default: 24)"},
        "example": '<tool_call>{"tool":"wazuh_alerts","args":{"hours":24}}</tool_call>',
    },
    "wazuh_failed_logins": {
        "description": "Query Wazuh for failed authentication alerts",
        "params": {"hours": "How many hours back (default: 24)"},
        "example": '<tool_call>{"tool":"wazuh_failed_logins","args":{"hours":24}}</tool_call>',
    },
    "wazuh_agents": {
        "description": "List all registered Wazuh agents and their status",
        "params": {},
        "example": '<tool_call>{"tool":"wazuh_agents","args":{}}</tool_call>',
    },
}


def get_agent_system_prompt() -> str:
    """Build the system prompt with tool definitions for agentic mode."""
    tool_defs = "\n".join([
        f"- **{name}**: {info['description']}\n  Example: {info['example']}"
        for name, info in AGENT_TOOLS.items()
    ])

    return f"""You are CyberSentinel AI - an elite agentic cybersecurity platform with 33 specialized tools.
You have REAL tool execution capabilities. When a user asks you to scan, check, or look up something,
you MUST use your tools to get real data - do NOT make up results or give hypothetical output.

## HOW TO USE TOOLS

When you need to run a tool, output a tool_call tag in your response:
<tool_call>{{"tool":"tool_name","args":{{"target":"value"}}}}</tool_call>

You can call MULTIPLE tools in one response. Each tool_call will be executed and the results
will be injected back so you can analyze them.

## AVAILABLE TOOLS

{tool_defs}

## RULES

1. **ALWAYS use tools** when the user asks to scan, check, look up, or investigate something
2. You can chain multiple tools - e.g., dns_recon + ssl_check + http_headers for a full domain assessment
3. After receiving tool results, analyze them like a senior security engineer
4. Map findings to MITRE ATT&CK technique IDs where relevant
5. Rate severity: 🔴 Critical, 🟠 High, ⚠️ Medium, ✅ Low
6. Include actionable remediation steps
7. If a tool errors or times out, note it and proceed with other tools
8. NEVER fabricate tool output - only report what tools actually return
9. For comprehensive assessments, run multiple relevant tools

## RESPONSE FORMAT
- Start with relevant emoji + bold title
- Show tool execution with 🔧 prefix
- Present results in organized sections
- End with severity rating + next steps
- Use code blocks for technical output"""


# ═══════════════════════════════════════════════
# TOOL EXECUTOR - Actually runs the tools
# ═══════════════════════════════════════════════

# Map from sandbox scan functions
SCAN_FN_MAP = {
    "nmap_scan": "nmap",
    "dns_recon": "dns",
    "ssl_check": "ssl",
    "whois_lookup": "whois",
    "ping": "ping",
    "traceroute": "traceroute",
    "http_headers": "headers",
    "nikto_scan": "nikto",
    "nuclei_scan": "nuclei",
    "subfinder": "subfinder",
    "zeek_analyze": "zeek",
    "zap_scan": "zap",
}


async def execute_tool(tool_name: str, args: dict) -> dict:
    """Execute a single tool and return results."""
    target = args.get("target", "")

    # Sandbox scan tools
    if tool_name in SCAN_FN_MAP:
        scan_key = SCAN_FN_MAP[tool_name]
        if scan_key in SCAN_REGISTRY:
            fn = SCAN_REGISTRY[scan_key]["fn"]
            if tool_name == "nmap_scan":
                return await fn(target, args.get("options", "-sV --top-ports 100"))
            elif tool_name == "nuclei_scan":
                return await fn(target, args.get("templates", ""))
            else:
                return await fn(target)
        return {"success": False, "error": f"Scan type {scan_key} not found in registry"}

    # sqlmap (special - not in SCAN_REGISTRY yet)
    if tool_name == "sqlmap_scan":
        safe = _sanitize(target)
        if not safe.startswith("http"):
            safe = f"http://{safe}"
        cmd = f"sqlmap -u '{safe}' --batch --level=1 --risk=1 --timeout=30 --retries=1 2>&1 | tail -80"
        return await _run_in_sandbox(cmd, timeout=120)

    # Threat intel API tools
    if tool_name == "shodan_lookup":
        return await shodan_lookup(target)
    if tool_name == "virustotal_lookup":
        return await virustotal_lookup(target)
    if tool_name == "abuseipdb_lookup":
        return await abuseipdb_lookup(target)
    if tool_name == "otx_lookup":
        return await otx_lookup(target)
    if tool_name == "multi_intel":
        return await multi_intel_lookup(target)

    # NVD / CISA KEV tools - queries the local threat intel database
    if tool_name in ("nvd_top_cves", "nvd_search", "nvd_cve_lookup", "cisa_kev", "cisa_kev_check", "nvd_critical", "nvd_epss"):
        import httpx
        base = "http://localhost:8000/api/threat-feed"
        async with httpx.AsyncClient(timeout=15) as c:
            try:
                if tool_name == "nvd_top_cves":
                    r = await c.get(f"{base}/cves/top", params={"limit": 15})
                    return {"source": "nvd_local", "type": "top_cves", **r.json()}
                elif tool_name == "nvd_critical":
                    r = await c.get(f"{base}/cves/search", params={"min_cvss": 9.0, "limit": 15})
                    return {"source": "nvd_local", "type": "critical_cves", **r.json()}
                elif tool_name == "nvd_search":
                    r = await c.get(f"{base}/cves/search", params={"q": target, "limit": 15})
                    return {"source": "nvd_local", "type": "cve_search", **r.json()}
                elif tool_name == "nvd_cve_lookup":
                    r = await c.get(f"{base}/cves/{target}")
                    return {"source": "nvd_local", "type": "cve_detail", **r.json()}
                elif tool_name == "cisa_kev":
                    r = await c.get(f"{base}/cves/exploited", params={"limit": 15})
                    return {"source": "cisa_kev", "type": "exploited_vulns", **r.json()}
                elif tool_name == "cisa_kev_check":
                    r = await c.get(f"{base}/cves/{target}")
                    data = r.json()
                    return {"source": "cisa_kev", "type": "kev_check", "cve_id": target, "in_kev": data.get("in_cisa_kev", False), **data}
                elif tool_name == "nvd_epss":
                    r = await c.get(f"{base}/cves/{target}")
                    data = r.json()
                    return {"source": "epss", "type": "epss_lookup", "cve_id": target, "epss_score": data.get("epss_score"), "epss_percentile": data.get("epss_percentile"), **data}
            except Exception as e:
                return {"source": "nvd_local", "error": str(e)[:200]}

    # ELK / Elasticsearch tools
    if tool_name.startswith("elk_"):
        from app.services.elk import (
            elk_health as _elk_health,
            elk_failed_logins as _elk_failed_logins,
            elk_lateral_movement as _elk_lateral_movement,
            elk_powershell_events as _elk_powershell,
            elk_high_severity_alerts as _elk_alerts,
        )
        hours = int(args.get("hours", 24))
        if tool_name == "elk_health":
            return await _elk_health()
        elif tool_name == "elk_failed_logins":
            return await _elk_failed_logins(hours)
        elif tool_name == "elk_lateral_movement":
            return await _elk_lateral_movement(hours)
        elif tool_name == "elk_powershell":
            return await _elk_powershell(hours)
        elif tool_name == "elk_alerts":
            return await _elk_alerts(hours)

    # Splunk tools
    if tool_name.startswith("splunk_"):
        from app.services.splunk import (
            splunk_health as _splunk_health,
            splunk_failed_logins as _splunk_fl,
            splunk_lateral_movement as _splunk_lat,
            splunk_powershell as _splunk_ps,
            splunk_alerts as _splunk_alerts,
            splunk_search as _splunk_search,
        )
        hours = int(args.get("hours", 24))
        if tool_name == "splunk_health":
            return await _splunk_health()
        elif tool_name == "splunk_failed_logins":
            return await _splunk_fl(hours)
        elif tool_name == "splunk_lateral_movement":
            return await _splunk_lat(hours)
        elif tool_name == "splunk_powershell":
            return await _splunk_ps(hours)
        elif tool_name == "splunk_alerts":
            return await _splunk_alerts(hours)
        elif tool_name == "splunk_search":
            return await _splunk_search(args.get("query", "search index=* | head 10"))

    # Wazuh tools
    if tool_name.startswith("wazuh_"):
        from app.services.wazuh import (
            wazuh_health as _wazuh_health,
            wazuh_agents as _wazuh_agents,
            wazuh_alerts as _wazuh_alerts,
            wazuh_failed_logins as _wazuh_fl,
            wazuh_fim_changes as _wazuh_fim,
            wazuh_vulnerabilities as _wazuh_vulns,
            wazuh_mitre_alerts as _wazuh_mitre,
        )
        hours = int(args.get("hours", 24))
        if tool_name == "wazuh_health":
            return await _wazuh_health()
        elif tool_name == "wazuh_agents":
            return await _wazuh_agents()
        elif tool_name == "wazuh_alerts":
            return await _wazuh_alerts(hours)
        elif tool_name == "wazuh_failed_logins":
            return await _wazuh_fl(hours)
        elif tool_name == "wazuh_fim":
            return await _wazuh_fim(hours)
        elif tool_name == "wazuh_vulnerabilities":
            return await _wazuh_vulns(args.get("agent_id", "001"))
        elif tool_name == "wazuh_mitre":
            return await _wazuh_mitre()

    return {"success": False, "error": f"Unknown tool: {tool_name}"}


def extract_tool_calls(text: str) -> list[dict]:
    """Parse <tool_call>...</tool_call> tags from AI response."""
    pattern = r'<tool_call>(.*?)</tool_call>'
    matches = re.findall(pattern, text, re.DOTALL)
    calls = []
    for m in matches:
        try:
            data = json.loads(m.strip())
            if "tool" in data:
                calls.append(data)
        except json.JSONDecodeError:
            continue
    return calls


async def execute_all_tools(tool_calls: list[dict]) -> list[dict]:
    """Execute all tool calls concurrently and return results."""
    async def _exec_one(tc):
        tool_name = tc.get("tool", "")
        args = tc.get("args", {})
        try:
            result = await execute_tool(tool_name, args)
            return {
                "tool": tool_name,
                "target": args.get("target", ""),
                "result": result,
            }
        except Exception as e:
            return {
                "tool": tool_name,
                "target": args.get("target", ""),
                "result": {"success": False, "error": str(e)[:500]},
            }

    # Run all tools concurrently (max 5 at a time)
    sem = asyncio.Semaphore(5)
    async def _limited(tc):
        async with sem:
            return await _exec_one(tc)

    results = await asyncio.gather(*[_limited(tc) for tc in tool_calls])
    return list(results)


def format_tool_results(results: list[dict]) -> str:
    """Format tool execution results for injection back into the conversation."""
    parts = []
    for r in results:
        tool = r["tool"]
        target = r["target"]
        result = r["result"]

        parts.append(f"\n--- TOOL RESULT: {tool} (target: {target}) ---")

        if isinstance(result, dict):
            if result.get("output"):
                # Sandbox tool output
                output = result["output"][:8000]  # Limit to prevent token overflow
                duration = result.get("duration", "?")
                parts.append(f"Duration: {duration}s | Exit code: {result.get('exit_code', '?')}")
                parts.append(f"```\n{output}\n```")
            elif result.get("error") and not result.get("success", True):
                parts.append(f"ERROR: {result['error']}")
            else:
                # API result - format as JSON
                clean = {k: v for k, v in result.items() if v and k != "source"}
                parts.append(f"```json\n{json.dumps(clean, indent=2, default=str)[:4000]}\n```")
        else:
            parts.append(str(result)[:4000])

    return "\n".join(parts)
