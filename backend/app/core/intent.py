"""
CyberSentinel v3.0 - LLM-Based Intent Detector
Uses the configured LLM to classify intent and extract parameters instead of regex.
"""
import json
import re
from typing import Optional

from app.core.config import settings
from app.services.ollama import stream_ollama
from app.services.claude import stream_claude
from app.services.openai_svc import stream_openai
from app.services.openrouter import stream_openrouter

ROUTER_PROMPT = """You are CyberSentinel Intent Router.
Your ONLY job is to determine if the user wants to execute a security tool.
You must output ONLY valid JSON. Do not output any markdown blocks (like ```json), explanations, or text.

Available tools:
- _full_domain_scan: (nmap+dns+ssl+headers) for full network/domain reconnaissance or penetration testing. Requires target.
- nmap_scan: port scanning. Requires target.
- dns_recon: DNS lookups. Requires target.
- ssl_check: SSL/TLS certificate checks. Requires target.
- http_headers: HTTP header checks. Requires target.
- nikto_scan: Web vulnerability scanner. Requires target.
- nuclei_scan: Nuclei vulnerability scanning (vuln scan, web scan). Requires target.
- sqlmap_scan: SQL injection testing. Requires target.
- zeek_analyze: PCAP/Network analysis. Requires target.
- zap_scan: OWASP ZAP web scan. Requires target.
- shodan_lookup: Shodan device/IP search. Requires target.
- virustotal_lookup: VT malware/IP/hash check. Requires target.
- abuseipdb_lookup: AbuseIPDB reputation check. Requires target.
- nvd_search: Search CVEs by keyword. Requires target.
- cisa_kev_check: Check if CVE is in CISA KEV. Requires target.
- elk_failed_logins: Check SIEM for failed logins (no target needed).
- elk_alerts: Check SIEM alerts (no target needed).

Output format if tool is needed:
{
  "tools": [
    {"tool": "<tool_name>", "args": {"target": "<ip_or_url>"}}
  ],
  "description": "<short description of what you are doing>"
}

Output format if NO tool is needed (user just wants to chat, ask a question, or say hi):
{
  "tools": []
}

Rules:
1. Output ONLY RAW JSON.
2. The user might use Chinese or English. If they use keywords like "漏扫" (nuclei_scan), "渗透测试" (_full_domain_scan), or "端口扫描" (nmap_scan), select the appropriate tool and extract the IP/URL as the target.
3. For nmap_scan, dns_recon, ssl_check, DO NOT include "http://" in the target. Provide only the IP or domain.
4. For nuclei_scan, nikto_scan, the target can include "http://".
"""

def _get_provider_stream_for_intent(messages: list[dict], provider: str, model: str | None = None):
    if provider == "ollama":
        return stream_ollama(messages, model or settings.ollama_model)
    elif provider == "claude":
        return stream_claude(messages, model or settings.claude_model)
    elif provider == "openai":
        return stream_openai(messages, model or settings.openai_model)
    elif provider == "openrouter":
        return stream_openrouter(messages, model or settings.openrouter_model)
    return None

async def async_detect_intent(user_message: str) -> Optional[dict]:
    """
    Detect tool execution intent using the LLM.
    Returns: {"tools": [{"tool": "name", "args": {...}}], "description": "..."} or None
    """
    provider = settings.ai_provider
    # Prepare messages
    messages = [
        {"role": "system", "content": ROUTER_PROMPT},
        {"role": "user", "content": user_message}
    ]
    
    stream = _get_provider_stream_for_intent(messages, provider, None)
    if not stream:
        return None

    # Accumulate response
    accumulated = ""
    async for chunk in stream:
        if chunk.startswith("data: "):
            try:
                data = json.loads(chunk[6:].strip())
                token = data.get("token", "")
                if token:
                    accumulated += token
            except Exception:
                pass

    accumulated = accumulated.strip()
    
    # Strip markdown code blocks if the LLM hallucinated them
    if "{" in accumulated and "}" in accumulated:
        start_idx = accumulated.find("{")
        end_idx = accumulated.rfind("}")
        if start_idx != -1 and end_idx != -1:
            accumulated = accumulated[start_idx:end_idx+1]
    
    try:
        parsed = json.loads(accumulated)
        if parsed and parsed.get("tools") and len(parsed["tools"]) > 0:
            
            # Special expansion for _full_domain_scan
            if parsed["tools"][0]["tool"] == "_full_domain_scan":
                target = parsed["tools"][0].get("args", {}).get("target", "")
                parsed["tools"] = [
                    {"tool": "nmap_scan", "args": {"target": target, "options": "-sV --top-ports 100"}},
                    {"tool": "ssl_check", "args": {"target": target}},
                    {"tool": "dns_recon", "args": {"target": target}},
                    {"tool": "http_headers", "args": {"target": target}},
                ]
                
            # Handle ELK default args if not provided
            if parsed["tools"][0]["tool"].startswith("elk_"):
                if "hours" not in parsed["tools"][0].get("args", {}):
                    if "args" not in parsed["tools"][0]:
                        parsed["tools"][0]["args"] = {}
                    parsed["tools"][0]["args"]["hours"] = 24
                    
            if not parsed.get("description"):
                parsed["description"] = f"Executing {parsed['tools'][0]['tool']}"
                
            return parsed
    except Exception as e:
        print(f"[Intent] JSON Parse error: {e}. Raw: {accumulated}")
        pass
        
    return None
