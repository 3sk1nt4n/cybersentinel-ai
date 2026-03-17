"""
CyberSentinel v3.0 - Intent Detector (Phase 3)
Pattern-matches user queries to auto-detect which tools to run.
This bypasses the unreliable AI tool_call approach for local models.

Instead of: User → AI → tool_call → execute → AI analyzes
Now:        User → intent detect → execute tools directly → AI analyzes real results
"""
import re
from typing import Optional


# ═══════════════════════════════════════════════
# INTENT PATTERNS - Maps user queries to tools
# ═══════════════════════════════════════════════

INTENT_PATTERNS = [
    # Nmap / Port scanning
    {
        "patterns": [
            r"(?:nmap|port)\s*(?:scan|check)",
            r"scan\s+(?:ports?|services?)\s+(?:on|for|of)\s+(\S+)",
            r"(?:scan|check)\s+(\S+)\s+(?:for\s+)?(?:open\s+)?ports",
            r"nmap\s+(\S+)",
            r"run\s+(?:a\s+)?(?:port|nmap|service)\s+scan",
        ],
        "tool": "nmap_scan",
        "extract_target": True,
    },
    # DNS Recon
    {
        "patterns": [
            r"dns\s*(?:recon|lookup|check|scan|records?)",
            r"(?:check|get|find|show)\s+(?:dns|mx|spf|dkim|dmarc|txt)\s+(?:records?|for)\s+(\S+)",
            r"(?:dns|domain)\s+(?:recon|reconnaissance)\s+(?:on|for)\s+(\S+)",
        ],
        "tool": "dns_recon",
        "extract_target": True,
    },
    # SSL/TLS Check
    {
        "patterns": [
            r"ssl\s*(?:check|scan|test|cert|certificate)",
            r"(?:check|test|verify)\s+ssl\s+(?:on|for|of)\s+(\S+)",
            r"tls\s*(?:check|scan|test|config)",
            r"certificate\s+(?:check|info|details)",
        ],
        "tool": "ssl_check",
        "extract_target": True,
    },
    # WHOIS
    {
        "patterns": [
            r"whois\s+(\S+)",
            r"(?:whois|registration)\s+(?:lookup|check|info)",
            r"who\s+owns\s+(\S+)",
        ],
        "tool": "whois_lookup",
        "extract_target": True,
    },
    # HTTP Headers
    {
        "patterns": [
            r"(?:http|security)\s*headers?\s+(?:check|scan|for|of|on)\s+(\S+)",
            r"(?:check|get|show)\s+(?:http\s+)?headers?\s+(?:for|of|on)\s+(\S+)",
            r"headers?\s+(?:scan|check)\s+(\S+)",
        ],
        "tool": "http_headers",
        "extract_target": True,
    },
    # Nikto
    {
        "patterns": [
            r"nikto\s+(?:scan|check|run)",
            r"(?:run|execute)\s+nikto",
            r"web\s+vulnerability\s+scan",
            r"nikto\s+(?:on|against)\s+(\S+)",
        ],
        "tool": "nikto_scan",
        "extract_target": True,
    },
    # Nuclei
    {
        "patterns": [
            r"nuclei\s+(?:scan|check|run)",
            r"(?:run|execute)\s+nuclei",
            r"(?:cve|vulnerability|vuln)\s+scan\s+(?:on|against|for)\s+(\S+)",
            r"nuclei\s+(?:on|against)\s+(\S+)",
        ],
        "tool": "nuclei_scan",
        "extract_target": True,
    },
    # SQLMap
    {
        "patterns": [
            r"sqlmap\s+(?:scan|check|run|test)",
            r"sql\s*injection\s+(?:scan|test|check)",
            r"(?:run|execute|test)\s+sqlmap",
            r"sqli\s+(?:scan|test|check)",
        ],
        "tool": "sqlmap_scan",
        "extract_target": True,
    },
    # Subfinder
    {
        "patterns": [
            r"(?:subdomain|sub)\s*(?:enum|enumerat|find|discover|scan)",
            r"(?:find|enumerate|discover)\s+subdomains?\s+(?:for|of|on)\s+(\S+)",
            r"subfinder\s+(\S+)",
        ],
        "tool": "subfinder",
        "extract_target": True,
    },
    # Traceroute
    {
        "patterns": [
            r"traceroute\s+(\S+)",
            r"trace\s+(?:route|path)\s+(?:to|for)\s+(\S+)",
        ],
        "tool": "traceroute",
        "extract_target": True,
    },
    # Ping
    {
        "patterns": [
            r"ping\s+(\S+)",
            r"(?:is|check\s+if)\s+(\S+)\s+(?:up|alive|online|reachable)",
        ],
        "tool": "ping",
        "extract_target": True,
    },
    # Shodan
    {
        "patterns": [
            r"shodan\s+(?:lookup|search|check|scan|find|query)",
            r"(?:search|lookup|check|find|query)\s+.*(?:on\s+)?shodan",
            r"shodan\s+(\S+)",
            r"(?:exposed|internet|open)\s+(?:services?|ports?|devices?)\s+(?:for|on)\s+(\S+)",
            r"(?:find|search)\s+(?:all\s+)?open\s+ports?\s+(?:for|on)\s+(\S+)",
            r"(?:find|search\s+for)\s+(?:exposed|open)\s+(?:\w+\s+)?(?:on|for)\s+(\S+)",
            r"(?:find|search\s+for)\s+exposed\s+(?:rdp|ssh|mongodb|redis|elasticsearch|webcam|iot|router)",
            r"(?:exposed|open)\s+(?:rdp|ssh|mongodb|redis|elasticsearch|webcam|iot)",
            r"(?:default\s+credentials?|vulnerable)\s+(?:on\s+)?(?:webcam|router|device)",
        ],
        "tool": "shodan_lookup",
        "extract_target": True,
    },
    # VirusTotal
    {
        "patterns": [
            r"virustotal\s+(?:lookup|check|scan|analysis|report|search)",
            r"(?:check|scan|lookup|analyze|report)\s+.*(?:on\s+)?virustotal",
            r"(?:vt|virustotal)\s+(\S+)",
            r"(?:is|check\s+if)\s+(\S+)\s+(?:malicious|malware|infected|flagged)",
            r"(?:check|scan)\s+(?:file\s+)?hash\s+(?:on\s+)?(?:virustotal|vt)",
            r"(?:check|get)\s+(?:url|domain|ip)\s+reputation\s+(?:on\s+)?(?:virustotal|vt)",
            r"(?:multi.engine|detection)\s+(?:for|on)\s+(?:suspicious\s+)?hash",
            r"(?:malware|phishing)\s+(?:detection|analysis)\s+(?:for|on)\s+(\S+)",
            r"(\S+)\s+(?:on\s+)?virustotal",
        ],
        "tool": "virustotal_lookup",
        "extract_target": True,
    },
    # AbuseIPDB
    {
        "patterns": [
            r"abuseipdb\s+(?:lookup|check|search|report|query)",
            r"(?:check|lookup|search|report|query)\s+.*(?:on\s+)?abuseipdb",
            r".*abuseipdb.*(\d+\.\d+\.\d+\.\d+)",
            r"(\d+\.\d+\.\d+\.\d+)\s+.*abuseipdb",
            r"(?:abuse|reputation)\s+(?:check|lookup|score)\s+(?:for|on)\s+(\S+)",
            r"(?:ip\s+)?reputation\s+(?:for|of|check)\s+(\S+)",
            r"(?:report\s+)?malicious\s+ip\s+(?:to\s+)?abuseipdb",
            r"(?:abuse\s+)?confidence\s+score\s+(?:for|of)\s+(\S+)",
            r"(?:check|get)\s+(?:abuse\s+)?reports?\s+(?:for|on)\s+(?:suspicious\s+)?(?:ip|address)",
            r"(?:reported\s+for|check\s+if.*reported)\s+(?:brute\s+force|scanning|spam)",
            r"(?:country|isp|geo)\s+(?:info|information)\s+(?:for\s+)?(?:malicious\s+)?ip",
            r"(?:check|lookup)\s+(?:our\s+)?firewall\s+blocked\s+ips?",
        ],
        "tool": "abuseipdb_lookup",
        "extract_target": True,
    },
    # OTX
    {
        "patterns": [
            r"(?:otx|alienvault)\s+(?:lookup|check|search|query|fetch|get)",
            r"(?:check|lookup|search|query|fetch|get)\s+.*(?:on\s+)?(?:otx|alienvault)",
            r"(?:get|fetch|pull|show|list)\s+(?:latest\s+)?(?:malware\s+)?(?:iocs?|indicators?|pulses?)\s+(?:from\s+)?(?:otx|alienvault)",
            r"(?:otx|alienvault)\s+(?:iocs?|indicators?|pulses?|malware|threats?)",
            r"(?:latest|recent|new)\s+(?:malware\s+)?(?:iocs?|indicators?)\s+(?:from\s+)?(?:otx|alienvault)",
            r"(?:search|find)\s+(?:otx|alienvault)\s+(?:for\s+)?(.+)",
            r"(?:otx|alienvault)\s+(?:for|on)\s+(.+)",
            r"(.+?)\s+(?:on|from|in)\s+(?:otx|alienvault)",
        ],
        "tool": "otx_lookup",
        "extract_target": True,
    },
    # Multi-intel (all sources)
    {
        "patterns": [
            r"(?:full|all|multi)\s+(?:threat\s+)?intel(?:ligence)?\s+(?:lookup|check|on|for)\s+(\S+)",
            r"(?:lookup|check|investigate)\s+(\S+)\s+(?:on\s+)?all\s+(?:threat\s+)?(?:intel|sources)",
            r"(?:threat\s+intel|intelligence)\s+(?:lookup|check)\s+(?:for|on)\s+(\S+)",
            r"look\s*up\s+(\S+)\s+(?:on\s+)?all\s+(?:threat\s+)?intel",
        ],
        "tool": "multi_intel",
        "extract_target": True,
    },
    # ═══ NVD / CVE Tools ═══
    # Show latest/top/critical CVEs
    {
        "patterns": [
            r"(?:show|get|list|fetch)\s+(?:latest|top|recent|new)\s+(?:critical\s+)?cves?",
            r"(?:latest|top|recent|new)\s+(?:critical\s+)?cves?\s+(?:from\s+)?nvd",
            r"nvd\s+(?:latest|top|recent|critical)\s+cves?",
            r"(?:critical|high)\s+(?:severity\s+)?cves?\s+(?:from\s+)?nvd",
        ],
        "tool": "nvd_top_cves",
        "extract_target": False,
    },
    # CVEs above score threshold
    {
        "patterns": [
            r"cves?\s+(?:with\s+)?cvss\s+(?:score\s+)?(?:above|over|greater|>=?)\s+(\d+\.?\d*)",
            r"(?:show|get|list)\s+(?:all\s+)?(?:critical\s+)?cves?\s+(?:with\s+)?(?:cvss|score)\s+(?:above|over|>=?)\s+(\d+\.?\d*)",
        ],
        "tool": "nvd_critical",
        "extract_target": False,
    },
    # Search CVEs by keyword (Log4j, Exchange, Apache, etc)
    {
        "patterns": [
            r"(?:search|find)\s+(?:nvd|cves?)\s+(?:for\s+)?(.+)",
            r"nvd\s+(?:search|lookup|find)\s+(?:for\s+)?(.+)",
            r"(?:search|find)\s+(?:for\s+)?(.+?)\s+cves?",
            r"(.+?)\s+cves?\s+(?:in\s+)?nvd",
        ],
        "tool": "nvd_search",
        "extract_target": True,
    },
    # Look up specific CVE ID
    {
        "patterns": [
            r"(?:check|lookup|look\s*up|get|show|details?\s+(?:for|on|about))\s+(CVE-\d{4}-\d+)",
            r"(CVE-\d{4}-\d+)\s+(?:details?|info|lookup|check)",
            r"(?:what\s+is|tell\s+me\s+about)\s+(CVE-\d{4}-\d+)",
        ],
        "tool": "nvd_cve_lookup",
        "extract_target": True,
    },
    # ═══ CISA KEV ═══
    # Check if specific CVE is in KEV (must be BEFORE general KEV listing)
    {
        "patterns": [
            r"(?:check|is)\s+(?:if\s+)?(cve-\d{4}-\d+)\s+(?:in\s+)?(?:cisa\s+)?kev",
            r"(cve-\d{4}-\d+)\s+(?:in\s+)?(?:cisa\s+)?(?:kev|known\s+exploited)",
            r"(?:is\s+)?(cve-\d{4}-\d+)\s+(?:actively\s+)?exploited",
            r"(?:check|is)\s+.*?(cve-\d{4}-\d+)\s+.*?(?:cisa|kev|exploited)",
        ],
        "tool": "cisa_kev_check",
        "extract_target": True,
    },
    # List CISA KEV
    {
        "patterns": [
            r"(?:show|get|list|check)\s+(?:cisa\s+)?(?:known\s+)?exploited\s+vulnerabilities",
            r"cisa\s+(?:kev|known\s+exploited)",
            r"(?:actively\s+)?exploited\s+(?:cves?|vulns?|vulnerabilities)",
            r"(?:latest|recent)\s+exploited\s+(?:cves?|vulns?|vulnerabilities)",
            r"(?:show|get|list)\s+(?:all\s+)?(?:critical\s+)?cves?\s+with\s+(?:active\s+)?exploits?",
        ],
        "tool": "cisa_kev",
        "extract_target": False,
    },
    # ═══ EPSS ═══
    {
        "patterns": [
            r"(?:get|show|check)\s+epss\s+(?:score|probability|rating)\s+(?:for\s+)?(CVE-\d{4}-\d+)",
            r"epss\s+(?:for|of|score)\s+(CVE-\d{4}-\d+)",
            r"(CVE-\d{4}-\d+)\s+epss\s+(?:score|probability)",
            r"(?:get|show)\s+epss\s+(?:scores?\s+)?(?:for\s+)?(?:recent|critical)\s+(?:cves?|vulnerabilities)",
            r"epss\s+(?:scores?|probability|probabilities)\s+(?:for|of)\s+(?:recent|critical|latest)",
        ],
        "tool": "nvd_epss",
        "extract_target": True,
    },
    # ELK queries
    {
        "patterns": [
            r"(?:elk|elastic|elasticsearch)\s+(?:failed|bad)\s+login",
            r"(?:failed|bad)\s+login(?:s)?\s+(?:in|from|on)\s+(?:elk|elastic|siem)",
            r"(?:query|search|check)\s+(?:elk|elastic)\s+(?:for\s+)?failed\s+login",
        ],
        "tool": "elk_failed_logins",
        "extract_target": False,
    },
    {
        "patterns": [
            r"(?:elk|elastic|siem)\s+(?:lateral\s+movement|4648|4624)",
            r"lateral\s+movement\s+(?:in|from|on)\s+(?:elk|elastic|siem)",
        ],
        "tool": "elk_lateral_movement",
        "extract_target": False,
    },
    {
        "patterns": [
            r"(?:elk|elastic|siem)\s+(?:powershell|4104)",
            r"powershell\s+(?:event|execution|log)s?\s+(?:in|from)\s+(?:elk|elastic|siem)",
        ],
        "tool": "elk_powershell",
        "extract_target": False,
    },
    {
        "patterns": [
            r"(?:elk|elastic|siem)\s+(?:alert|high.severity|critical)",
            r"(?:alerts?|detection)\s+(?:from|in)\s+(?:elk|elastic|siem)",
            r"(?:pull|get|show)\s+(?:elk|elastic|siem)\s+alerts?",
        ],
        "tool": "elk_alerts",
        "extract_target": False,
    },
    {
        "patterns": [
            r"(?:elk|elastic)\s+(?:health|status|cluster)",
            r"(?:check|connect)\s+(?:to\s+)?(?:elk|elastic)",
        ],
        "tool": "elk_health",
        "extract_target": False,
    },
    # Splunk - failed logins
    {
        "patterns": [
            r"splunk\s+(?:failed|bad)\s+login",
            r"(?:failed|bad)\s+login.*splunk",
            r"splunk.*(?:brute\s*force|auth.*fail)",
        ],
        "tool": "splunk_failed_logins",
        "extract_target": False,
    },
    # Splunk - lateral movement
    {
        "patterns": [
            r"splunk\s+(?:lateral|4648|logon\s*type\s*3)",
            r"(?:lateral|movement).*splunk",
        ],
        "tool": "splunk_lateral_movement",
        "extract_target": False,
    },
    # Splunk - PowerShell
    {
        "patterns": [
            r"splunk\s+(?:powershell|ps\s+event|script\s*block)",
            r"(?:powershell|script.block).*splunk",
        ],
        "tool": "splunk_powershell",
        "extract_target": False,
    },
    # Splunk - alerts
    {
        "patterns": [
            r"splunk\s+(?:alert|detection|rule)",
            r"(?:pull|get|show)\s+splunk\s+alert",
        ],
        "tool": "splunk_alerts",
        "extract_target": False,
    },
    # Splunk - health
    {
        "patterns": [
            r"splunk\s+(?:health|status|connect)",
            r"(?:check|test)\s+splunk",
            r"connect.*splunk",
        ],
        "tool": "splunk_health",
        "extract_target": False,
    },
    # Splunk - general search
    {
        "patterns": [
            r"splunk\s+(?:search|query|spl)\b",
            r"(?:run|execute)\s+(?:spl|splunk)\s+(?:search|query)",
            r"(?:search|query)\s+splunk\s+for",
        ],
        "tool": "splunk_search",
        "extract_target": False,
    },
    # Wazuh - health
    {
        "patterns": [
            r"wazuh\s+(?:health|status|connect)",
            r"(?:check|test)\s+wazuh",
            r"connect.*wazuh",
        ],
        "tool": "wazuh_health",
        "extract_target": False,
    },
    # Wazuh - agents
    {
        "patterns": [
            r"wazuh\s+agent",
            r"(?:list|show|check)\s+wazuh\s+agent",
        ],
        "tool": "wazuh_agents",
        "extract_target": False,
    },
    # Wazuh - alerts
    {
        "patterns": [
            r"wazuh\s+(?:alert|detection|event)",
            r"(?:pull|get|show)\s+wazuh\s+alert",
        ],
        "tool": "wazuh_alerts",
        "extract_target": False,
    },
    # Wazuh - failed logins
    {
        "patterns": [
            r"wazuh\s+(?:failed|bad)\s+login",
            r"(?:failed|bad)\s+login.*wazuh",
            r"wazuh.*(?:brute\s*force|auth.*fail)",
        ],
        "tool": "wazuh_failed_logins",
        "extract_target": False,
    },
    # Wazuh - FIM
    {
        "patterns": [
            r"wazuh\s+(?:fim|file\s*integrity)",
            r"(?:file\s*integrity|fim).*wazuh",
        ],
        "tool": "wazuh_fim",
        "extract_target": False,
    },
    # Wazuh - vulnerabilities
    {
        "patterns": [
            r"wazuh\s+(?:vuln|vulnerability)",
            r"(?:vuln|vulnerability).*wazuh",
        ],
        "tool": "wazuh_vulnerabilities",
        "extract_target": False,
    },
    # Wazuh - MITRE
    {
        "patterns": [
            r"wazuh\s+(?:mitre|att.ck)",
            r"(?:mitre|att.ck).*wazuh",
        ],
        "tool": "wazuh_mitre",
        "extract_target": False,
    },
    # Full domain scan (multi-tool)
    {
        "patterns": [
            r"(?:full|complete|comprehensive)\s+(?:domain\s+)?scan\s+(?:on|of|for)\s+(\S+)",
            r"scan\s+(\S+)\s+(?:—|-|–)\s+",
            r"(?:scan|assess|check)\s+(\S+\.(?:com|org|net|io|dev|co|ai|xyz|me))\b",
        ],
        "tool": "_full_domain_scan",
        "extract_target": True,
    },
    # Zeek - network analysis
    {
        "patterns": [
            r"zeek\s+(?:analyz|scan|check|run)",
            r"(?:analyz|inspect)\s+(?:network|traffic|pcap|packet).*zeek",
            r"(?:run|use)\s+zeek",
            r"zeek\s+(?:on|against)\s+(\S+)",
            r"(?:network|traffic)\s+(?:analysis|monitor|capture)",
            r"(?:capture|sniff).*(?:network|traffic|packet)",
            r"(?:capture|analyz).*(?:network\s+traffic|packets?|connections?)\s+(?:to|on|from|for)",
            r"(?:traffic|packet)\s+(?:capture|analysis)\s+(?:on|to|for|against)",
            r"analyz.*\.pcap",
        ],
        "tool": "zeek_analyze",
        "extract_target": True,
    },
    # OWASP ZAP - web app scan
    {
        "patterns": [
            r"(?:zap|owasp)\s+(?:scan|check|test|run)",
            r"(?:run|use)\s+(?:zap|owasp\s*zap)",
            r"(?:web\s*app|webapp)\s+(?:security\s+)?(?:scan|test|check)",
            r"zap\s+(?:on|against)\s+(\S+)",
            r"owasp\s+(?:scan|check)",
        ],
        "tool": "zap_scan",
        "extract_target": True,
    },
]


def _extract_target_from_text(text: str) -> Optional[str]:
    """Try to extract an IP, domain, or URL from text."""
    # URL
    url_match = re.search(r'(https?://\S+)', text)
    if url_match:
        return url_match.group(1).rstrip('.,;:')

    # IP address
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', text)
    if ip_match:
        return ip_match.group(1)

    # Domain
    domain_match = re.search(r'(\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b)', text)
    if domain_match:
        candidate = domain_match.group(1)
        # Skip common words that look like domains
        if candidate.lower() not in {"e.g", "i.e", "etc.com", "vs.com"}:
            return candidate

    # Email -> extract domain
    email_match = re.search(r'(\S+@(\S+\.\S+))', text)
    if email_match:
        return email_match.group(2)

    return None


def detect_intent(user_message: str) -> Optional[dict]:
    """
    Detect tool execution intent from user message.
    Returns: {"tools": [{"tool": "name", "args": {...}}], "description": "..."} or None
    """
    text = user_message.lower().strip()

    for intent in INTENT_PATTERNS:
        for pattern in intent["patterns"]:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                tool = intent["tool"]
                target = None

                # Try to get target from regex group
                if match.lastindex and match.lastindex >= 1:
                    target = match.group(match.lastindex).strip().rstrip('.,;:?')

                # Fallback: extract from full text
                if not target and intent.get("extract_target"):
                    target = _extract_target_from_text(user_message)

                # Handle multi-tool scans
                if tool == "_full_domain_scan" and target:
                    return {
                        "tools": [
                            {"tool": "nmap_scan", "args": {"target": target, "options": "-sV --top-ports 100"}},
                            {"tool": "ssl_check", "args": {"target": target}},
                            {"tool": "dns_recon", "args": {"target": target}},
                            {"tool": "http_headers", "args": {"target": target}},
                        ],
                        "description": f"Full domain scan on {target} (nmap + SSL + DNS + headers)",
                    }

                # ELK tools don't need a target
                if not intent.get("extract_target"):
                    return {
                        "tools": [{"tool": tool, "args": {"hours": 24}}],
                        "description": f"Running {tool.replace('_', ' ')}",
                    }

                if target:
                    return {
                        "tools": [{"tool": tool, "args": {"target": target}}],
                        "description": f"Running {tool.replace('_', ' ')} on {target}",
                    }

                # Some tools can work without a specific target (general queries)
                TOOLS_OK_WITHOUT_TARGET = {
                    "shodan_lookup", "otx_lookup", "abuseipdb_lookup", "virustotal_lookup",
                    "nvd_top_cves", "nvd_critical", "nvd_search", "nvd_epss",
                    "cisa_kev", "cisa_kev_check",
                }
                if tool in TOOLS_OK_WITHOUT_TARGET:
                    return {
                        "tools": [{"tool": tool, "args": {"target": user_message.strip()}}],
                        "description": f"Running {tool.replace('_', ' ')}",
                    }

    return None
