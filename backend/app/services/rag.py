"""
CyberSentinel v3.0 - RAG Service (Embedded ChromaDB)
Uses ChromaDB in EMBEDDED mode - runs inside the backend process.
No separate container, no network issues, no healthchecks needed.
Data persists to /app/data/chromadb volume.
"""
import hashlib
import os
from app.core.logging import get_logger

logger = get_logger(__name__)

_client = None
CHROMA_PATH = os.environ.get("CHROMA_DATA_DIR", "/app/data/chromadb")

COLLECTIONS = {
    "security_kb": "Core cybersecurity knowledge base",
    "mitre_attack": "MITRE ATT&CK techniques and procedures",
    "cve_data": "CVE vulnerability descriptions and mitigations",
    "compliance": "Compliance framework controls and requirements",
    "user_docs": "User-uploaded documents and reports",
}


def get_chroma_client():
    global _client
    if _client is not None:
        return _client
    try:
        os.makedirs(CHROMA_PATH, exist_ok=True)
        import chromadb
        _client = chromadb.PersistentClient(path=CHROMA_PATH)
        logger.info(f"Embedded mode OK - {CHROMA_PATH}")
        return _client
    except Exception as e:
        logger.error(f"Init failed: {e}")
        return None


def _chunk_text(text: str, chunk_size: int = 1000, overlap: int = 200) -> list[str]:
    if len(text) <= chunk_size:
        return [text]
    chunks, start = [], 0
    while start < len(text):
        end = start + chunk_size
        if end < len(text):
            brk = max(text.rfind('. ', start + chunk_size // 2, end), text.rfind('\n', start + chunk_size // 2, end))
            if brk > start:
                end = brk + 1
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        start = end - overlap
    return chunks


def _make_id(text: str) -> str:
    return hashlib.sha256(text[:500].encode()).hexdigest()[:16]


async def search_knowledge(query: str, collection_name: str = "security_kb", n_results: int = 5) -> list[dict]:
    client = get_chroma_client()
    if not client:
        return []
    try:
        coll = client.get_or_create_collection(collection_name)
        if coll.count() == 0:
            return []
        actual_n = min(n_results, coll.count())
        results = coll.query(query_texts=[query], n_results=actual_n)
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        dists = results.get("distances", [[]])[0]
        return [{"text": d, "metadata": m, "score": 1 - dist} for d, m, dist in zip(docs, metas, dists) if d]
    except Exception:
        return []


async def multi_collection_search(query: str, n_results: int = 3) -> list[dict]:
    all_r = []
    for coll_name in COLLECTIONS:
        results = await search_knowledge(query, coll_name, n_results)
        for r in results:
            r["collection"] = coll_name
        all_r.extend(results)
    all_r.sort(key=lambda x: x.get("score", 0), reverse=True)
    return all_r[:n_results * 2]


async def add_document(text: str, collection_name: str = "security_kb", metadata: dict = None, chunk: bool = True) -> int:
    client = get_chroma_client()
    if not client:
        return 0
    try:
        coll = client.get_or_create_collection(collection_name)
        chunks = _chunk_text(text) if chunk else [text]
        base_meta = metadata or {}
        ids = [_make_id(c) for c in chunks]
        metas = [{**base_meta, "chunk_index": i, "total_chunks": len(chunks)} for i in range(len(chunks))]
        coll.upsert(ids=ids, documents=chunks, metadatas=metas)
        return len(chunks)
    except Exception:
        return 0


async def add_batch(items: list[dict], collection_name: str = "security_kb") -> int:
    total = 0
    for item in items:
        total += await add_document(text=item["text"], collection_name=collection_name, metadata=item.get("metadata"))
    return total


async def get_rag_context(query: str) -> str:
    results = await multi_collection_search(query, n_results=5)
    if not results:
        return ""
    parts = []
    for r in results:
        src = r.get("metadata", {}).get("source", r.get("collection", "kb"))
        parts.append(f"[Source: {src}]\n{r['text']}")
    return "\n\n---\n\n".join(parts)


async def get_collection_stats() -> dict:
    client = get_chroma_client()
    if not client:
        return {"status": "disconnected", "collections": {}}
    try:
        stats = {}
        for name, desc in COLLECTIONS.items():
            try:
                coll = client.get_or_create_collection(name)
                stats[name] = {"description": desc, "documents": coll.count()}
            except Exception:
                stats[name] = {"description": desc, "documents": 0}
        return {"status": "connected", "collections": stats}
    except Exception:
        return {"status": "error", "collections": {}}


async def delete_collection(collection_name: str) -> bool:
    client = get_chroma_client()
    if not client:
        return False
    try:
        client.delete_collection(collection_name)
        return True
    except Exception:
        return False


SEED_DATA = {
    "mitre_attack": [
        {"text": "T1059.001 - PowerShell: Adversaries use PowerShell for execution. Detection: Monitor Event ID 4104 (Script Block Logging), 4103 (Module Logging). Look for encoded commands (-enc), bypass attempts (-ep bypass), download cradles (IEX, Invoke-WebRequest).", "metadata": {"source": "MITRE ATT&CK", "tactic": "Execution", "technique_id": "T1059.001"}},
        {"text": "T1003.001 - LSASS Memory: Adversaries dump LSASS to extract credentials. Detection: Monitor for processes accessing lsass.exe (Sysmon Event ID 10). Tools: Mimikatz, comsvcs.dll, procdump. Prevent with Credential Guard and LSA Protection.", "metadata": {"source": "MITRE ATT&CK", "tactic": "Credential Access", "technique_id": "T1003.001"}},
        {"text": "T1558.003 - Kerberoasting: Adversaries request TGS tickets for SPNs to crack offline. Detection: Event ID 4769 with Ticket_Encryption_Type 0x17 (RC4). Mitigate: Long random SPN passwords, prefer AES, monitor anomalous TGS requests.", "metadata": {"source": "MITRE ATT&CK", "tactic": "Credential Access", "technique_id": "T1558.003"}},
        {"text": "T1021.001 - RDP: Adversaries use Remote Desktop for lateral movement. Detection: Event ID 4624 Logon Type 10, unusual source IPs. Mitigate: Restrict RDP, require MFA, use jump servers.", "metadata": {"source": "MITRE ATT&CK", "tactic": "Lateral Movement", "technique_id": "T1021.001"}},
        {"text": "T1486 - Data Encrypted for Impact: Ransomware encrypts files. Detection: Mass file modifications, shadow copy deletion (vssadmin delete shadows), bcdedit changes. Mitigate: Offline backups, segmentation, EDR.", "metadata": {"source": "MITRE ATT&CK", "tactic": "Impact", "technique_id": "T1486"}},
        {"text": "T1190 - Exploit Public-Facing Application: Adversaries exploit internet-facing vulnerabilities. Detection: WAF logs, anomalous HTTP requests, unexpected process creation from web servers. Mitigate: Patch management, WAF, input validation.", "metadata": {"source": "MITRE ATT&CK", "tactic": "Initial Access", "technique_id": "T1190"}},
        {"text": "T1053.005 - Scheduled Task: Adversaries create scheduled tasks for persistence. Detection: Event ID 4698 (created), 4702 (updated). Monitor tasks from unusual users or temp directories.", "metadata": {"source": "MITRE ATT&CK", "tactic": "Persistence", "technique_id": "T1053.005"}},
        {"text": "T1071.001 - Web Protocols: Adversaries use HTTP/HTTPS for C2. Detection: Beaconing patterns, unusual user-agents, high-volume single-domain connections, DNS over HTTPS.", "metadata": {"source": "MITRE ATT&CK", "tactic": "Command and Control", "technique_id": "T1071.001"}},
    ],
    "compliance": [
        {"text": "CIS Control 1 - Inventory and Control of Enterprise Assets: Actively manage all connected assets. IG1: 1.1 Establish inventory, 1.2 Address unauthorized assets. IG2: 1.3 Use DHCP logging, 1.4 Client certificates. IG3: 1.5 Network-level auth.", "metadata": {"source": "CIS Controls v8", "control": "1"}},
        {"text": "CIS Control 4 - Secure Configuration: Establish and maintain secure configs. IG1: 4.1 Secure config process, 4.2 Change defaults, 4.3 Auto-lock. IG2: 4.4 Firewall on servers, 4.6 Securely manage assets. IG3: 4.8 Disable unnecessary services.", "metadata": {"source": "CIS Controls v8", "control": "4"}},
        {"text": "CIS Control 8 - Audit Log Management: Collect, alert, review, retain logs. IG1: 8.1 Log management process, 8.2 Collect logs, 8.3 Adequate storage. IG2: 8.5 Detailed logs, 8.9 Centralize. IG3: 8.11 Log reviews, 8.12 Service provider logs.", "metadata": {"source": "CIS Controls v8", "control": "8"}},
        {"text": "NIST 800-53 AC-2 Account Management: Manage accounts - establish, activate, modify, review, disable, remove. Require MFA for privileged. Review annually.", "metadata": {"source": "NIST 800-53", "control_family": "Access Control"}},
        {"text": "PCI-DSS v4.0 Req 8: 8.3.1 MFA for admin access. 8.3.6 Minimum 12-char passwords. 8.6 Strictly manage application/system accounts.", "metadata": {"source": "PCI-DSS v4.0", "requirement": "8"}},
        {"text": "HIPAA 164.312: Access Control - Unique user ID (Required), Emergency access (Required), Auto logoff (Addressable). Transmission Security - Integrity controls (Addressable), Encryption (Addressable but expected for ePHI).", "metadata": {"source": "HIPAA", "section": "164.312"}},
    ],
    "security_kb": [
        {"text": "Incident Response (NIST 800-61): 1) Preparation - plan, team, tools. 2) Detection & Analysis - monitor, validate, scope. 3) Containment - isolate short-term, patch long-term. 4) Eradication - remove malware, close vulns. 5) Recovery - restore, monitor. 6) Lessons Learned - review, update.", "metadata": {"source": "NIST 800-61", "topic": "Incident Response"}},
        {"text": "Key Log Sources: Windows Security (4624/4625 logon, 4688 process, 4698 task, 4720 account, 7045 service). Sysmon (1 process, 3 network, 7 DLL, 10 access, 11 file, 13 registry). Linux: auth.log, syslog, audit.log. Network: firewall, proxy, DNS, NetFlow.", "metadata": {"source": "Security Operations", "topic": "Log Sources"}},
        {"text": "Ransomware Response: IMMEDIATE - 1) Isolate (disconnect, don't shutdown). 2) Preserve evidence (memory dump, disk image). 3) Identify variant (note, extensions). 4) Check lateral movement. 5) Notify IR team. DON'T: Pay immediately, wipe before forensics, use compromised channels.", "metadata": {"source": "IR Playbook", "topic": "Ransomware"}},
        {"text": "EPSS vs CVSS: CVSS = theoretical severity (0-10). EPSS = exploitation probability in 30 days (0-1.0). Best: EPSS > 0.5 first, then CVSS >= 9.0. Risk = EPSS x CVSS x Asset_Value.", "metadata": {"source": "Vulnerability Management", "topic": "Prioritization"}},
        {"text": "Zero Trust: 1) Never trust, always verify. 2) Assume breach. 3) Verify explicitly. 4) Least privilege. 5) Micro-segmentation. Implement: Identity-aware proxy, device posture, continuous auth, encryption, real-time monitoring.", "metadata": {"source": "Zero Trust", "topic": "Architecture"}},
    ],
    "cve_data": [
        {"text": "CVE-2021-44228 (Log4Shell) - CVSS 10.0. Apache Log4j2 RCE via JNDI lookup in log messages. Affects versions 2.0-2.14.1. Mitigation: Upgrade to 2.17.1+, set log4j2.formatMsgNoLookups=true, remove JndiLookup class from classpath.", "metadata": {"source": "NVD", "cve_id": "CVE-2021-44228", "cvss": 10.0}},
        {"text": "CVE-2023-44228 (Apache Struts RCE) - CVSS 9.8. Path traversal leading to RCE in file upload. Affects Struts 2.0.0-6.3.0.1. Mitigation: Upgrade to 6.3.0.2+, restrict file upload paths, implement WAF rules.", "metadata": {"source": "NVD", "cve_id": "CVE-2023-44228", "cvss": 9.8}},
        {"text": "CVE-2024-3400 (PAN-OS GlobalProtect) - CVSS 10.0. Command injection in GlobalProtect gateway. Actively exploited in the wild. Mitigation: Apply hotfix, enable Threat Prevention signatures, check for webshell indicators.", "metadata": {"source": "NVD", "cve_id": "CVE-2024-3400", "cvss": 10.0}},
        {"text": "CVE-2023-23397 (Outlook Elevation of Privilege) - CVSS 9.8. NTLM relay via crafted calendar invite, no user interaction needed. Mitigation: Apply Microsoft patch, block outbound SMB (TCP 445), audit for exploitation.", "metadata": {"source": "NVD", "cve_id": "CVE-2023-23397", "cvss": 9.8}},
        {"text": "CVE-2024-21762 (FortiOS SSL VPN RCE) - CVSS 9.6. Out-of-bounds write in FortiOS SSL VPN. Exploited by state-sponsored actors. Mitigation: Upgrade FortiOS, disable SSL VPN if not needed, monitor for anomalous VPN sessions.", "metadata": {"source": "NVD", "cve_id": "CVE-2024-21762", "cvss": 9.6}},
        {"text": "CVE-2023-34362 (MOVEit Transfer SQLi) - CVSS 9.8. SQL injection in MOVEit Transfer web app. Used by Cl0p ransomware gang. Mitigation: Patch immediately, check for webshells in MOVEit directories, audit file transfer logs.", "metadata": {"source": "NVD", "cve_id": "CVE-2023-34362", "cvss": 9.8}},
        {"text": "CVE-2024-0012 (PAN-OS Management Interface Auth Bypass) - CVSS 9.3. Authentication bypass in PAN-OS management interface. Mitigation: Restrict management interface access to trusted IPs, apply patch, review access logs.", "metadata": {"source": "NVD", "cve_id": "CVE-2024-0012", "cvss": 9.3}},
        {"text": "CVE-2023-22515 (Confluence DC/Server Broken Access Control) - CVSS 10.0. Allows creation of unauthorized admin accounts. Mitigation: Upgrade Confluence, restrict external access, audit admin accounts for unauthorized entries.", "metadata": {"source": "NVD", "cve_id": "CVE-2023-22515", "cvss": 10.0}},
    ],
}


async def seed_knowledge_base() -> dict:
    results = {}
    for coll_name, items in SEED_DATA.items():
        results[coll_name] = await add_batch(items, coll_name)
    return results
