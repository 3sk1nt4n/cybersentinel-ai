"""
CyberSentinel v3.0 - Live Threat Intel Feed Router
Serves live CVEs, IOCs, C2 data from threat_intel_puller.py SQLite DB.
"""
import sqlite3
import json
import os
import asyncio
import threading
from fastapi import APIRouter
from pathlib import Path
from app.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/threat-feed", tags=["threat-feed"])

DATA_DIR = Path("/app/data/threat_data")
DB_PATH = DATA_DIR / "threat_intel.db"
SUMMARY_PATH = DATA_DIR / "threat_summary.json"


def _get_db():
    """Get SQLite connection if DB exists."""
    if not DB_PATH.exists():
        return None
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # Allow concurrent reads during writes
    return conn


@router.get("/status")
async def feed_status():
    """Get threat intel feed status and stats."""
    conn = _get_db()
    if not conn:
        return {"status": "no_data", "message": "Run threat intel puller first"}

    try:
        stats = {
            "total_cves": conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0],
            "critical_cves": conn.execute("SELECT COUNT(*) FROM cves WHERE cvss_score >= 9.0").fetchone()[0],
            "exploited_vulns": conn.execute("SELECT COUNT(*) FROM exploited_vulns").fetchone()[0],
            "total_iocs": conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0],
            "active_c2": conn.execute("SELECT COUNT(*) FROM c2_servers").fetchone()[0],
        }

        feeds = []
        for row in conn.execute("SELECT feed_name, last_pull, records_pulled, status FROM feed_status").fetchall():
            feeds.append({"feed": row[0], "last_pull": row[1], "records": row[2], "status": row[3]})

        conn.close()
        return {"status": "loaded", "stats": stats, "feeds": feeds}
    except Exception as e:
        conn.close()
        return {"status": "error", "message": str(e)[:200]}


@router.get("/summary")
async def get_summary():
    """Get the full threat intel summary JSON."""
    if SUMMARY_PATH.exists():
        with open(SUMMARY_PATH, "r") as f:
            return json.load(f)
    return {"status": "no_data", "message": "Run threat intel puller first"}


@router.get("/cves/top")
async def top_cves(limit: int = 10):
    """Get top CVEs by CVSS score."""
    conn = _get_db()
    if not conn:
        return {"cves": []}
    try:
        rows = conn.execute("""
            SELECT cve_id, description, cvss_score, cvss_severity, epss_score, vendor, product, published, actively_exploited
            FROM cves ORDER BY cvss_score DESC LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return {"cves": [dict(r) for r in rows]}
    except Exception as e:
        conn.close()
        return {"cves": [], "error": str(e)}


@router.get("/cves/search")
async def search_cves(q: str = "", min_cvss: float = 0, limit: int = 15):
    """Search CVEs by keyword, vendor, product, or CVE ID."""
    conn = _get_db()
    if not conn:
        return {"cves": [], "query": q}
    query = q.strip()
    if not query:
        rows = conn.execute("""
            SELECT cve_id, description, cvss_score, cvss_severity, epss_score, vendor, product, published, actively_exploited
            FROM cves WHERE cvss_score >= ? ORDER BY cvss_score DESC LIMIT ?
        """, (min_cvss, limit)).fetchall()
    else:
        rows = conn.execute("""
            SELECT cve_id, description, cvss_score, cvss_severity, epss_score, vendor, product, published, actively_exploited
            FROM cves WHERE (cve_id LIKE ? OR description LIKE ? OR vendor LIKE ? OR product LIKE ?)
            AND cvss_score >= ? ORDER BY cvss_score DESC LIMIT ?
        """, (f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%", min_cvss, limit)).fetchall()
    conn.close()
    return {"cves": [dict(r) for r in rows], "query": query, "count": len(rows)}


@router.get("/cves/exploited")
async def exploited_cves(limit: int = 10):
    """Get CISA KEV actively exploited vulnerabilities."""
    conn = _get_db()
    if not conn:
        return {"vulns": [], "status": "db_not_ready"}
    try:
        rows = conn.execute("""
            SELECT cve_id, vendor, product, name, date_added, due_date, known_ransomware
            FROM exploited_vulns ORDER BY date_added DESC LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return {"vulns": [dict(r) for r in rows]}
    except Exception as e:
        conn.close()
        return {"vulns": [], "status": "error", "message": str(e)}


@router.get("/cves/{cve_id}")
async def get_cve(cve_id: str):
    """Get details for a specific CVE."""
    conn = _get_db()
    if not conn:
        return {"error": "No threat intel database"}
    row = conn.execute("""
        SELECT cve_id, description, cvss_score, cvss_severity, epss_score, epss_percentile,
               vendor, product, published, actively_exploited, cisa_due_date
        FROM cves WHERE cve_id = ?
    """, (cve_id.upper(),)).fetchone()
    # Check if in KEV
    kev = conn.execute("SELECT * FROM exploited_vulns WHERE cve_id = ?", (cve_id.upper(),)).fetchone()
    conn.close()
    if not row:
        return {"error": f"{cve_id} not found in local database", "cve_id": cve_id}
    result = dict(row)
    result["in_cisa_kev"] = kev is not None
    if kev:
        result["kev_details"] = dict(kev)
    return result


@router.get("/iocs/recent")
async def recent_iocs(ioc_type: str = "ip", limit: int = 15):
    """Get recent IOCs by type (ip, domain, hash_sha256, url)."""
    conn = _get_db()
    if not conn:
        return {"iocs": []}
    rows = conn.execute("""
        SELECT indicator, source, threat_type, malware_family, confidence, first_seen
        FROM iocs WHERE type=? ORDER BY fetched_at DESC LIMIT ?
    """, (ioc_type, limit)).fetchall()
    conn.close()
    return {"iocs": [dict(r) for r in rows]}


@router.get("/c2")
async def c2_servers(limit: int = 10):
    """Get recent C2 servers."""
    conn = _get_db()
    if not conn:
        return {"servers": []}
    rows = conn.execute("""
        SELECT ip, port, malware, status, country, last_online
        FROM c2_servers ORDER BY last_online DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return {"servers": [dict(r) for r in rows]}


@router.get("/feed-counts")
async def feed_counts():
    """Get IOC counts per source for the sidebar."""
    conn = _get_db()
    if not conn:
        return {"counts": {}}
    try:
        counts = {}
        for row in conn.execute("SELECT source, COUNT(*) as cnt FROM iocs GROUP BY source").fetchall():
            counts[row[0]] = row[1]
        conn.close()
        return {"counts": counts}
    except:
        conn.close()
        return {"counts": {}}


@router.post("/pull")
async def trigger_pull():
    """Trigger a threat intel pull in the background."""
    def _run():
        try:
            from app.services.threat_intel_puller import main
            main()
        except Exception as e:
            logger.error(f"Pull error: {e}")

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return {"status": "pulling", "message": "Threat intel pull started in background"}
