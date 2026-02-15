#!/usr/bin/env python3
"""
CyberSentinel Threat Intelligence Feed Puller
Pulls from 7 free threat intel sources and stores in SQLite + ChromaDB
Run as scheduled task every 2 hours
"""

import sqlite3
import json
import os
import sys
import time
import logging
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Runtime dependencies must be baked into the container image.
try:
    import requests
except ImportError as exc:
    raise RuntimeError("Missing dependency: requests. Add it to backend requirements and rebuild image.") from exc

# ═══════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════
DATA_DIR = Path(os.environ.get("CS_DATA_DIR", "/app/data/threat_data"))
DB_PATH = DATA_DIR / "threat_intel.db"
FEEDS_DIR = DATA_DIR / "feeds"
LOG_PATH = DATA_DIR / "puller.log"

# API Keys (optional - many feeds are free without keys)
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")  # Optional, increases rate limit

# Ensure dirs exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
FEEDS_DIR.mkdir(parents=True, exist_ok=True)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("ThreatIntel")

# ═══════════════════════════════════════════════════════
# DATABASE SETUP
# ═══════════════════════════════════════════════════════
def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            cvss_score REAL,
            cvss_severity TEXT,
            epss_score REAL,
            epss_percentile REAL,
            cwe_id TEXT,
            vendor TEXT,
            product TEXT,
            published TEXT,
            modified TEXT,
            references_json TEXT,
            actively_exploited INTEGER DEFAULT 0,
            cisa_due_date TEXT,
            fetched_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            type TEXT NOT NULL,  -- ip, domain, hash_md5, hash_sha1, hash_sha256, url, email
            source TEXT NOT NULL,  -- otx, abusech, feodo, urlhaus
            threat_type TEXT,  -- malware, c2, phishing, ransomware
            malware_family TEXT,
            confidence INTEGER DEFAULT 50,  -- 0-100
            tags TEXT,  -- JSON array
            first_seen TEXT,
            last_seen TEXT,
            fetched_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(indicator, source)
        );
        
        CREATE TABLE IF NOT EXISTS exploited_vulns (
            cve_id TEXT PRIMARY KEY,
            vendor TEXT,
            product TEXT,
            name TEXT,
            description TEXT,
            date_added TEXT,
            due_date TEXT,
            known_ransomware TEXT,
            notes TEXT,
            fetched_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS c2_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            port INTEGER,
            status TEXT,  -- online, offline
            malware TEXT,
            first_seen TEXT,
            last_online TEXT,
            country TEXT,
            as_number TEXT,
            source TEXT,
            fetched_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(ip, port, source)
        );
        
        CREATE TABLE IF NOT EXISTS feed_status (
            feed_name TEXT PRIMARY KEY,
            last_pull TEXT,
            records_pulled INTEGER,
            status TEXT,  -- success, error
            error_msg TEXT,
            duration_sec REAL
        );
        
        -- Full-text search indexes
        CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
            cve_id, description, vendor, product, content=cves
        );
        
        CREATE VIRTUAL TABLE IF NOT EXISTS iocs_fts USING fts5(
            indicator, type, threat_type, malware_family, tags, content=iocs
        );
        
        -- Regular indexes
        CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss_score DESC);
        CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published DESC);
        CREATE INDEX IF NOT EXISTS idx_cves_exploited ON cves(actively_exploited);
        CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
        CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);
        CREATE INDEX IF NOT EXISTS idx_iocs_indicator ON iocs(indicator);
        CREATE INDEX IF NOT EXISTS idx_c2_malware ON c2_servers(malware);
    """)
    conn.commit()
    return conn


def update_feed_status(conn, feed_name, records, status, error="", duration=0):
    conn.execute("""
        INSERT OR REPLACE INTO feed_status (feed_name, last_pull, records_pulled, status, error_msg, duration_sec)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (feed_name, datetime.utcnow().isoformat(), records, status, error, duration))
    conn.commit()


# ═══════════════════════════════════════════════════════
# FEED 1: NVD - CVEs + CVSS Scores
# ═══════════════════════════════════════════════════════
def pull_nvd_cves(conn, days_back=7):
    log.info("Pulling NVD CVEs (last %d days)...", days_back)
    start = time.time()
    
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)
    
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": 200
    }
    
    total = 0
    start_index = 0
    
    while True:
        params["startIndex"] = start_index
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            log.error("NVD API error: %s", e)
            update_feed_status(conn, "nvd_cves", total, "error", str(e), time.time()-start)
            break
        
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break
        
        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            
            # Get description
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            
            # Get CVSS score
            cvss_score = 0
            cvss_severity = "UNKNOWN"
            metrics = cve.get("metrics", {})
            
            # Try CVSS 3.1 first, then 3.0, then 2.0
            for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0)
                    cvss_severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    break
            
            # Get CWE
            cwe_id = ""
            weaknesses = cve.get("weaknesses", [])
            if weaknesses:
                for w in weaknesses:
                    for wd in w.get("description", []):
                        if wd.get("value", "").startswith("CWE-"):
                            cwe_id = wd["value"]
                            break
            
            # Get vendor/product from configurations
            vendor = ""
            product = ""
            configs = cve.get("configurations", [])
            if configs:
                for cfg in configs:
                    for node in cfg.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            cpe = match.get("criteria", "")
                            parts = cpe.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                break
            
            published = cve.get("published", "")
            modified = cve.get("lastModified", "")
            refs = json.dumps([r.get("url", "") for r in cve.get("references", [])][:5])
            
            try:
                conn.execute("""
                    INSERT OR REPLACE INTO cves 
                    (cve_id, description, cvss_score, cvss_severity, cwe_id, vendor, product, published, modified, references_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (cve_id, desc, cvss_score, cvss_severity, cwe_id, vendor, product, published, modified, refs))
                
                # Update FTS
                conn.execute("INSERT OR REPLACE INTO cves_fts (rowid, cve_id, description, vendor, product) VALUES ((SELECT rowid FROM cves WHERE cve_id=?), ?, ?, ?, ?)",
                    (cve_id, cve_id, desc, vendor, product))
                
                total += 1
            except Exception as e:
                log.warning("Failed to insert %s: %s", cve_id, e)
        
        conn.commit()
        
        total_results = data.get("totalResults", 0)
        start_index += len(vulns)
        if start_index >= total_results:
            break
        
        time.sleep(1 if NVD_API_KEY else 6)  # Rate limiting
    
    duration = time.time() - start
    log.info("NVD: Pulled %d CVEs in %.1fs", total, duration)
    update_feed_status(conn, "nvd_cves", total, "success", "", duration)
    return total


# ═══════════════════════════════════════════════════════
# FEED 2: CISA KEV - Known Exploited Vulnerabilities
# ═══════════════════════════════════════════════════════
def pull_cisa_kev(conn):
    log.info("Pulling CISA Known Exploited Vulnerabilities...")
    start = time.time()
    
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        log.error("CISA KEV error: %s", e)
        update_feed_status(conn, "cisa_kev", 0, "error", str(e), time.time()-start)
        return 0
    
    total = 0
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "")
        try:
            conn.execute("""
                INSERT OR REPLACE INTO exploited_vulns
                (cve_id, vendor, product, name, description, date_added, due_date, known_ransomware, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cve_id,
                vuln.get("vendorProject", ""),
                vuln.get("product", ""),
                vuln.get("vulnerabilityName", ""),
                vuln.get("shortDescription", ""),
                vuln.get("dateAdded", ""),
                vuln.get("dueDate", ""),
                vuln.get("knownRansomwareCampaignUse", ""),
                vuln.get("notes", "")
            ))
            
            # Mark as actively exploited in CVEs table
            conn.execute("UPDATE cves SET actively_exploited=1, cisa_due_date=? WHERE cve_id=?",
                (vuln.get("dueDate", ""), cve_id))
            total += 1
        except Exception as e:
            log.warning("CISA KEV insert error for %s: %s", cve_id, e)
    
    conn.commit()
    duration = time.time() - start
    log.info("CISA KEV: Pulled %d exploited vulns in %.1fs", total, duration)
    update_feed_status(conn, "cisa_kev", total, "success", "", duration)
    return total


# ═══════════════════════════════════════════════════════
# FEED 3: EPSS - Exploit Prediction Scoring System
# ═══════════════════════════════════════════════════════
def pull_epss(conn):
    log.info("Pulling EPSS scores...")
    start = time.time()
    
    url = "https://api.first.org/data/v1/epss?order=!epss&limit=1000"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        log.error("EPSS error: %s", e)
        update_feed_status(conn, "epss", 0, "error", str(e), time.time()-start)
        return 0
    
    total = 0
    for item in data.get("data", []):
        cve_id = item.get("cve", "")
        epss = float(item.get("epss", 0))
        percentile = float(item.get("percentile", 0))
        
        conn.execute("UPDATE cves SET epss_score=?, epss_percentile=? WHERE cve_id=?",
            (epss, percentile, cve_id))
        total += 1
    
    conn.commit()
    duration = time.time() - start
    log.info("EPSS: Updated %d scores in %.1fs", total, duration)
    update_feed_status(conn, "epss", total, "success", "", duration)
    return total


# ═══════════════════════════════════════════════════════
# FEED 4: AlienVault OTX - IOCs
# ═══════════════════════════════════════════════════════
def pull_otx_pulses(conn):
    log.info("Pulling AlienVault OTX pulses...")
    start = time.time()
    
    # If we have an API key, use the subscribed pulses endpoint
    if OTX_API_KEY:
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&modified_since=" + \
              (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%dT00:00:00")
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            
            total = 0
            for pulse in data.get("results", []):
                tags = json.dumps(pulse.get("tags", [])[:10])
                malware = pulse.get("malware_families", [])
                if malware and isinstance(malware[0], dict):
                    malware_name = malware[0].get("display_name", "")
                elif malware and isinstance(malware[0], str):
                    malware_name = malware[0]
                else:
                    malware_name = ""
                
                for indicator in pulse.get("indicators", []):
                    ioc_type_map = {
                        "IPv4": "ip", "IPv6": "ip", "domain": "domain", "hostname": "domain",
                        "URL": "url", "email": "email",
                        "FileHash-MD5": "hash_md5", "FileHash-SHA1": "hash_sha1", "FileHash-SHA256": "hash_sha256"
                    }
                    ioc_type = ioc_type_map.get(indicator.get("type", ""), "")
                    if not ioc_type:
                        continue
                    try:
                        conn.execute("""
                            INSERT OR IGNORE INTO iocs (indicator, type, source, threat_type, malware_family, confidence, tags, first_seen)
                            VALUES (?, ?, 'otx', ?, ?, ?, ?, ?)
                        """, (
                            indicator.get("indicator", ""),
                            ioc_type,
                            indicator.get("description", "malware"),
                            malware_name,
                            80, tags,
                            indicator.get("created", "")
                        ))
                        total += 1
                    except:
                        pass
            
            conn.commit()
            duration = time.time() - start
            log.info("OTX (API key): Pulled %d IOCs in %.1fs", total, duration)
            update_feed_status(conn, "otx", total, "success", "", duration)
            return total
            
        except Exception as e:
            log.warning("OTX API key failed (%s), falling back to public feeds", e)
    
    # No API key or API key failed - use truly public endpoints
    return pull_otx_public(conn)


def pull_otx_public(conn):
    """Pull IOCs from OTX public feeds that DON'T require an API key"""
    log.info("OTX: Using public feeds (no API key required)")
    start = time.time()
    total = 0
    
    # === SOURCE 1: OTX Public Pulse Activity Feed ===
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00")
        url = f"https://otx.alienvault.com/api/v1/pulses/activity?limit=20&modified_since={since}"
        log.info("OTX [1/4]: Trying activity feed...")
        resp = requests.get(url, timeout=30, headers={"User-Agent": "CyberSentinel/3.0"})
        log.info("OTX [1/4]: status=%d length=%d", resp.status_code, len(resp.text))
        if resp.status_code == 200:
            data = resp.json()
            pulses = data.get("results", [])
            log.info("OTX [1/4]: Got %d pulses", len(pulses))
            for pulse in pulses:
                tags = json.dumps(pulse.get("tags", [])[:10])
                malware_fams = pulse.get("malware_families", [])
                if malware_fams and isinstance(malware_fams[0], dict):
                    malware_name = malware_fams[0].get("display_name", "")
                elif malware_fams and isinstance(malware_fams[0], str):
                    malware_name = malware_fams[0]
                else:
                    malware_name = ""
                for indicator in pulse.get("indicators", []):
                    ioc_type_map = {
                        "IPv4": "ip", "IPv6": "ip", "domain": "domain", "hostname": "domain",
                        "URL": "url", "email": "email",
                        "FileHash-MD5": "hash_md5", "FileHash-SHA1": "hash_sha1", "FileHash-SHA256": "hash_sha256"
                    }
                    ioc_type = ioc_type_map.get(indicator.get("type", ""), "")
                    if not ioc_type:
                        continue
                    try:
                        conn.execute("""
                            INSERT OR IGNORE INTO iocs (indicator, type, source, threat_type, malware_family, confidence, tags, first_seen)
                            VALUES (?, ?, 'otx', ?, ?, ?, ?, ?)
                        """, (
                            indicator.get("indicator", ""), ioc_type,
                            indicator.get("description", "") or "suspicious",
                            malware_name, 75, tags, indicator.get("created", "")
                        ))
                        total += 1
                    except:
                        pass
            log.info("OTX [1/4]: %d IOCs from activity feed", total)
        else:
            log.warning("OTX [1/4]: status %d: %s", resp.status_code, resp.text[:300])
    except Exception as e:
        log.warning("OTX [1/4]: error: %s", e)
    
    # === SOURCE 2: Search for recent public pulses ===
    if total == 0:
        try:
            url = "https://otx.alienvault.com/api/v1/search/pulses?q=malware&sort=modified&limit=10"
            log.info("OTX [2/4]: Trying search endpoint...")
            resp = requests.get(url, timeout=30, headers={"User-Agent": "CyberSentinel/3.0"})
            log.info("OTX [2/4]: status=%d length=%d", resp.status_code, len(resp.text))
            if resp.status_code == 200:
                data = resp.json()
                pulses = data.get("results", [])
                log.info("OTX [2/4]: Got %d pulses", len(pulses))
                for pulse in pulses:
                    pulse_id = pulse.get("id", "")
                    if not pulse_id:
                        continue
                    try:
                        iurl = f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}/indicators?limit=200"
                        iresp = requests.get(iurl, timeout=15, headers={"User-Agent": "CyberSentinel/3.0"})
                        if iresp.status_code == 200:
                            idata = iresp.json()
                            for indicator in idata.get("results", []):
                                ioc_type_map = {
                                    "IPv4": "ip", "IPv6": "ip", "domain": "domain", "hostname": "domain",
                                    "URL": "url", "FileHash-MD5": "hash_md5", "FileHash-SHA1": "hash_sha1",
                                    "FileHash-SHA256": "hash_sha256"
                                }
                                ioc_type = ioc_type_map.get(indicator.get("type", ""), "")
                                if not ioc_type:
                                    continue
                                try:
                                    conn.execute("""
                                        INSERT OR IGNORE INTO iocs (indicator, type, source, threat_type, confidence, first_seen)
                                        VALUES (?, ?, 'otx', 'malware', 70, ?)
                                    """, (indicator.get("indicator", ""), ioc_type, indicator.get("created", "")))
                                    total += 1
                                except:
                                    pass
                        time.sleep(0.3)
                    except Exception as ie:
                        log.warning("OTX [2/4]: pulse %s error: %s", pulse_id, ie)
                log.info("OTX [2/4]: %d IOCs from search", total)
            else:
                log.warning("OTX [2/4]: status %d: %s", resp.status_code, resp.text[:300])
        except Exception as e:
            log.warning("OTX [2/4]: error: %s", e)
    
    # === SOURCE 3: Direct IOC export feeds ===
    if total == 0:
        for feed_type, ioc_type in [("IPv4", "ip"), ("domain", "domain"), ("URL", "url")]:
            try:
                url = f"https://otx.alienvault.com/api/v1/indicators/export?type={feed_type}&limit=200"
                log.info("OTX [3/4]: Trying export %s...", feed_type)
                resp = requests.get(url, timeout=15, headers={"User-Agent": "CyberSentinel/3.0"})
                log.info("OTX [3/4]: export %s status=%d length=%d", feed_type, resp.status_code, len(resp.text))
                if resp.status_code == 200 and resp.text.strip():
                    count = 0
                    for line in resp.text.strip().split("\n")[:200]:
                        indicator = line.strip()
                        if indicator and not indicator.startswith("#") and not indicator.startswith("<") and len(indicator) < 500:
                            try:
                                conn.execute("""
                                    INSERT OR IGNORE INTO iocs (indicator, type, source, threat_type, confidence)
                                    VALUES (?, ?, 'otx_public', 'suspicious', 60)
                                """, (indicator, ioc_type))
                                count += 1
                            except:
                                pass
                    total += count
                    log.info("OTX [3/4]: export %s: %d IOCs", feed_type, count)
            except Exception as e:
                log.warning("OTX [3/4]: export %s error: %s", feed_type, e)
    
    # === SOURCE 4: Enrich existing IPs via OTX reputation ===
    try:
        known_ips = conn.execute(
            "SELECT DISTINCT indicator FROM iocs WHERE type='ip' AND source NOT LIKE 'otx%%' LIMIT 15"
        ).fetchall()
        enriched = 0
        log.info("OTX [4/4]: Enriching %d IPs via reputation...", len(known_ips))
        for row in known_ips:
            ip = row[0]
            try:
                url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
                resp = requests.get(url, timeout=10, headers={"User-Agent": "CyberSentinel/3.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    pulse_count = data.get("pulse_info", {}).get("count", 0)
                    if pulse_count > 0:
                        conn.execute("""
                            INSERT OR REPLACE INTO iocs (indicator, type, source, threat_type, confidence, tags)
                            VALUES (?, 'ip', 'otx_enriched', 'confirmed_malicious', ?, ?)
                        """, (ip, min(50 + pulse_count * 5, 99), json.dumps({"otx_pulses": pulse_count})))
                        enriched += 1
                time.sleep(0.5)
            except:
                pass
        if enriched:
            log.info("OTX [4/4]: Enriched %d IPs", enriched)
            total += enriched
    except Exception as e:
        log.warning("OTX [4/4]: enrichment error: %s", e)
    
    conn.commit()
    duration = time.time() - start
    status = "success" if total > 0 else "error"
    error_msg = "" if total > 0 else "All 4 OTX sources returned 0. Check puller.log for details. Get free key at https://otx.alienvault.com"
    log.info("OTX TOTAL: %d IOCs in %.1fs (status=%s)", total, duration, status)
    update_feed_status(conn, "otx", total, status, error_msg, duration)
    return total


# ═══════════════════════════════════════════════════════
# FEED 5: Abuse.ch - Malware IOCs
# ═══════════════════════════════════════════════════════
def pull_abusech(conn):
    log.info("Pulling Abuse.ch feeds...")
    start = time.time()
    total = 0
    
    feeds = [
        ("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json", "feodo_c2", "c2"),
        ("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/200/", "urlhaus", "malware_url"),
        ("https://bazaar.abuse.ch/export/txt/sha256/recent/", "malware_bazaar", "malware"),
    ]
    
    # Feodo Tracker - C2 IPs (JSON)
    try:
        resp = requests.get(feeds[0][0], timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                ip = entry.get("ip_address", "")
                port = entry.get("port", 0)
                malware = entry.get("malware", "")
                status = entry.get("status", "")
                first_seen = entry.get("first_seen", "")
                last_online = entry.get("last_online", "")
                country = entry.get("country", "")
                as_num = entry.get("as_number", "")
                
                try:
                    conn.execute("""
                        INSERT OR REPLACE INTO c2_servers (ip, port, status, malware, first_seen, last_online, country, as_number, source)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'feodo')
                    """, (ip, port, status, malware, first_seen, last_online, country, str(as_num)))
                    
                    conn.execute("""
                        INSERT OR IGNORE INTO iocs (indicator, type, source, threat_type, malware_family, confidence, first_seen, last_seen)
                        VALUES (?, 'ip', 'feodo', 'c2', ?, 90, ?, ?)
                    """, (ip, malware, first_seen, last_online))
                    total += 1
                except:
                    pass
    except Exception as e:
        log.error("Feodo error: %s", e)
    
    # URLhaus - Malicious URLs (POST API)
    try:
        resp = requests.post("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/200/", timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get("urls", []):
                url_val = entry.get("url", "")
                threat = entry.get("threat", "")
                tags = json.dumps(entry.get("tags", []))
                
                try:
                    conn.execute("""
                        INSERT OR IGNORE INTO iocs (indicator, type, source, threat_type, malware_family, confidence, tags, first_seen)
                        VALUES (?, 'url', 'urlhaus', 'malware_distribution', ?, 85, ?, ?)
                    """, (url_val, threat, tags, entry.get("date_added", "")))
                    total += 1
                except:
                    pass
    except Exception as e:
        log.error("URLhaus error: %s", e)
    
    # Malware Bazaar - Recent SHA256 hashes
    try:
        resp = requests.get("https://bazaar.abuse.ch/export/txt/sha256/recent/", timeout=15)
        if resp.status_code == 200:
            lines = resp.text.strip().split("\n")
            for line in lines[:200]:
                h = line.strip()
                if h and not h.startswith("#") and len(h) == 64:
                    try:
                        conn.execute("""
                            INSERT OR IGNORE INTO iocs (indicator, type, source, threat_type, confidence)
                            VALUES (?, 'hash_sha256', 'malware_bazaar', 'malware', 85)
                        """, (h,))
                        total += 1
                    except:
                        pass
    except Exception as e:
        log.error("Malware Bazaar error: %s", e)
    
    conn.commit()
    duration = time.time() - start
    log.info("Abuse.ch: Pulled %d IOCs in %.1fs", total, duration)
    update_feed_status(conn, "abusech", total, "success", "", duration)
    return total


# ═══════════════════════════════════════════════════════
# FEED 6: Cleanup old data (90 days)
# ═══════════════════════════════════════════════════════
def cleanup_old_data(conn, days=90):
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    
    deleted_iocs = conn.execute("DELETE FROM iocs WHERE fetched_at < ?", (cutoff,)).rowcount
    deleted_c2 = conn.execute("DELETE FROM c2_servers WHERE fetched_at < ?", (cutoff,)).rowcount
    conn.commit()
    
    log.info("Cleanup: Removed %d old IOCs, %d old C2 entries", deleted_iocs, deleted_c2)


# ═══════════════════════════════════════════════════════
# GENERATE JSON SUMMARY (for GUI consumption)
# ═══════════════════════════════════════════════════════
def generate_summary(conn):
    summary = {
        "generated_at": datetime.utcnow().isoformat(),
        "stats": {},
        "top_cves": [],
        "exploited_vulns": [],
        "recent_iocs": {"ips": [], "domains": [], "hashes": [], "urls": []},
        "c2_servers": [],
        "feed_status": []
    }
    
    # Stats
    summary["stats"]["total_cves"] = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    summary["stats"]["critical_cves"] = conn.execute("SELECT COUNT(*) FROM cves WHERE cvss_score >= 9.0").fetchone()[0]
    summary["stats"]["exploited_cves"] = conn.execute("SELECT COUNT(*) FROM exploited_vulns").fetchone()[0]
    summary["stats"]["total_iocs"] = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    summary["stats"]["active_c2"] = conn.execute("SELECT COUNT(*) FROM c2_servers WHERE status='online'").fetchone()[0]
    
    # Top CVEs by CVSS
    for row in conn.execute("""
        SELECT cve_id, description, cvss_score, cvss_severity, epss_score, vendor, product, published, actively_exploited
        FROM cves ORDER BY cvss_score DESC LIMIT 20
    """).fetchall():
        summary["top_cves"].append({
            "cve_id": row[0], "description": row[1][:200], "cvss_score": row[2],
            "cvss_severity": row[3], "epss_score": row[4], "vendor": row[5],
            "product": row[6], "published": row[7], "actively_exploited": bool(row[8])
        })
    
    # Actively exploited (most recent)
    for row in conn.execute("""
        SELECT cve_id, vendor, product, name, date_added, due_date, known_ransomware
        FROM exploited_vulns ORDER BY date_added DESC LIMIT 15
    """).fetchall():
        summary["exploited_vulns"].append({
            "cve_id": row[0], "vendor": row[1], "product": row[2], "name": row[3],
            "date_added": row[4], "due_date": row[5], "ransomware": row[6]
        })
    
    # Recent IOCs by type
    for ioc_type, key in [("ip", "ips"), ("domain", "domains"), ("hash_sha256", "hashes"), ("url", "urls")]:
        for row in conn.execute("""
            SELECT indicator, source, threat_type, malware_family, confidence, first_seen
            FROM iocs WHERE type=? ORDER BY fetched_at DESC LIMIT 25
        """, (ioc_type,)).fetchall():
            summary["recent_iocs"][key].append({
                "indicator": row[0], "source": row[1], "threat_type": row[2],
                "malware": row[3], "confidence": row[4], "first_seen": row[5]
            })
    
    # C2 servers
    for row in conn.execute("""
        SELECT ip, port, malware, status, country, last_online
        FROM c2_servers ORDER BY last_online DESC LIMIT 15
    """).fetchall():
        summary["c2_servers"].append({
            "ip": row[0], "port": row[1], "malware": row[2],
            "status": row[3], "country": row[4], "last_online": row[5]
        })
    
    # Feed status
    for row in conn.execute("SELECT feed_name, last_pull, records_pulled, status FROM feed_status").fetchall():
        summary["feed_status"].append({
            "feed": row[0], "last_pull": row[1], "records": row[2], "status": row[3]
        })
    
    # Write summary JSON
    summary_path = DATA_DIR / "threat_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    
    log.info("Summary generated: %s", summary_path)
    return summary


# ═══════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════
def main():
    log.info("=" * 60)
    log.info("CyberSentinel Threat Intel Puller - Starting")
    log.info("=" * 60)
    
    conn = init_db()
    
    total = 0
    total += pull_nvd_cves(conn, days_back=7)
    total += pull_cisa_kev(conn)
    total += pull_epss(conn)
    total += pull_otx_pulses(conn)
    total += pull_abusech(conn)
    
    cleanup_old_data(conn)
    summary = generate_summary(conn)
    
    log.info("=" * 60)
    log.info("COMPLETE: %d total records pulled", total)
    log.info("  CVEs:      %d", summary["stats"]["total_cves"])
    log.info("  Critical:  %d", summary["stats"]["critical_cves"])
    log.info("  Exploited: %d", summary["stats"]["exploited_cves"])
    log.info("  IOCs:      %d", summary["stats"]["total_iocs"])
    log.info("  C2:        %d", summary["stats"]["active_c2"])
    log.info("=" * 60)
    
    conn.close()


if __name__ == "__main__":
    main()
