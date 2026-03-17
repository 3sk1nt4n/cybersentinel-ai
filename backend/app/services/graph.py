"""
CyberSentinel v3.0 - Neo4j Graph Intelligence Service
Maps attack surfaces, asset relationships, and threat paths as a graph.
"""
import json
from typing import Optional
from app.core.config import settings

_driver = None


def get_driver():
    """Lazy-init Neo4j driver."""
    global _driver
    if _driver is None:
        try:
            from neo4j import GraphDatabase
            _driver = GraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password),
            )
            # Verify connectivity
            _driver.verify_connectivity()
        except Exception:
            _driver = None
    return _driver


async def check_neo4j_health() -> dict:
    """Check Neo4j connection status."""
    driver = get_driver()
    if not driver:
        return {"status": "disconnected"}
    try:
        with driver.session() as session:
            result = session.run("RETURN 1 AS ok")
            result.single()
        return {"status": "connected"}
    except Exception as e:
        return {"status": "error", "message": str(e)[:100]}


async def init_schema():
    """Create indexes and constraints for the attack surface graph."""
    driver = get_driver()
    if not driver:
        return False
    try:
        with driver.session() as session:
            # Asset constraints
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (t:Technique) REQUIRE t.technique_id IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (i:IOC) REQUIRE i.value IS UNIQUE")

            # Indexes for fast lookups
            session.run("CREATE INDEX IF NOT EXISTS FOR (a:Asset) ON (a.type)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (a:Asset) ON (a.risk_score)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (v:Vulnerability) ON (v.cvss_score)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (i:IOC) ON (i.type)")
        return True
    except Exception:
        return False


async def add_asset(asset_id: str, asset_type: str, name: str, properties: dict = None):
    """Add an asset node (host, service, domain, cloud resource, etc.)."""
    driver = get_driver()
    if not driver:
        return None
    props = properties or {}
    props.update({"id": asset_id, "type": asset_type, "name": name})
    try:
        with driver.session() as session:
            result = session.run(
                "MERGE (a:Asset {id: $id}) SET a += $props RETURN a",
                id=asset_id, props=props,
            )
            record = result.single()
            return dict(record["a"]) if record else None
    except Exception:
        return None


async def add_vulnerability(cve_id: str, cvss_score: float, epss_score: float = 0,
                            description: str = "", exploited: bool = False):
    """Add a CVE vulnerability node."""
    driver = get_driver()
    if not driver:
        return None
    try:
        with driver.session() as session:
            result = session.run(
                """MERGE (v:Vulnerability {cve_id: $cve_id})
                   SET v.cvss_score = $cvss, v.epss_score = $epss,
                       v.description = $desc, v.actively_exploited = $exploited
                   RETURN v""",
                cve_id=cve_id, cvss=cvss_score, epss=epss_score,
                desc=description, exploited=exploited,
            )
            record = result.single()
            return dict(record["v"]) if record else None
    except Exception:
        return None


async def link_asset_to_vuln(asset_id: str, cve_id: str):
    """Create AFFECTED_BY relationship between asset and vulnerability."""
    driver = get_driver()
    if not driver:
        return False
    try:
        with driver.session() as session:
            session.run(
                """MATCH (a:Asset {id: $asset_id}), (v:Vulnerability {cve_id: $cve_id})
                   MERGE (a)-[:AFFECTED_BY]->(v)""",
                asset_id=asset_id, cve_id=cve_id,
            )
        return True
    except Exception:
        return False


async def add_technique(technique_id: str, name: str, tactic: str = ""):
    """Add a MITRE ATT&CK technique node."""
    driver = get_driver()
    if not driver:
        return None
    try:
        with driver.session() as session:
            result = session.run(
                """MERGE (t:Technique {technique_id: $tid})
                   SET t.name = $name, t.tactic = $tactic
                   RETURN t""",
                tid=technique_id, name=name, tactic=tactic,
            )
            record = result.single()
            return dict(record["t"]) if record else None
    except Exception:
        return None


async def add_ioc(value: str, ioc_type: str, source: str = "", malicious: bool = True):
    """Add an IOC (Indicator of Compromise) node."""
    driver = get_driver()
    if not driver:
        return None
    try:
        with driver.session() as session:
            result = session.run(
                """MERGE (i:IOC {value: $value})
                   SET i.type = $type, i.source = $source, i.malicious = $malicious
                   RETURN i""",
                value=value, type=ioc_type, source=source, malicious=malicious,
            )
            record = result.single()
            return dict(record["i"]) if record else None
    except Exception:
        return None


async def get_attack_surface_summary() -> dict:
    """Get a summary of the entire attack surface graph."""
    driver = get_driver()
    if not driver:
        return {"status": "disconnected"}
    try:
        with driver.session() as session:
            counts = {}
            # Use parameterized count queries - avoid f-string label injection
            for label in ["Asset", "Vulnerability", "Technique", "IOC"]:
                # Labels can't be parameterized in Cypher, but these are hardcoded constants (safe)
                if label not in ("Asset", "Vulnerability", "Technique", "IOC"):
                    continue  # Whitelist guard
                result = session.run(f"MATCH (n:{label}) RETURN count(n) AS c")
                record = result.single()
                counts[label.lower() + "s"] = record["c"] if record else 0

            # High-risk assets
            result = session.run(
                """MATCH (a:Asset)-[:AFFECTED_BY]->(v:Vulnerability)
                   WHERE v.cvss_score >= 9.0
                   RETURN a.name AS asset, count(v) AS critical_vulns
                   ORDER BY critical_vulns DESC LIMIT 10"""
            )
            high_risk = [{"asset": r["asset"], "critical_vulns": r["critical_vulns"]} for r in result]

            # Relationship count
            result = session.run("MATCH ()-[r]->() RETURN count(r) AS c")
            record = result.single()
            counts["relationships"] = record["c"] if record else 0

        return {"status": "connected", "counts": counts, "high_risk_assets": high_risk}
    except Exception as e:
        return {"status": "error", "message": str(e)[:200]}


async def query_graph(cypher: str, params: dict = None) -> list[dict]:
    """Execute a custom Cypher query (read-only, sanitized against injection)."""
    driver = get_driver()
    if not driver:
        return []

    # ── Cypher injection defense ──
    # Block destructive/dangerous operations
    upper = cypher.upper().strip()
    BLOCKED_KEYWORDS = [
        "DELETE", "DETACH DELETE", "REMOVE", "DROP", "CREATE CONSTRAINT",
        "CREATE INDEX", "SET ", "MERGE", "CREATE ",
        "CALL apoc.export", "CALL apoc.import", "CALL apoc.cypher.run",
        "CALL apoc.cypher.doIt", "CALL apoc.trigger",
        "LOAD CSV FROM 'http", "LOAD CSV FROM 'file",
        "LOAD CSV FROM \"http", "LOAD CSV FROM \"file",
        "dbms.security", "GRANT ", "DENY ", "REVOKE ",
    ]
    for kw in BLOCKED_KEYWORDS:
        if kw.upper() in upper:
            return [{"error": f"Blocked: '{kw.strip()}' operations not allowed in custom queries"}]

    # Block SSRF patterns
    if "169.254.169.254" in cypher or "metadata" in cypher.lower():
        return [{"error": "Blocked: potential SSRF attempt"}]

    try:
        with driver.session() as session:
            # Use read transaction to enforce read-only at driver level
            result = session.execute_read(
                lambda tx: list(tx.run(cypher, **(params or {})))
            )
            return [dict(record) for record in result]
    except Exception as e:
        return [{"error": str(e)[:200]}]
