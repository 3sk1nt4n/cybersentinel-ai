"""
CyberSentinel v3.0 - Scan Router (Phase 3)
API endpoints for executing real security scans in the sandbox.
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from app.services.scanner import (
    check_sandbox_health, nmap_scan, dns_recon, ssl_check,
    whois_lookup, nikto_scan, nuclei_scan, subfinder_enum,
    traceroute_target, ping_target, curl_headers, SCAN_REGISTRY,
)

router = APIRouter(prefix="/scan", tags=["scan"])


class ScanRequest(BaseModel):
    target: str
    scan_type: str  # nmap, dns, ssl, whois, nikto, nuclei, subfinder, traceroute, ping, headers
    options: Optional[str] = ""


@router.get("/health")
async def sandbox_health():
    """Check if sandbox container is running."""
    return await check_sandbox_health()


@router.get("/types")
async def list_scan_types():
    """List all available scan types."""
    return {
        "scans": {
            name: {"description": info["desc"], "params": info["params"]}
            for name, info in SCAN_REGISTRY.items()
        }
    }


@router.post("/run")
async def run_scan(req: ScanRequest):
    """Execute a security scan in the sandbox."""
    if req.scan_type not in SCAN_REGISTRY:
        return {"success": False, "error": f"Unknown scan type: {req.scan_type}. Available: {list(SCAN_REGISTRY.keys())}"}

    scan = SCAN_REGISTRY[req.scan_type]
    fn = scan["fn"]

    # Route to the correct function
    if req.scan_type == "nmap":
        result = await fn(req.target, req.options or "-sV --top-ports 100")
    elif req.scan_type == "nuclei":
        result = await fn(req.target, req.options or "")
    elif req.scan_type == "ping":
        result = await fn(req.target)
    else:
        result = await fn(req.target)

    return {"scan_type": req.scan_type, "target": req.target, **result}
