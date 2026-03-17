"""
CyberSentinel v3.0 - Knowledge Base Router (Phase 2)
RAG knowledge base management API.
"""
from fastapi import APIRouter, UploadFile, File
from pydantic import BaseModel
from typing import Optional
from app.services.rag import (
    search_knowledge, multi_collection_search, add_document,
    get_rag_context, get_collection_stats, delete_collection,
    seed_knowledge_base, COLLECTIONS,
)

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


class SearchInput(BaseModel):
    query: str
    collection: str = "security_kb"
    n_results: int = 5


class DocumentInput(BaseModel):
    text: str
    collection: str = "security_kb"
    metadata: Optional[dict] = None


class MultiSearchInput(BaseModel):
    query: str
    n_results: int = 5


@router.get("/stats")
async def kb_stats():
    """Get knowledge base collection statistics."""
    return await get_collection_stats()


@router.get("/collections")
async def list_collections():
    """List all available collections."""
    return {"collections": COLLECTIONS}


@router.post("/search")
async def search(data: SearchInput):
    """Search a specific collection."""
    results = await search_knowledge(data.query, data.collection, data.n_results)
    return {"query": data.query, "collection": data.collection, "results": results}


@router.post("/search/all")
async def search_all(data: MultiSearchInput):
    """Search across all collections."""
    results = await multi_collection_search(data.query, data.n_results)
    return {"query": data.query, "results": results}


@router.post("/context")
async def get_context(data: MultiSearchInput):
    """Get formatted RAG context for AI injection."""
    context = await get_rag_context(data.query)
    return {"query": data.query, "context": context, "has_context": bool(context)}


@router.post("/documents")
async def add_doc(data: DocumentInput):
    """Add a document to the knowledge base."""
    chunks = await add_document(data.text, data.collection, data.metadata)
    return {"success": chunks > 0, "chunks_added": chunks}


@router.post("/upload")
async def upload_file(file: UploadFile = File(...), collection: str = "user_docs"):
    """Upload a text file to the knowledge base."""
    try:
        content = await file.read()
        text = content.decode("utf-8", errors="ignore")
        if not text.strip():
            return {"success": False, "error": "File is empty"}

        # ── RAG Poisoning Defense: Scan for prompt injection patterns ──
        injection_patterns = [
            r"\[SYSTEM\s*(INSTRUCTION|OVERRIDE|PROMPT)\b",
            r"\bIGNORE\s+(ALL\s+)?(PREVIOUS\s+)?INSTRUCTIONS\b",
            r"\bDISREGARD\b.*\b(TASK|RULES|INSTRUCTIONS)\b",
            r"\bYOU\s+ARE\s+NOW\b",
            r"\bDAN\s+MODE\b",
            r"\bOVERRIDE\s+SECURITY\b",
            r"\bDEBUG\s+MODE\b",
            r"\bACT\s+AS\s+(AN?\s+)?UNRESTRICTED\b",
            r"\bFORGET\s+YOUR\s+(RULES|INSTRUCTIONS|PROMPT)\b",
        ]
        import re
        warnings = []
        for pattern in injection_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                warnings.append(f"Suspicious pattern detected: {pattern}")
        if len(warnings) > 2:
            return {"success": False, "error": "File rejected: multiple prompt injection patterns detected", "warnings": warnings}

        metadata = {"source": file.filename, "content_type": file.content_type}
        if warnings:
            metadata["security_warning"] = "Contains patterns resembling prompt injection"
        chunks = await add_document(text, collection, metadata)
        return {"success": chunks > 0, "filename": file.filename, "chunks_added": chunks, "warnings": warnings or None}
    except Exception as e:
        return {"success": False, "error": str(e)[:200]}


@router.post("/seed")
async def seed_kb():
    """Seed the knowledge base with built-in security knowledge."""
    results = await seed_knowledge_base()
    total = sum(results.values())
    return {"success": total > 0, "seeded": results, "total_chunks": total}


@router.delete("/collections/{collection_name}")
async def remove_collection(collection_name: str):
    """Delete an entire collection."""
    if collection_name not in COLLECTIONS:
        return {"success": False, "error": f"Unknown collection: {collection_name}"}
    ok = await delete_collection(collection_name)
    return {"success": ok}
