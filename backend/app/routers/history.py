"""
CyberSentinel v3.0 - History Router (Phase 3)
Chat history persistence API.
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from app.services.history import (
    create_conversation, add_message, get_conversations,
    get_conversation, delete_conversation, clear_all_history,
)

router = APIRouter(prefix="/history", tags=["history"])


class NewConversation(BaseModel):
    title: str = "New Chat"
    provider: str = "ollama"


class AddMessage(BaseModel):
    conversation_id: str
    role: str
    content: str
    badges: Optional[list] = None


@router.get("/conversations")
async def list_conversations(limit: int = 30, offset: int = 0):
    """List recent conversations."""
    convos = get_conversations(limit, offset)
    return {"conversations": convos, "total": len(convos)}


@router.post("/conversations")
async def new_conversation(req: NewConversation):
    """Create a new conversation."""
    return create_conversation(req.title, req.provider)


@router.get("/conversations/{conversation_id}")
async def load_conversation(conversation_id: str):
    """Load a conversation with all messages."""
    conv = get_conversation(conversation_id)
    if not conv:
        return {"error": "Conversation not found"}
    return conv


@router.post("/messages")
async def save_message(req: AddMessage):
    """Save a message to a conversation."""
    return add_message(req.conversation_id, req.role, req.content, req.badges)


@router.delete("/conversations/{conversation_id}")
async def remove_conversation(conversation_id: str):
    """Delete a conversation."""
    delete_conversation(conversation_id)
    return {"success": True}


@router.delete("/all")
async def clear_history():
    """Clear all chat history."""
    clear_all_history()
    return {"success": True}
