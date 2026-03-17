"""
CyberSentinel v3.0 - Chat History Service (Phase 3)
Persists chat conversations to SQLite for history sidebar.
"""
import sqlite3
import json
import time
import uuid
import os

DB_PATH = os.environ.get("CHAT_DB_PATH", "/app/data/chat_history.db")


def _get_db():
    """Get SQLite connection with WAL mode for performance."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS conversations (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            provider TEXT DEFAULT 'ollama',
            message_count INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp REAL NOT NULL,
            badges TEXT DEFAULT '[]',
            FOREIGN KEY (conversation_id) REFERENCES conversations(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_conv_updated ON conversations(updated_at DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_msg_conv ON messages(conversation_id)")
    conn.commit()
    return conn


def create_conversation(title: str = "New Chat", provider: str = "ollama") -> dict:
    """Create a new conversation and return its metadata."""
    conn = _get_db()
    conv_id = str(uuid.uuid4())[:8]
    now = time.time()
    conn.execute(
        "INSERT INTO conversations (id, title, created_at, updated_at, provider) VALUES (?, ?, ?, ?, ?)",
        (conv_id, title, now, now, provider),
    )
    conn.commit()
    conn.close()
    return {"id": conv_id, "title": title, "created_at": now, "updated_at": now, "provider": provider, "message_count": 0}


def add_message(conversation_id: str, role: str, content: str, badges: list = None) -> dict:
    """Add a message to a conversation."""
    conn = _get_db()
    now = time.time()
    conn.execute(
        "INSERT INTO messages (conversation_id, role, content, timestamp, badges) VALUES (?, ?, ?, ?, ?)",
        (conversation_id, role, content, now, json.dumps(badges or [])),
    )
    # Update conversation
    title_update = ""
    if role == "user":
        # Use first user message as title
        row = conn.execute("SELECT COUNT(*) as c FROM messages WHERE conversation_id = ? AND role = 'user'", (conversation_id,)).fetchone()
        if row["c"] <= 1:
            title = content[:60] + ("..." if len(content) > 60 else "")
            conn.execute("UPDATE conversations SET title = ? WHERE id = ?", (title, conversation_id))

    conn.execute(
        "UPDATE conversations SET updated_at = ?, message_count = message_count + 1 WHERE id = ?",
        (now, conversation_id),
    )
    conn.commit()
    conn.close()
    return {"conversation_id": conversation_id, "role": role, "timestamp": now}


def get_conversations(limit: int = 30, offset: int = 0) -> list[dict]:
    """Get recent conversations."""
    conn = _get_db()
    rows = conn.execute(
        "SELECT * FROM conversations ORDER BY updated_at DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_conversation(conversation_id: str) -> dict | None:
    """Get a conversation with all its messages."""
    conn = _get_db()
    conv = conn.execute("SELECT * FROM conversations WHERE id = ?", (conversation_id,)).fetchone()
    if not conv:
        conn.close()
        return None
    messages = conn.execute(
        "SELECT * FROM messages WHERE conversation_id = ? ORDER BY timestamp",
        (conversation_id,),
    ).fetchall()
    conn.close()
    return {
        **dict(conv),
        "messages": [
            {**dict(m), "badges": json.loads(m["badges"])} for m in messages
        ],
    }


def delete_conversation(conversation_id: str) -> bool:
    """Delete a conversation and all its messages."""
    conn = _get_db()
    conn.execute("DELETE FROM messages WHERE conversation_id = ?", (conversation_id,))
    conn.execute("DELETE FROM conversations WHERE id = ?", (conversation_id,))
    conn.commit()
    conn.close()
    return True


def clear_all_history() -> bool:
    """Delete all conversations and messages."""
    conn = _get_db()
    conn.execute("DELETE FROM messages")
    conn.execute("DELETE FROM conversations")
    conn.commit()
    conn.close()
    return True
