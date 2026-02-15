"""
CyberSentinel v2.0 - Configuration
Reads all settings from .env file automatically.
"""
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # App
    app_name: str = "CyberSentinel AI"
    app_version: str = "2.0.0"
    app_env: str = "development"
    secret_key: str = ""

    # AI Provider: ollama | claude | openai | openrouter
    ai_provider: str = "ollama"

    # Ollama
    ollama_base_url: str = "http://ollama:11434"
    ollama_model: str = "qwen2.5:7b"

    # Anthropic
    anthropic_api_key: Optional[str] = None
    claude_model: str = "claude-sonnet-4-20250514"

    # OpenAI
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o"

    # OpenRouter
    openrouter_api_key: Optional[str] = None
    openrouter_model: str = "anthropic/claude-sonnet-4-20250514"

    # Neo4j
    neo4j_uri: str = "bolt://neo4j:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""

    # API security
    # Defaults to False in development for backwards compatibility.
    api_auth_enabled: bool = False
    api_key: Optional[str] = None
    allow_plaintext_secret_persistence: bool = False

    # ChromaDB
    # Threat Intel Keys
    shodan_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    otx_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None

    # Search
    tavily_api_key: Optional[str] = None

    # Elasticsearch / ELK Stack
    elasticsearch_url: str = "http://elasticsearch:9200"
    elasticsearch_api_key: Optional[str] = None
    elasticsearch_user: Optional[str] = None
    elasticsearch_password: Optional[str] = None

    # Splunk
    splunk_url: str = "https://splunk:8089"
    splunk_token: Optional[str] = None
    splunk_user: Optional[str] = None
    splunk_password: Optional[str] = None

    # Wazuh
    wazuh_url: str = "https://wazuh:55000"
    wazuh_user: Optional[str] = None
    wazuh_password: Optional[str] = None

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()


def is_production() -> bool:
    return settings.app_env.lower() in {"prod", "production"}


def is_api_auth_active() -> bool:
    """Whether API auth should be enforced at runtime."""
    return settings.api_auth_enabled and bool(settings.api_key)


def validate_security_settings() -> list[str]:
    """Return startup security configuration errors."""
    errors: list[str] = []

    if is_production() and (not settings.secret_key or settings.secret_key == "change-me"):
        errors.append("SECRET_KEY must be configured and not use defaults in production")

    if is_production() and settings.api_auth_enabled and not settings.api_key:
        errors.append("API_AUTH_ENABLED=true requires API_KEY to be set in production")

    return errors
