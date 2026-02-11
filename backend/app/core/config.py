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
    secret_key: str = "change-me"

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
    neo4j_password: str = "cybersentinel2024"

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
