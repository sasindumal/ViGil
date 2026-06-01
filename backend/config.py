"""
ViGiL — Configuration Module
Loads all settings from environment variables / .env file.
"""
from __future__ import annotations

import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

# .env lives at the project root (one level above this backend/ directory)
_ROOT_ENV = Path(__file__).parent.parent / ".env"


class VigilSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ROOT_ENV),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── LLM ──────────────────────────────────────────────────────────────────
    llm_provider: str = Field(default="openai", description="openai | gemini | ollama | lmstudio")
    openai_api_key: str = Field(default="", description="OpenAI API key")
    openai_model: str = Field(default="gpt-4o")
    google_api_key: str = Field(default="", description="Google Gemini API key")
    gemini_model: str = Field(default="gemini-2.0-flash")
    ollama_base_url: str = Field(default="http://localhost:11434")
    ollama_model: str = Field(default="llama3.2")
    # LM Studio — OpenAI-compatible local server
    lmstudio_base_url: str = Field(default="http://localhost:1234/v1")
    lmstudio_model: str = Field(default="local-model")  # matches the model loaded in LM Studio UI

    # ── Threat Intel ─────────────────────────────────────────────────────────
    virustotal_api_key: str = Field(default="")
    malwarebazaar_api_key: str = Field(default="")
    abuseipdb_api_key: str = Field(default="")
    alienvault_otx_api_key: str = Field(default="")

    # ── Vector Store ─────────────────────────────────────────────────────────
    vector_store: str = Field(default="faiss", description="faiss | qdrant")
    qdrant_url: str = Field(default="http://localhost:6333")

    # ── Server ───────────────────────────────────────────────────────────────
    vigil_host: str = Field(default="0.0.0.0")
    vigil_port: int = Field(default=8000)
    vigil_debug: bool = Field(default=True)

    # ── Analysis ─────────────────────────────────────────────────────────────
    max_file_size_mb: int = Field(default=100)
    upload_dir: Path = Field(default=Path("./uploads"))
    reports_dir: Path = Field(default=Path("./reports"))
    demo_mode: bool = Field(default=True)
    capa_timeout: int = Field(default=600, description="CAPA analysis timeout in seconds")

    # ── CrewAI Agentic Reasoning ──────────────────────────────────────────────
    crewai_enabled: bool = Field(default=True, description="Enable CrewAI agentic reasoning phase")
    crewai_verbose: bool = Field(default=False, description="Verbose CrewAI agent output to console")

    def get_llm_provider_info(self) -> dict:
        """Return active LLM configuration summary."""
        return {
            "provider": self.llm_provider,
            "model": {
                "openai": self.openai_model,
                "gemini": self.gemini_model,
                "ollama": self.ollama_model,
                "lmstudio": self.lmstudio_model,
            }.get(self.llm_provider, self.openai_model),
            "has_key": {
                "openai": bool(self.openai_api_key),
                "gemini": bool(self.google_api_key),
                "ollama": True,
                "lmstudio": True,  # no API key needed
            }.get(self.llm_provider, False),
        }

    @property
    def threat_intel_enabled(self) -> bool:
        return bool(
            self.virustotal_api_key
            or self.malwarebazaar_api_key
            or self.abuseipdb_api_key
            or self.alienvault_otx_api_key
        )


settings = VigilSettings()

# Ensure directories exist
settings.upload_dir.mkdir(parents=True, exist_ok=True)
settings.reports_dir.mkdir(parents=True, exist_ok=True)
