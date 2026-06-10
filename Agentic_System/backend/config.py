"""
ViGil Agentic System — Central Configuration
"""

import os
from pathlib import Path
from typing import Optional, Literal
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load environment
_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
if _ENV_PATH.exists():
    load_dotenv(_ENV_PATH)
else:
    _EXAMPLE = _ENV_PATH.with_suffix(".env.example")
    if _EXAMPLE.exists():
        load_dotenv(_EXAMPLE)

PROJECT_ROOT = Path(__file__).resolve().parent.parent          # Agentic_System/
VIGIL_ROOT   = PROJECT_ROOT.parent                              # ViGil/


# ═══════════════════════════════════════════════════════════════
# LLM Provider Configuration
# ═══════════════════════════════════════════════════════════════

LLMProviderType = Literal[
    "openai", "gemini", "ollama", "nvidia_nim", "openrouter", "lmstudio"
]


class OpenAIConfig(BaseModel):
    api_key: str = Field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    model: str = Field(default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o"))
    base_url: Optional[str] = None


class GeminiConfig(BaseModel):
    api_key: str = Field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    model: str = Field(default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-2.5-flash"))


class OllamaConfig(BaseModel):
    base_url: str = Field(default_factory=lambda: os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"))
    model: str = Field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3"))


class NvidiaNIMConfig(BaseModel):
    api_key: str = Field(default_factory=lambda: os.getenv("NVIDIA_NIM_API_KEY", ""))
    base_url: str = Field(default_factory=lambda: os.getenv("NVIDIA_NIM_BASE_URL", "https://integrate.api.nvidia.com/v1"))
    model: str = Field(default_factory=lambda: os.getenv("NVIDIA_NIM_MODEL", "meta/llama-3.1-70b-instruct"))


class OpenRouterConfig(BaseModel):
    api_key: str = Field(default_factory=lambda: os.getenv("OPENROUTER_API_KEY", ""))
    model: str = Field(default_factory=lambda: os.getenv("OPENROUTER_MODEL", "anthropic/claude-sonnet-4"))


class LMStudioConfig(BaseModel):
    base_url: str = Field(default_factory=lambda: os.getenv("LMSTUDIO_BASE_URL", "http://localhost:1234/v1"))
    model: str = Field(default_factory=lambda: os.getenv("LMSTUDIO_MODEL", "local-model"))


class LLMSettings(BaseModel):
    """All LLM provider configurations — one is active at a time."""
    active_provider: LLMProviderType = Field(
        default_factory=lambda: os.getenv("LLM_PROVIDER", "openai")
    )
    openai: OpenAIConfig = Field(default_factory=OpenAIConfig)
    gemini: GeminiConfig = Field(default_factory=GeminiConfig)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    nvidia_nim: NvidiaNIMConfig = Field(default_factory=NvidiaNIMConfig)
    openrouter: OpenRouterConfig = Field(default_factory=OpenRouterConfig)
    lmstudio: LMStudioConfig = Field(default_factory=LMStudioConfig)


# ═══════════════════════════════════════════════════════════════
# Analysis & Server Settings
# ═══════════════════════════════════════════════════════════════

class AnalysisSettings(BaseModel):
    mc_dropout_samples: int = Field(
        default_factory=lambda: int(os.getenv("MC_DROPOUT_SAMPLES", "20"))
    )
    max_recursion_depth: int = Field(
        default_factory=lambda: int(os.getenv("MAX_RECURSION_DEPTH", "5"))
    )
    max_extracted_files: int = Field(
        default_factory=lambda: int(os.getenv("MAX_EXTRACTED_FILES", "1000"))
    )
    timeout_seconds: int = Field(
        default_factory=lambda: int(os.getenv("ANALYSIS_TIMEOUT", "600"))
    )


class StoragePaths(BaseModel):
    upload_dir: Path = Field(
        default_factory=lambda: PROJECT_ROOT / os.getenv("UPLOAD_DIR", "uploads")
    )
    reports_dir: Path = Field(
        default_factory=lambda: PROJECT_ROOT / os.getenv("REPORTS_DIR", "reports")
    )
    memory_db: Path = Field(
        default_factory=lambda: PROJECT_ROOT / os.getenv("MEMORY_DB_PATH", "data/vigil_memory.db")
    )
    knowledge_base: Path = Field(
        default_factory=lambda: PROJECT_ROOT / os.getenv("KNOWLEDGE_BASE_PATH", "data/knowledge_base.json")
    )
    model_checkpoint: Path = Field(
        default_factory=lambda: (PROJECT_ROOT / os.getenv(
            "MODEL_CHECKPOINT_PATH",
            str(VIGIL_ROOT / "models" / "01" / "models" / "joint_model.pt")
        )).resolve()
    )
    model_config_path: Path = Field(
        default_factory=lambda: (PROJECT_ROOT / os.getenv(
            "MODEL_CONFIG_PATH",
            str(VIGIL_ROOT / "models" / "01" / "model_config.json")
        )).resolve()
    )

    def ensure_dirs(self):
        for p in [self.upload_dir, self.reports_dir, self.memory_db.parent]:
            p.mkdir(parents=True, exist_ok=True)


class ServerSettings(BaseModel):
    host: str = Field(default_factory=lambda: os.getenv("BACKEND_HOST", "0.0.0.0"))
    port: int = Field(default_factory=lambda: int(os.getenv("BACKEND_PORT", "8000")))
    frontend_url: str = Field(
        default_factory=lambda: os.getenv("FRONTEND_URL", "http://localhost:3000")
    )


# ═══════════════════════════════════════════════════════════════
# Master Config Singleton
# ═══════════════════════════════════════════════════════════════

class VigilConfig(BaseModel):
    """Top-level configuration aggregating all sub-configs."""
    server: ServerSettings = Field(default_factory=ServerSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)
    storage: StoragePaths = Field(default_factory=StoragePaths)

    def init(self):
        self.storage.ensure_dirs()


_config: Optional[VigilConfig] = None


def get_config() -> VigilConfig:
    global _config
    if _config is None:
        _config = VigilConfig()
        _config.init()
    return _config


def update_config(patch: dict) -> VigilConfig:
    """Merge partial updates into the running config."""
    global _config
    cfg = get_config()
    data = cfg.model_dump()
    _deep_merge(data, patch)
    _config = VigilConfig(**data)
    _config.init()
    return _config


def _deep_merge(base: dict, override: dict):
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
