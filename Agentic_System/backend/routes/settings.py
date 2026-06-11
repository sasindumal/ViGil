"""
ViGil Routes — Settings & LLM Configuration Endpoints
======================================================

Allows retrieving and updating configurations for LLM providers and server
directories, testing API connections, and querying active providers.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException

from backend.config import get_config, update_config
from backend.agents.llm_config import test_connection

logger = logging.getLogger("vigil.routes.settings")

router = APIRouter(prefix="/api/settings", tags=["Settings"])


def _mask_key(key: str) -> str:
    """Mask a key keeping only the last 4 characters visible."""
    if not key:
        return ""
    if len(key) <= 8:
        return "****"
    return f"{"*" * (len(key) - 4)}{key[-4:]}"


@router.get("")
async def get_settings():
    """Retrieve current system settings with masked API keys."""
    cfg = get_config()
    data = cfg.model_dump()

    # Mask sensitive keys
    for p in ["openai", "gemini", "nvidia_nim", "openrouter"]:
        if p in data.get("llm", {}):
            key_val = data["llm"][p].get("api_key", "")
            data["llm"][p]["api_key"] = _mask_key(key_val)

    return data


@router.put("")
async def put_settings(payload: dict[str, Any]):
    """Update system configurations."""
    try:
        # If payload contains masked keys, do not overwrite the actual stored keys
        # We check and restore the actual key from config if the payload is masked
        cfg = get_config()
        current_data = cfg.model_dump()
        
        for p in ["openai", "gemini", "nvidia_nim", "openrouter"]:
            if "llm" in payload and p in payload["llm"]:
                new_key = payload["llm"][p].get("api_key", "")
                if new_key.startswith("*****") or new_key == "":
                    # Restore current key
                    payload["llm"][p]["api_key"] = current_data["llm"][p]["api_key"]

        updated = update_config(payload)
        return updated.model_dump()
    except Exception as exc:
        logger.exception("Failed to update system settings")
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/test-connection")
async def test_llm_connection(payload: dict[str, Any]):
    """Test connection to the specified LLM provider."""
    provider = payload.get("provider")
    if not provider:
        raise HTTPException(status_code=400, detail="Provider field is required.")

    # Temporarily overlay settings for testing
    cfg = get_config()
    current_data = cfg.model_dump()
    test_cfg = {
        "active_provider": provider,
    }

    # Overlay keys if provided in the test payload
    for p in ["openai", "gemini", "nvidia_nim", "openrouter"]:
        if p == provider and p in payload:
            key_val = payload[p].get("api_key", "")
            # If the user passed masked key, use the stored key
            if key_val.startswith("*****") or key_val == "":
                key_val = current_data["llm"][p]["api_key"]
            test_cfg[p] = {**current_data["llm"][p], "api_key": key_val}
            
            # Map other fields
            if "model" in payload[p]:
                test_cfg[p]["model"] = payload[p]["model"]
            if "base_url" in payload[p]:
                test_cfg[p]["base_url"] = payload[p]["base_url"]

    # Call test connection in llm_config
    res = await test_connection(test_cfg)
    return res


@router.get("/providers")
async def get_providers():
    """List supported LLM providers and their required configuration fields."""
    return {
        "providers": [
            {
                "id": "openai",
                "name": "OpenAI",
                "fields": ["api_key", "model", "base_url"],
                "default_model": "gpt-4o",
            },
            {
                "id": "gemini",
                "name": "Google Gemini",
                "fields": ["api_key", "model"],
                "default_model": "gemini-2.5-flash",
            },
            {
                "id": "ollama",
                "name": "Ollama (Local)",
                "fields": ["base_url", "model"],
                "default_model": "llama3",
            },
            {
                "id": "nvidia_nim",
                "name": "NVIDIA NIM",
                "fields": ["api_key", "base_url", "model"],
                "default_model": "meta/llama-3.1-70b-instruct",
            },
            {
                "id": "openrouter",
                "name": "OpenRouter",
                "fields": ["api_key", "model"],
                "default_model": "anthropic/claude-sonnet-4",
            },
            {
                "id": "lmstudio",
                "name": "LM Studio (Local)",
                "fields": ["base_url", "model"],
                "default_model": "local-model",
            }
        ]
    }
