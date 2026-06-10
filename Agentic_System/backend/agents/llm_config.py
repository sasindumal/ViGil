"""
ViGil — LLM Configuration Factory
==================================

Configures and instantiates LangChain-compatible LLM providers for CrewAI:
- OpenAI
- Google Gemini (using ChatGoogleGenerativeAI)
- Ollama (local)
- NVIDIA NIM
- OpenRouter
- LM Studio (local)
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from langchain_core.language_models.chat_models import BaseChatModel

# Config imports
from backend.config import get_config

logger = logging.getLogger("vigil.llm_config")


def get_llm(provider_config: Optional[dict] = None) -> BaseChatModel:
    """Return a LangChain-compatible chat model based on the active provider.

    Parameters
    ----------
    provider_config:
        Optional dictionary to override the loaded config file settings.

    Returns
    -------
    BaseChatModel
        LangChain chat model instance.
    """
    cfg = get_config()
    
    # Extract settings
    active_provider = cfg.llm.active_provider
    if provider_config and "active_provider" in provider_config:
        active_provider = provider_config["active_provider"]

    logger.info("Initializing LLM provider: %s", active_provider)

    try:
        if active_provider == "openai":
            from langchain_openai import ChatOpenAI
            opt = cfg.llm.openai
            key = provider_config.get("openai_api_key", opt.api_key) if provider_config else opt.api_key
            model = provider_config.get("openai_model", opt.model) if provider_config else opt.model
            base_url = provider_config.get("openai_base_url", opt.base_url) if provider_config else opt.base_url
            
            return ChatOpenAI(
                openai_api_key=key,
                model=model,
                base_url=base_url,
                temperature=0.1,
            )

        elif active_provider == "gemini":
            from langchain_google_genai import ChatGoogleGenerativeAI
            opt = cfg.llm.gemini
            key = provider_config.get("gemini_api_key", opt.api_key) if provider_config else opt.api_key
            model = provider_config.get("gemini_model", opt.model) if provider_config else opt.model
            
            return ChatGoogleGenerativeAI(
                google_api_key=key,
                model=model,
                temperature=0.1,
            )

        elif active_provider == "ollama":
            from langchain_openai import ChatOpenAI
            opt = cfg.llm.ollama
            base_url = provider_config.get("ollama_base_url", opt.base_url) if provider_config else opt.base_url
            model = provider_config.get("ollama_model", opt.model) if provider_config else opt.model
            
            return ChatOpenAI(
                openai_api_key="ollama",  # dummy
                base_url=f"{base_url.rstrip('/')}/v1",
                model=model,
                temperature=0.1,
            )

        elif active_provider == "nvidia_nim":
            from langchain_openai import ChatOpenAI
            opt = cfg.llm.nvidia_nim
            key = provider_config.get("nvidia_api_key", opt.api_key) if provider_config else opt.api_key
            base_url = provider_config.get("nvidia_base_url", opt.base_url) if provider_config else opt.base_url
            model = provider_config.get("nvidia_model", opt.model) if provider_config else opt.model
            
            return ChatOpenAI(
                openai_api_key=key,
                base_url=base_url,
                model=model,
                temperature=0.1,
            )

        elif active_provider == "openrouter":
            from langchain_openai import ChatOpenAI
            opt = cfg.llm.openrouter
            key = provider_config.get("openrouter_api_key", opt.api_key) if provider_config else opt.api_key
            model = provider_config.get("openrouter_model", opt.model) if provider_config else opt.model
            
            return ChatOpenAI(
                openai_api_key=key,
                base_url="https://openrouter.ai/api/v1",
                model=model,
                temperature=0.1,
            )

        elif active_provider == "lmstudio":
            from langchain_openai import ChatOpenAI
            opt = cfg.llm.lmstudio
            base_url = provider_config.get("lmstudio_base_url", opt.base_url) if provider_config else opt.base_url
            model = provider_config.get("lmstudio_model", opt.model) if provider_config else opt.model
            
            return ChatOpenAI(
                openai_api_key="lmstudio",  # dummy
                base_url=base_url,
                model=model,
                temperature=0.1,
            )

        else:
            raise ValueError(f"Unknown LLM provider: {active_provider}")

    except Exception as exc:
        logger.exception("Failed to initialize LLM provider %s", active_provider)
        raise exc


async def test_connection(provider_config: Optional[dict] = None) -> dict[str, Any]:
    """Test connection to the configured LLM provider.

    Returns
    -------
    dict
        Keys: success (bool), message (str), response_time_ms (int).
    """
    start_time = time.perf_counter()
    try:
        llm = get_llm(provider_config)
        
        # Test with a simple prompt in executor to avoid blocking
        def run_test():
            return llm.invoke("Respond with the word 'pong' and nothing else.")

        response = await asyncio.get_event_loop().run_in_executor(None, run_test)
        response_text = response.content.strip().lower() if hasattr(response, "content") else str(response).strip().lower()
        
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        
        if "pong" in response_text:
            return {
                "success": True,
                "message": "Connection test succeeded (pong response received).",
                "response_time_ms": elapsed_ms,
            }
        else:
            return {
                "success": True,
                "message": f"Connection succeeded but returned unexpected output: {response_text}",
                "response_time_ms": elapsed_ms,
            }

    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        logger.error("Connection test failed: %s", exc)
        return {
            "success": False,
            "message": f"Connection test failed: {exc}",
            "response_time_ms": elapsed_ms,
        }
