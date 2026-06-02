import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

class Config:
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai").lower()
    
    # OpenAI
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL_NAME = os.getenv("OPENAI_MODEL_NAME", "gpt-4o")
    
    # Ollama
    OLLAMA_API_BASE = os.getenv("OLLAMA_API_BASE", "http://localhost:11434")
    OLLAMA_MODEL_NAME = os.getenv("OLLAMA_MODEL_NAME", "llama3")
    
    # LM Studio
    LMSTUDIO_API_BASE = os.getenv("LMSTUDIO_API_BASE", "http://localhost:1234/v1")
    LMSTUDIO_MODEL_NAME = os.getenv("LMSTUDIO_MODEL_NAME", "meta-llama-3-8b-instruct")
    
    # Tavily
    TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")
    
    # Server
    PORT = int(os.getenv("PORT", "8000"))
    HOST = os.getenv("HOST", "0.0.0.0")

    @classmethod
    def get_llm(cls):
        """Returns the configured LLM based on provider selection."""
        # We dynamic import to avoid requiring crewai / langchain when not active
        if cls.LLM_PROVIDER == "openai":
            from langchain_openai import ChatOpenAI
            if not cls.OPENAI_API_KEY:
                raise ValueError("OPENAI_API_KEY must be set in .env when using openai provider.")
            return ChatOpenAI(
                api_key=cls.OPENAI_API_KEY,
                model=cls.OPENAI_MODEL_NAME,
                temperature=0.1
            )
        elif cls.LLM_PROVIDER == "ollama":
            from langchain_openai import ChatOpenAI
            # Ollama operates as an OpenAI compatible endpoint or via ChatOllama
            # Let's use OpenAI compatible client for Ollama to stay robust with CrewAI
            return ChatOpenAI(
                base_url=f"{cls.OLLAMA_API_BASE}/v1",
                api_key="ollama", # placeholder
                model=cls.OLLAMA_MODEL_NAME,
                temperature=0.1
            )
        elif cls.LLM_PROVIDER == "lmstudio":
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(
                base_url=cls.LMSTUDIO_API_BASE,
                api_key="lmstudio", # placeholder
                model=cls.LMSTUDIO_MODEL_NAME,
                temperature=0.1
            )
        else:
            raise ValueError(f"Unknown LLM_PROVIDER: {cls.LLM_PROVIDER}")
