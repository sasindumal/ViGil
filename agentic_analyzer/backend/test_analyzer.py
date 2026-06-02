import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Setup temporary environment variables for simple mock test
import os
os.environ["LLM_PROVIDER"] = "ollama"  # Mock Ollama provider which can accept dummy values
os.environ["OLLAMA_API_BASE"] = "http://localhost:11434"
os.environ["OLLAMA_MODEL_NAME"] = "llama3"

from agentic_analyzer.backend.analyzer import AgenticMalwareAnalyzer
from agentic_analyzer.backend.chunker import CPGChunker

def test_analyzer():
    print("Testing Analyzer module configuration...")
    dummy_cpg = PROJECT_ROOT / "cpg_cache/dummy.cpg.json"
    if not dummy_cpg.exists():
        dummy_cpg.parent.mkdir(parents=True, exist_ok=True)
        import json
        dummy_data = {
            "file_type": "exe",
            "metadata": {
                "architecture": "x64",
                "strings": ["hello", "world", "http://malicious.com"],
                "imports": ["KERNEL32.dll!VirtualAllocEx", "KERNEL32.dll!WriteProcessMemory"]
            },
            "nodes": [
                {"id": 0, "type": "METHOD", "name": "main"},
                {"id": 1, "type": "BLOCK", "name": "block_0"},
                {"id": 2, "type": "CALL", "name": "VirtualAllocEx", "code": "VirtualAllocEx()"}
            ],
            "edges": [
                {"source": 0, "target": 1, "type": "IS_AST_PARENT"},
                {"source": 1, "target": 2, "type": "IS_AST_PARENT"}
            ]
        }
        with open(dummy_cpg, 'w') as f:
            json.dump(dummy_data, f)

    chunker = CPGChunker(dummy_cpg)
    chunks = chunker.chunk()
    
    # Initialize analyzer
    analyzer = AgenticMalwareAnalyzer("test_run_123")
    
    print("Agent setup summary:")
    print(f"LLM Provider: {analyzer.llm.model_name if hasattr(analyzer.llm, 'model_name') else 'Configured'}")
    print("Analyzer loaded and verified successfully!")

if __name__ == "__main__":
    test_analyzer()
