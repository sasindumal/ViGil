import sys
from pathlib import Path
import json

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Setup environment variables from .env
from agentic_analyzer.backend.config import Config
from agentic_analyzer.backend.chunker import CPGChunker
from agentic_analyzer.backend.analyzer import AgenticMalwareAnalyzer

def main():
    print("Starting synchronous E2E test of the CrewAI analysis pipeline...")
    
    # Locate a generated CPG file from one of the runs
    runs_dir = PROJECT_ROOT / "agentic_analyzer" / "runs"
    cpg_files = list(runs_dir.glob("**/extracted_file.cpg.json"))
    
    if not cpg_files:
        print("No generated CPG files found in runs! Please run test_chunker or upload a file first.")
        return
        
    cpg_path = cpg_files[0]
    print(f"Using CPG file for testing: {cpg_path}")
    
    chunker = CPGChunker(cpg_path)
    chunks = chunker.chunk()
    print(f"CPG successfully chunked: {len(chunks['behavioral_subgraphs'])} subgraphs found.")
    
    # Initialize analyzer with a mock run ID
    analyzer = AgenticMalwareAnalyzer("test_run_E2E")
    
    print("\nTriggering CrewAI analysis (this might take a few minutes)...")
    try:
        report = analyzer.analyze(chunks)
        print("\n[✓] CrewAI analysis finished successfully!")
        print("--- Final Report Preview ---")
        print(report[:1000])
        print("----------------------------")
    except Exception as e:
        print(f"\n[❌] E2E test failed with exception: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
