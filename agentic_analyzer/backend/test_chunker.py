import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agentic_analyzer.backend.chunker import CPGChunker

def test_chunker():
    print("Starting chunker test...")
    sample_cpg = PROJECT_ROOT / "cpg/Benignes/TopMost.cpg.json"
    if not sample_cpg.exists():
        print(f"Sample CPG not found at {sample_cpg}, trying alternative location...")
        # Check if there is any json in cpg directory
        cpg_dir = PROJECT_ROOT / "cpg"
        json_files = list(cpg_dir.glob("**/*.json"))
        if json_files:
            sample_cpg = json_files[0]
            print(f"Found alternative CPG: {sample_cpg}")
        else:
            print("No CPG files found in repository to test chunker with. Creating dummy CPG...")
            # Create a simple CPG for testing
            sample_cpg = PROJECT_ROOT / "cpg_cache/dummy.cpg.json"
            sample_cpg.parent.mkdir(parents=True, exist_ok=True)
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
            import json
            with open(sample_cpg, 'w') as f:
                json.dump(dummy_data, f)
                
    chunker = CPGChunker(sample_cpg)
    chunks = chunker.chunk()
    
    print("\n--- Chunker Output Details ---")
    print(f"Source: {sample_cpg.name}")
    print(f"Metadata - File Type: {chunks['metadata']['file_type']}")
    print(f"Metadata - Architecture: {chunks['metadata']['architecture']}")
    print(f"Metadata - Imports Count: {len(chunks['metadata']['imports'])}")
    print(f"Strings Found: {len(chunks['strings'])}")
    print(f"Call Graph Size: {len(chunks['call_graph'])}")
    print(f"Behavioral Subgraphs Count: {len(chunks['behavioral_subgraphs'])}")
    if chunks['behavioral_subgraphs']:
        first_sub = chunks['behavioral_subgraphs'][0]
        print(f"First Subgraph - Method: {first_sub['method_name']} (ID: {first_sub['method_id']})")
        print(f"  Nodes: {len(first_sub['nodes'])}")
        print(f"  Edges: {len(first_sub['edges'])}")
    print("------------------------------")
    print("Chunker test completed successfully!")

if __name__ == "__main__":
    test_chunker()
