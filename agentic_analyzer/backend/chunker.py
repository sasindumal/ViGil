import json
from pathlib import Path
from typing import Dict, Any, List

class CPGChunker:
    """
    CPG Chunker
    Splits massive Code Property Graphs (CPGs) into semantic chunks 
    suitable for CrewAI specialist agent analysis.
    """
    
    def __init__(self, cpg_path: Path):
        self.cpg_path = Path(cpg_path)
        self.raw_data = self._load_json()
        
    def _load_json(self) -> Dict[str, Any]:
        if not self.cpg_path.exists():
            raise FileNotFoundError(f"CPG file not found: {self.cpg_path}")
        with open(self.cpg_path, 'r', encoding='utf-8') as f:
            return json.load(f)
            
    def get_metadata_chunk(self) -> Dict[str, Any]:
        """Extracts basic info, imports, exports, and high-level structure."""
        metadata = self.raw_data.get("metadata", {})
        return {
            "file_type": self.raw_data.get("file_type", "unknown"),
            "architecture": metadata.get("architecture", "unknown"),
            "subsystem": metadata.get("subsystem", "unknown"),
            "timestamp": metadata.get("timestamp", 0),
            "imports": metadata.get("imports", []),
            "exports": metadata.get("exports", [])
        }
        
    def get_strings_chunk(self) -> List[str]:
        """Extracts all strings embedded in the file."""
        return self.raw_data.get("metadata", {}).get("strings", [])
        
    def get_call_graph_chunk(self) -> List[Dict[str, Any]]:
        """Extracts all call details and method signatures."""
        nodes = self.raw_data.get("nodes", [])
        methods = [n for n in nodes if n.get("type") == "METHOD"]
        calls = [n for n in nodes if n.get("type") == "CALL"]
        
        call_graph = []
        for method in methods:
            call_graph.append({
                "method_id": method.get("id"),
                "name": method.get("name"),
                "signature": method.get("signature", ""),
                "is_external": method.get("is_external", False)
            })
            
        for call in calls:
            call_graph.append({
                "call_id": call.get("id"),
                "name": call.get("name"),
                "code": call.get("code", "")
            })
            
        return call_graph
        
    def get_behavioral_subgraphs(self, max_nodes: int = 500) -> List[Dict[str, Any]]:
        """
        Groups nodes and edges into smaller semantic subgraphs
        corresponding to functions to stay safely inside LLM context window limits.
        """
        nodes = self.raw_data.get("nodes", [])
        edges = self.raw_data.get("edges", [])
        
        # Build node registry
        node_map = {n["id"]: n for n in nodes}
        
        # Group instruction nodes by their parent BLOCK node via AST edge
        # and then link blocks to METHOD nodes
        block_to_method = {}
        inst_to_block = {}
        
        for edge in edges:
            edge_type = edge.get("type")
            source = edge.get("source")
            target = edge.get("target")
            
            if edge_type == "IS_AST_PARENT":
                source_node = node_map.get(source)
                target_node = node_map.get(target)
                
                if source_node and target_node:
                    if source_node["type"] == "METHOD" and target_node["type"] == "BLOCK":
                        block_to_method[target] = source
                    elif source_node["type"] == "BLOCK" and target_node["type"] in ("CALL", "OPERATOR", "CONTROL_STRUCTURE", "RETURN"):
                        inst_to_block[target] = source
                        
        # Resolve which method each instruction belongs to
        inst_to_method = {}
        for inst_id, block_id in inst_to_block.items():
            method_id = block_to_method.get(block_id)
            if method_id:
                inst_to_method[inst_id] = method_id
                
        # Group nodes by method
        subgraph_nodes = {}
        for node in nodes:
            nid = node["id"]
            m_id = None
            if node["type"] == "METHOD":
                m_id = nid
            elif node["type"] == "BLOCK":
                m_id = block_to_method.get(nid)
            elif node["type"] in ("CALL", "OPERATOR", "CONTROL_STRUCTURE", "RETURN"):
                m_id = inst_to_method.get(nid)
                
            if m_id is not None:
                if m_id not in subgraph_nodes:
                    subgraph_nodes[m_id] = []
                subgraph_nodes[m_id].append(node)
                
        # Build individual subgraphs
        subgraphs = []
        for m_id, s_nodes in subgraph_nodes.items():
            method_node = node_map.get(m_id)
            method_name = method_node.get("name", "unknown") if method_node else "unknown"
            
            # Get subset of edges containing only these nodes
            s_node_ids = {n["id"] for n in s_nodes}
            s_edges = [e for e in edges if e["source"] in s_node_ids and e["target"] in s_node_ids]
            
            # Truncate if nodes count exceeds threshold to avoid overflow
            if len(s_nodes) > max_nodes:
                s_nodes = s_nodes[:max_nodes]
                s_node_ids = {n["id"] for n in s_nodes}
                s_edges = [e for e in s_edges if e["source"] in s_node_ids and e["target"] in s_node_ids]
                
            subgraphs.append({
                "method_id": m_id,
                "method_name": method_name,
                "nodes": s_nodes,
                "edges": s_edges
            })
            
        return subgraphs
        
    def chunk(self) -> Dict[str, Any]:
        """Runs the entire chunking pipeline and returns all chunks."""
        return {
            "metadata": self.get_metadata_chunk(),
            "strings": self.get_strings_chunk(),
            "call_graph": self.get_call_graph_chunk(),
            "behavioral_subgraphs": self.get_behavioral_subgraphs()
        }
