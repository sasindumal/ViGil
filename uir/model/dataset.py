"""
CPG Dataset Module

PyTorch dataset for CPG-based training.
"""

import torch
from torch.utils.data import Dataset
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import json
import logging

from ..cpg.graph import CodePropertyGraph
from ..cpg.schema import NodeType, EdgeType

logger = logging.getLogger(__name__)


# Mappings for node/edge types to indices
NODE_TYPE_MAP = {nt: i for i, nt in enumerate(NodeType)}
EDGE_TYPE_MAP = {et: i for i, et in enumerate(EdgeType)}


class CPGData:
    """Single CPG sample with tensor data."""
    
    def __init__(self):
        self.x: Optional[torch.Tensor] = None  # Node features
        self.edge_index: Optional[torch.Tensor] = None  # Edge indices
        self.node_types: Optional[torch.Tensor] = None  # Node type IDs
        self.edge_types: Optional[torch.Tensor] = None  # Edge type IDs
        self.y: Optional[torch.Tensor] = None  # Label
        self.num_nodes: int = 0
        self.num_edges: int = 0
        self.file_path: str = ""
    
    def to(self, device: torch.device) -> 'CPGData':
        """Move data to device."""
        data = CPGData()
        data.x = self.x.to(device) if self.x is not None else None
        data.edge_index = self.edge_index.to(device) if self.edge_index is not None else None
        data.node_types = self.node_types.to(device) if self.node_types is not None else None
        data.edge_types = self.edge_types.to(device) if self.edge_types is not None else None
        data.y = self.y.to(device) if self.y is not None else None
        data.num_nodes = self.num_nodes
        data.num_edges = self.num_edges
        data.file_path = self.file_path
        return data


class CPGDataset(Dataset):
    """Dataset for CPG graphs."""
    
    def __init__(self, 
                 cpg_dir: Path,
                 labels: Optional[Dict[str, int]] = None,
                 embedding_dim: int = 256,
                 max_nodes: int = 10000):
        """
        Initialize CPG dataset.
        
        Args:
            cpg_dir: Directory containing CPG JSON files
            labels: Dict mapping filename to label (0=benign, 1=malware)
            embedding_dim: Dimension of node features
            max_nodes: Maximum nodes per graph
        """
        self.cpg_dir = Path(cpg_dir)
        self.labels = labels or {}
        self.embedding_dim = embedding_dim
        self.max_nodes = max_nodes
        
        # Find all CPG files
        self.cpg_files = list(self.cpg_dir.rglob("*.json"))
        logger.info(f"Found {len(self.cpg_files)} CPG files")
    
    def __len__(self) -> int:
        return len(self.cpg_files)
    
    def __getitem__(self, idx: int) -> CPGData:
        cpg_path = self.cpg_files[idx]
        
        try:
            cpg = CodePropertyGraph.load(cpg_path)
            data = self._cpg_to_data(cpg)
            
            # Get label
            source_file = cpg.source_file
            if not source_file:
                 source_file = str(cpg_path)
            if source_file in self.labels:
                data.y = torch.tensor([self.labels[source_file]], dtype=torch.long)
            else:
                # Infer from source file path (not CPG path)
                # Check 'benign' first because parent folder 'malware_dataset' contains 'malware'
                source_lower = source_file.lower()
                if any(x in source_lower for x in ['\\benign\\', '/benign/', '\\benigns\\', '/benigns/']):
                    data.y = torch.tensor([0], dtype=torch.long)
                elif any(x in source_lower for x in ['\\malware\\', '/malware/', '\\malwares\\', '/malwares/']):
                    data.y = torch.tensor([1], dtype=torch.long)
                else:
                    data.y = torch.tensor([0], dtype=torch.long)
            
            data.file_path = str(cpg_path)
            return data
            
        except Exception as e:
            logger.error(f"Error loading {cpg_path}: {e}")
            return self._empty_data()
    
    def _cpg_to_data(self, cpg: CodePropertyGraph) -> CPGData:
        """Convert CPG to tensor data, reducing to basic-block nodes and pruning edges on the fly if needed."""
        data = CPGData()
        
        # Check if loaded graph contains instruction-level nodes
        has_instruction_nodes = any(
            n.node_type not in (NodeType.BLOCK, NodeType.METHOD)
            for n in cpg.nodes.values()
        )
        
        if has_instruction_nodes:
            # On-the-fly conversion of instruction-level CPG to Basic-block only CPG
            bb_nodes = [n for n in cpg.nodes.values() if n.node_type in (NodeType.BLOCK, NodeType.METHOD)]
            
            # Map every node to its parent BLOCK node ID
            node_to_block = {}
            for n in bb_nodes:
                if n.node_type == NodeType.BLOCK:
                    node_to_block[n.id] = n.id
                    
            # Propagate BLOCK containment via AST edges
            for edge in cpg.edges:
                if edge.edge_type == EdgeType.AST:
                    if edge.source_id in node_to_block:
                        node_to_block[edge.target_id] = node_to_block[edge.source_id]
                        
            # Bounded propagation for nested/argument nodes (operands, literals, identifiers, etc.)
            for _ in range(3):
                for edge in cpg.edges:
                    if edge.source_id in node_to_block and edge.target_id not in node_to_block:
                        node_to_block[edge.target_id] = node_to_block[edge.source_id]
                    elif edge.target_id in node_to_block and edge.source_id not in node_to_block:
                        node_to_block[edge.source_id] = node_to_block[edge.target_id]
            
            # Reconstruct edges at basic block level
            new_edges = []
            seen_edges = set()
            
            for edge in cpg.edges:
                src_id, tgt_id = edge.source_id, edge.target_id
                etype = edge.edge_type
                
                # 1. CFG edges: keep only block-to-block CFG edges
                if etype == EdgeType.CFG:
                    src_block = node_to_block.get(src_id)
                    tgt_block = node_to_block.get(tgt_id)
                    if src_block is not None and tgt_block is not None and src_block != tgt_block:
                        edge_key = (src_block, tgt_block, EdgeType.CFG.value)
                        if edge_key not in seen_edges:
                            seen_edges.add(edge_key)
                            new_edges.append((src_block, tgt_block, EdgeType.CFG))
                            
                # 2. CALLS edges: 
                # Keep METHOD-to-METHOD CALLS edges, and map BLOCK-to-METHOD CALLS edges
                elif etype == EdgeType.CALLS:
                    src_node = cpg.nodes.get(src_id)
                    tgt_node = cpg.nodes.get(tgt_id)
                    
                    if src_node and tgt_node:
                        # Method to Method
                        if src_node.node_type == NodeType.METHOD and tgt_node.node_type == NodeType.METHOD:
                            edge_key = (src_id, tgt_id, EdgeType.CALLS.value)
                            if edge_key not in seen_edges:
                                seen_edges.add(edge_key)
                                new_edges.append((src_id, tgt_id, EdgeType.CALLS))
                        # Block/Instruction to Method
                        else:
                            src_block = node_to_block.get(src_id)
                            if src_block is not None and tgt_node.node_type == NodeType.METHOD:
                                edge_key = (src_block, tgt_id, EdgeType.CALLS.value)
                                if edge_key not in seen_edges:
                                    seen_edges.add(edge_key)
                                    new_edges.append((src_block, tgt_id, EdgeType.CALLS))
                                    
                # 3. DATA_FLOW edges: map instruction-level reaches to block-level reaches
                elif etype == EdgeType.DATA_FLOW:
                    src_block = node_to_block.get(src_id)
                    tgt_block = node_to_block.get(tgt_id)
                    if src_block is not None and tgt_block is not None and src_block != tgt_block:
                        edge_key = (src_block, tgt_block, EdgeType.DATA_FLOW.value)
                        if edge_key not in seen_edges:
                            seen_edges.add(edge_key)
                            new_edges.append((src_block, tgt_block, EdgeType.DATA_FLOW))
            # 4. Connect METHOD to its contained BLOCK nodes using CFG edges
            for edge in cpg.edges:
                if edge.edge_type == EdgeType.AST:
                    src_node = cpg.nodes.get(edge.source_id)
                    tgt_node = cpg.nodes.get(edge.target_id)
                    if src_node and tgt_node:
                        if src_node.node_type == NodeType.METHOD and tgt_node.node_type == NodeType.BLOCK:
                            edge_key = (edge.source_id, edge.target_id, EdgeType.CFG.value)
                            if edge_key not in seen_edges:
                                seen_edges.add(edge_key)
                                new_edges.append((edge.source_id, edge.target_id, EdgeType.CFG))
            
            nodes = bb_nodes
        else:
            # Graph is already basic-block only, extract nodes and edges directly
            nodes = list(cpg.nodes.values())
            new_edges = []
            for edge in cpg.edges:
                if edge.edge_type in (EdgeType.CFG, EdgeType.CALLS, EdgeType.DATA_FLOW):
                    new_edges.append((edge.source_id, edge.target_id, edge.edge_type))
                    
        # Apply max_nodes limit if needed
        if len(nodes) > self.max_nodes:
            nodes = nodes[:self.max_nodes]
            
        if not nodes:
            return self._empty_data()
            
        data.num_nodes = len(nodes)
        
        # Create node ID mapping
        node_id_map = {n.id: i for i, n in enumerate(nodes)}
        valid_ids = set(node_id_map.keys())
        
        # Node features
        features = []
        node_types = []
        
        for node in nodes:
            feat = self._node_to_features(node)
            features.append(feat)
            type_id = NODE_TYPE_MAP.get(node.node_type, 0)
            node_types.append(type_id)
            
        data.x = torch.stack(features)
        data.node_types = torch.tensor(node_types, dtype=torch.long)
        
        # Build edge tensors
        sources = []
        targets = []
        edge_types = []
        
        for src, tgt, etype in new_edges:
            if src in valid_ids and tgt in valid_ids:
                sources.append(node_id_map[src])
                targets.append(node_id_map[tgt])
                edge_types.append(EDGE_TYPE_MAP.get(etype, 0))
                
        if sources:
            data.edge_index = torch.tensor([sources, targets], dtype=torch.long)
            data.edge_types = torch.tensor(edge_types, dtype=torch.long)
        else:
            data.edge_index = torch.zeros((2, 0), dtype=torch.long)
            data.edge_types = torch.zeros(0, dtype=torch.long)
            
        data.num_edges = len(sources)
        return data
    
    def _node_to_features(self, node) -> torch.Tensor:
        """Convert node to feature vector."""
        feat = torch.zeros(self.embedding_dim)
        
        # Encode node type
        type_id = NODE_TYPE_MAP.get(node.node_type, 0)
        feat[type_id] = 1.0
        
        # Encode some attributes
        if node.is_external:
            feat[20] = 1.0
        
        if node.line_number > 0:
            feat[21] = min(node.line_number / 1000, 1.0)
        
        # Hash the name for simple encoding
        if node.name:
            name_hash = hash(node.name) % 100
            feat[50 + name_hash] = 1.0
        
        return feat
    
    def _empty_data(self) -> CPGData:
        """Return empty data for failed loads."""
        data = CPGData()
        data.x = torch.zeros((1, self.embedding_dim))
        data.edge_index = torch.zeros((2, 0), dtype=torch.long)
        data.node_types = torch.zeros(1, dtype=torch.long)
        data.edge_types = torch.zeros(0, dtype=torch.long)
        data.y = torch.tensor([0], dtype=torch.long)
        data.num_nodes = 1
        data.num_edges = 0
        return data


def collate_cpg_batch(batch: List[CPGData]) -> Tuple[CPGData, torch.Tensor]:
    """Collate a batch of CPG data."""
    # Combine into single graph with batch indicator
    xs = []
    edge_indices = []
    node_types = []
    edge_types = []
    ys = []
    batches = []
    
    node_offset = 0
    
    for i, data in enumerate(batch):
        xs.append(data.x)
        node_types.append(data.node_types)
        
        # Offset edge indices
        if data.edge_index is not None and data.edge_index.size(1) > 0:
            edge_indices.append(data.edge_index + node_offset)
            edge_types.append(data.edge_types)
        
        ys.append(data.y)
        batches.append(torch.full((data.num_nodes,), i, dtype=torch.long))
        
        node_offset += data.num_nodes
    
    combined = CPGData()
    combined.x = torch.cat(xs, dim=0)
    combined.node_types = torch.cat(node_types, dim=0)
    combined.y = torch.cat(ys, dim=0)
    
    if edge_indices:
        combined.edge_index = torch.cat(edge_indices, dim=1)
        combined.edge_types = torch.cat(edge_types, dim=0)
    else:
        combined.edge_index = torch.zeros((2, 0), dtype=torch.long)
        combined.edge_types = torch.zeros(0, dtype=torch.long)
    
    batch_tensor = torch.cat(batches, dim=0)
    
    return combined, batch_tensor
