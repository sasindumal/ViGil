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

import hashlib

logger = logging.getLogger(__name__)


# Mappings for node/edge types to indices
NODE_TYPE_MAP = {nt: i for i, nt in enumerate(NodeType)}
EDGE_TYPE_MAP = {et: i for i, et in enumerate(EdgeType)}

ALL_INST_KEYS = [
    # NodeTypes
    'CALL', 'RETURN', 'CONTROL_STRUCTURE', 'OPERATOR', 'LITERAL', 'IDENTIFIER',
    # OperatorTypes
    '<operator>.addition', '<operator>.subtraction', '<operator>.multiplication',
    '<operator>.division', '<operator>.modulo', '<operator>.negation',
    '<operator>.bitAnd', '<operator>.bitOr', '<operator>.bitXor', '<operator>.bitNot',
    '<operator>.leftShift', '<operator>.rightShift', '<operator>.equals',
    '<operator>.notEquals', '<operator>.lessThan', '<operator>.lessEqual',
    '<operator>.greaterThan', '<operator>.greaterEqual', '<operator>.logicalAnd',
    '<operator>.logicalOr', '<operator>.logicalNot', '<operator>.assignment',
    '<operator>.load', '<operator>.store', '<operator>.addressOf',
    '<operator>.dereference', '<operator>.indexAccess', '<operator>.memberAccess',
    '<operator>.cast',
    # ControlTypes
    'IF', 'ELSE', 'WHILE', 'FOR', 'DO', 'SWITCH', 'TRY', 'CATCH', 'FINALLY'
]
INST_KEY_TO_IDX = {key: 100 + i for i, key in enumerate(ALL_INST_KEYS)}


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
            
            # Reconstruct instruction counts for BLOCK nodes from original instruction-level nodes
            block_inst_counts = {}
            for node in cpg.nodes.values():
                if node.node_type not in (NodeType.BLOCK, NodeType.METHOD):
                    parent_block = node_to_block.get(node.id)
                    if parent_block is not None:
                        if parent_block not in block_inst_counts:
                            block_inst_counts[parent_block] = {}
                        
                        # Determine key: NodeType value or operator_type/control_type value
                        key = node.node_type.value
                        if node.operator_type:
                            key = node.operator_type.value
                        elif node.control_type:
                            key = node.control_type.value
                            
                        block_inst_counts[parent_block][key] = block_inst_counts[parent_block].get(key, 0) + 1
            
            # Inject inst_counts into BLOCK node attributes
            for n in bb_nodes:
                if n.node_type == NodeType.BLOCK:
                    n.attributes['inst_counts'] = block_inst_counts.get(n.id, {})
            
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
                    
        # Apply max_nodes limit if needed via BFS subgraph sampling
        if len(nodes) > self.max_nodes:
            # Find method entry points as seed nodes
            start_nodes = [n.id for n in nodes if n.node_type == NodeType.METHOD]
            if not start_nodes:
                start_nodes = [nodes[0].id]
            
            # Build adjacency mapping (undirected for connectivity)
            adj = {}
            for src, tgt, etype in new_edges:
                adj.setdefault(src, []).append(tgt)
                adj.setdefault(tgt, []).append(src)
            
            visited = set(start_nodes)
            queue = list(start_nodes)
            while queue and len(visited) < self.max_nodes:
                curr = queue.pop(0)
                for neighbor in adj.get(curr, []):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)
                        if len(visited) >= self.max_nodes:
                            break
            
            # If we still haven't reached max_nodes, add more
            if len(visited) < self.max_nodes:
                for n in nodes:
                    if n.id not in visited:
                        visited.add(n.id)
                        if len(visited) >= self.max_nodes:
                            break
            
            # Filter nodes and edges
            nodes = [n for n in nodes if n.id in visited]
            new_edges = [(src, tgt, etype) for src, tgt, etype in new_edges if src in visited and tgt in visited]
            
        if not nodes:
            return self._empty_data()
            
        # Compute node degrees on filtered graph
        in_degrees = {}
        out_degrees = {}
        edge_in_degrees = {}   # (node_id, edge_type_idx) -> count
        edge_out_degrees = {}  # (node_id, edge_type_idx) -> count
        
        for src, tgt, etype in new_edges:
            et_idx = EDGE_TYPE_MAP.get(etype, 0)
            out_degrees[src] = out_degrees.get(src, 0) + 1
            in_degrees[tgt] = in_degrees.get(tgt, 0) + 1
            edge_out_degrees[(src, et_idx)] = edge_out_degrees.get((src, et_idx), 0) + 1
            edge_in_degrees[(tgt, et_idx)] = edge_in_degrees.get((tgt, et_idx), 0) + 1
            
        data.num_nodes = len(nodes)
        
        # Create node ID mapping
        node_id_map = {n.id: i for i, n in enumerate(nodes)}
        valid_ids = set(node_id_map.keys())
        
        # Node features
        features = []
        node_types = []
        
        total_nodes = len(nodes)
        total_edges = len(new_edges)
        
        for node in nodes:
            n_in = in_degrees.get(node.id, 0)
            n_out = out_degrees.get(node.id, 0)
            
            # Gather edge-specific counts
            etype_in = {et_idx: edge_in_degrees.get((node.id, et_idx), 0) for et_idx in range(8)}
            etype_out = {et_idx: edge_out_degrees.get((node.id, et_idx), 0) for et_idx in range(8)}
            
            feat = self._node_to_features(
                node,
                in_deg=n_in,
                out_deg=n_out,
                etype_in_deg=etype_in,
                etype_out_deg=etype_out,
                total_nodes=total_nodes,
                total_edges=total_edges
            )
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
    
    def _node_to_features(self, node,
                           in_deg: int = 0,
                           out_deg: int = 0,
                           etype_in_deg: Dict[int, int] = None,
                           etype_out_deg: Dict[int, int] = None,
                           total_nodes: int = 1,
                           total_edges: int = 0) -> torch.Tensor:
        """Convert node to feature vector with deterministic hashing, degrees, context, and n-grams."""
        feat = torch.zeros(self.embedding_dim)
        import math
        
        # Helper for deterministic hashing
        def deterministic_hash(s: str) -> int:
            h = 0
            for char in s:
                h = (31 * h + ord(char)) & 0xFFFFFFFF
            return h
        
        # 1. Encode node type (dims 0..10)
        type_id = NODE_TYPE_MAP.get(node.node_type, 0)
        if 0 <= type_id < 11:
            feat[type_id] = 1.0
        
        # 2. Structural features (dims 10..28)
        # Normalize with log(x + 1)
        feat[10] = math.log1p(in_deg) / 5.0
        feat[11] = math.log1p(out_deg) / 5.0
        feat[12] = math.log1p(in_deg + out_deg) / 5.0
        
        # Edge-type specific in-degrees (dims 13..20)
        if etype_in_deg:
            for et_idx, count in etype_in_deg.items():
                if 0 <= et_idx < 8:
                    feat[13 + et_idx] = math.log1p(count) / 5.0
                    
        # Edge-type specific out-degrees (dims 21..28)
        if etype_out_deg:
            for et_idx, count in etype_out_deg.items():
                if 0 <= et_idx < 8:
                    feat[21 + et_idx] = math.log1p(count) / 5.0
        
        # 3. Attributes (dims 29..31)
        if node.is_external:
            feat[29] = 1.0
        
        if node.line_number > 0:
            feat[30] = min(node.line_number / 1000.0, 1.0)
            
        # 4. Character n-gram multi-hash (dims 32..99)
        if node.name:
            name = node.name.lower()
            ngrams = [name[i:i+3] for i in range(len(name)-2)]
            if not ngrams:
                ngrams = [name]
            
            num_buckets = 68
            start_bucket = 32
            for ng in ngrams:
                ng_bytes = ng.encode('utf-8', errors='ignore')
                h1 = int(hashlib.md5(ng_bytes).hexdigest(), 16) % num_buckets
                h2 = int(hashlib.sha1(ng_bytes).hexdigest(), 16) % num_buckets
                h3 = deterministic_hash(ng) % num_buckets
                feat[start_bucket + h1] = 1.0
                feat[start_bucket + h2] = 1.0
                feat[start_bucket + h3] = 1.0
            
        # 5. Populate instruction composition features for BLOCK nodes (dims 100..131)
        if node.node_type == NodeType.BLOCK:
            inst_counts = node.attributes.get('inst_counts', {})
            for k, count in inst_counts.items():
                if k in INST_KEY_TO_IDX:
                    idx = INST_KEY_TO_IDX[k]
                    # Normalize frequency count
                    feat[idx] = min(count / 10.0, 1.0)
                    
        # 6. Graph-level context features (dims 150..152)
        feat[150] = math.log1p(total_nodes) / 10.0
        feat[151] = math.log1p(total_edges) / 10.0
        feat[152] = total_edges / max(total_nodes, 1)  # average degree/density
        
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
