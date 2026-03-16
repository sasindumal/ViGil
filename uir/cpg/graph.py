"""
CPG Graph Module

Implements the Code Property Graph data structure.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Iterator, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

from .schema import CPGNode, CPGEdge, NodeType, EdgeType


@dataclass
class CodePropertyGraph:
    """
    Code Property Graph - unified graph representation of code.
    
    Combines:
    - AST (Abstract Syntax Tree) edges
    - CFG (Control Flow Graph) edges
    - PDG (Program Dependence Graph) edges
    """
    
    nodes: Dict[int, CPGNode] = field(default_factory=dict)
    edges: List[CPGEdge] = field(default_factory=list)
    
    # Indexes for fast lookup
    _outgoing: Dict[int, List[CPGEdge]] = field(default_factory=lambda: defaultdict(list))
    _incoming: Dict[int, List[CPGEdge]] = field(default_factory=lambda: defaultdict(list))
    _by_type: Dict[NodeType, Set[int]] = field(default_factory=lambda: defaultdict(set))
    _next_id: int = 0
    
    # Metadata
    source_file: str = ""
    file_type: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_node(self, node: CPGNode) -> int:
        """Add a node to the graph. Returns node ID."""
        if node.id in self.nodes:
            raise ValueError(f"Node with ID {node.id} already exists")
        
        self.nodes[node.id] = node
        self._by_type[node.node_type].add(node.id)
        self._next_id = max(self._next_id, node.id + 1)
        return node.id
    
    def create_node(self, node_type: NodeType, **kwargs) -> CPGNode:
        """Create and add a new node with auto-assigned ID."""
        node = CPGNode(id=self._next_id, node_type=node_type, **kwargs)
        self.add_node(node)
        return node
    
    def add_edge(self, edge: CPGEdge):
        """Add an edge to the graph."""
        if edge.source_id not in self.nodes:
            raise ValueError(f"Source node {edge.source_id} not found")
        if edge.target_id not in self.nodes:
            raise ValueError(f"Target node {edge.target_id} not found")
        
        self.edges.append(edge)
        self._outgoing[edge.source_id].append(edge)
        self._incoming[edge.target_id].append(edge)
    
    def create_edge(self, source_id: int, target_id: int, edge_type: EdgeType, **kwargs) -> CPGEdge:
        """Create and add a new edge."""
        edge = CPGEdge(source_id=source_id, target_id=target_id, edge_type=edge_type, **kwargs)
        self.add_edge(edge)
        return edge
    
    def get_node(self, node_id: int) -> Optional[CPGNode]:
        """Get a node by ID."""
        return self.nodes.get(node_id)
    
    def get_nodes_by_type(self, node_type: NodeType) -> List[CPGNode]:
        """Get all nodes of a specific type."""
        return [self.nodes[nid] for nid in self._by_type.get(node_type, set())]
    
    def get_outgoing_edges(self, node_id: int, edge_type: Optional[EdgeType] = None) -> List[CPGEdge]:
        """Get outgoing edges from a node."""
        edges = self._outgoing.get(node_id, [])
        if edge_type:
            edges = [e for e in edges if e.edge_type == edge_type]
        return edges
    
    def get_incoming_edges(self, node_id: int, edge_type: Optional[EdgeType] = None) -> List[CPGEdge]:
        """Get incoming edges to a node."""
        edges = self._incoming.get(node_id, [])
        if edge_type:
            edges = [e for e in edges if e.edge_type == edge_type]
        return edges
    
    def get_successors(self, node_id: int, edge_type: Optional[EdgeType] = None) -> List[CPGNode]:
        """Get successor nodes."""
        edges = self.get_outgoing_edges(node_id, edge_type)
        return [self.nodes[e.target_id] for e in edges if e.target_id in self.nodes]
    
    def get_predecessors(self, node_id: int, edge_type: Optional[EdgeType] = None) -> List[CPGNode]:
        """Get predecessor nodes."""
        edges = self.get_incoming_edges(node_id, edge_type)
        return [self.nodes[e.source_id] for e in edges if e.source_id in self.nodes]
    
    def get_methods(self) -> List[CPGNode]:
        """Get all METHOD nodes."""
        return self.get_nodes_by_type(NodeType.METHOD)
    
    def get_calls(self) -> List[CPGNode]:
        """Get all CALL nodes."""
        return self.get_nodes_by_type(NodeType.CALL)
    
    @property
    def num_nodes(self) -> int:
        """Number of nodes in the graph."""
        return len(self.nodes)
    
    @property
    def num_edges(self) -> int:
        """Number of edges in the graph."""
        return len(self.edges)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert graph to dictionary for serialization."""
        return {
            'file_type': self.file_type,
            'metadata': self.metadata,
            'nodes': [n.to_dict() for n in self.nodes.values()],
            'edges': [e.to_dict() for e in self.edges],
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CodePropertyGraph':
        """Create graph from dictionary."""
        cpg = cls()
        cpg.source_file = data.get('source_file', '')
        cpg.file_type = data.get('file_type', '')
        cpg.metadata = data.get('metadata', {})
        
        for node_data in data.get('nodes', []):
            node = CPGNode.from_dict(node_data)
            cpg.add_node(node)
        
        for edge_data in data.get('edges', []):
            edge = CPGEdge.from_dict(edge_data)
            cpg.add_edge(edge)
        
        return cpg
    
    def save(self, path: Path):
        """Save graph to JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load(cls, path: Path) -> 'CodePropertyGraph':
        """Load graph from JSON file."""
        with open(path) as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    def save_optimized(self, path: Path, profile: str = "cpu_default"):
        """
        Save graph using hardware-optimized serialization.
        
        - M4 profile: uses msgpack (compact binary, lower memory bandwidth)
        - GTX/default: uses orjson (fastest JSON serialization)
        - Falls back to stdlib json if neither is available
        
        Args:
            path: Output file path
            profile: Hardware profile name
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.to_dict()
        
        if profile == "m4":
            try:
                import msgpack
                msgpack_path = path.with_suffix('.msgpack')
                with open(msgpack_path, 'wb') as f:
                    msgpack.pack(data, f, use_bin_type=True)
                return
            except ImportError:
                pass
        
        # Try orjson first (10-50x faster than json)
        try:
            import orjson
            with open(path, 'wb') as f:
                f.write(orjson.dumps(data, option=orjson.OPT_INDENT_2))
            return
        except ImportError:
            pass
        
        # Fallback to stdlib json
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
    
    @classmethod
    def load_optimized(cls, path: Path) -> 'CodePropertyGraph':
        """
        Load graph using the fastest available deserializer.
        
        Auto-detects format from file extension (.msgpack or .json).
        
        Args:
            path: Path to CPG file
            
        Returns:
            CodePropertyGraph loaded from file
        """
        path = Path(path)
        
        # Check for msgpack variant
        msgpack_path = path.with_suffix('.msgpack')
        if msgpack_path.exists():
            try:
                import msgpack
                with open(msgpack_path, 'rb') as f:
                    data = msgpack.unpack(f, raw=False)
                return cls.from_dict(data)
            except ImportError:
                pass
        
        # Try orjson first
        if path.exists():
            try:
                import orjson
                with open(path, 'rb') as f:
                    data = orjson.loads(f.read())
                return cls.from_dict(data)
            except ImportError:
                pass
            
            # Fallback to stdlib json
            with open(path) as f:
                data = json.load(f)
            return cls.from_dict(data)
        
        raise FileNotFoundError(f"CPG file not found: {path}")
    
    def merge(self, other: 'CodePropertyGraph', id_offset: Optional[int] = None):
        """Merge another graph into this one."""
        if id_offset is None:
            id_offset = self._next_id
        
        id_map = {}
        
        for old_id, node in other.nodes.items():
            new_id = old_id + id_offset
            id_map[old_id] = new_id
            new_node = CPGNode(
                id=new_id,
                node_type=node.node_type,
                name=node.name,
                code=node.code,
                line_number=node.line_number,
                order=node.order,
                attributes=node.attributes.copy(),
                signature=node.signature,
                is_external=node.is_external,
                value=node.value,
                value_type=node.value_type,
                control_type=node.control_type,
                operator_type=node.operator_type,
            )
            self.add_node(new_node)
        
        for edge in other.edges:
            new_edge = CPGEdge(
                source_id=id_map[edge.source_id],
                target_id=id_map[edge.target_id],
                edge_type=edge.edge_type,
                attributes=edge.attributes.copy(),
            )
            self.add_edge(new_edge)
    
    def subgraph(self, node_ids: Set[int]) -> 'CodePropertyGraph':
        """Create a subgraph containing only the specified nodes."""
        sub = CodePropertyGraph()
        sub.source_file = self.source_file
        sub.file_type = self.file_type
        
        for nid in node_ids:
            if nid in self.nodes:
                sub.add_node(self.nodes[nid])
        
        for edge in self.edges:
            if edge.source_id in node_ids and edge.target_id in node_ids:
                sub.add_edge(edge)
        
        return sub
    
    def bfs(self, start_id: int, edge_type: Optional[EdgeType] = None) -> Iterator[CPGNode]:
        """Breadth-first traversal from a node."""
        visited = set()
        queue = [start_id]
        
        while queue:
            nid = queue.pop(0)
            if nid in visited:
                continue
            visited.add(nid)
            
            if nid in self.nodes:
                yield self.nodes[nid]
            
            for succ in self.get_successors(nid, edge_type):
                if succ.id not in visited:
                    queue.append(succ.id)
    
    def dfs(self, start_id: int, edge_type: Optional[EdgeType] = None) -> Iterator[CPGNode]:
        """Depth-first traversal from a node."""
        visited = set()
        stack = [start_id]
        
        while stack:
            nid = stack.pop()
            if nid in visited:
                continue
            visited.add(nid)
            
            if nid in self.nodes:
                yield self.nodes[nid]
            
            for succ in reversed(self.get_successors(nid, edge_type)):
                if succ.id not in visited:
                    stack.append(succ.id)
