"""
Heterogeneous Graph Transformer Module

Implements the HGT model for CPG-based malware classification.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Optional, Tuple
import math


class HGTConv(nn.Module):
    """
    Heterogeneous Graph Transformer Convolution Layer.
    
    Uses meta-relation aware attention for different node/edge types.
    """
    
    def __init__(self, 
                 in_channels: int,
                 out_channels: int,
                 num_node_types: int,
                 num_edge_types: int,
                 num_heads: int = 8,
                 dropout: float = 0.1):
        super().__init__()
        
        self.in_channels = in_channels
        self.out_channels = out_channels
        self.num_node_types = num_node_types
        self.num_edge_types = num_edge_types
        self.num_heads = num_heads
        self.head_dim = out_channels // num_heads
        
        # Per-type linear transformations for Query, Key, Value
        self.k_linear = nn.ModuleList([
            nn.Linear(in_channels, out_channels) for _ in range(num_node_types)
        ])
        self.q_linear = nn.ModuleList([
            nn.Linear(in_channels, out_channels) for _ in range(num_node_types)
        ])
        self.v_linear = nn.ModuleList([
            nn.Linear(in_channels, out_channels) for _ in range(num_node_types)
        ])
        
        # Attention weight for each edge type
        self.a_linear = nn.ModuleList([
            nn.Linear(out_channels, out_channels) for _ in range(num_edge_types)
        ])
        
        # Message transformation for edge types
        self.m_linear = nn.ModuleList([
            nn.Linear(out_channels, out_channels) for _ in range(num_edge_types)
        ])
        
        # Output projection
        self.out_proj = nn.Linear(out_channels, out_channels)
        
        self.dropout = nn.Dropout(dropout)
        self.layer_norm = nn.LayerNorm(out_channels)
        
        self._reset_parameters()
    
    def _reset_parameters(self):
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
    
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor,
                node_types: torch.Tensor, edge_types: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: Node features (num_nodes, in_channels)
            edge_index: Edge indices (2, num_edges)
            node_types: Node type IDs (num_nodes,)
            edge_types: Edge type IDs (num_edges,)
            
        Returns:
            Updated node features (num_nodes, out_channels)
        """
        num_nodes = x.size(0)
        
        # Initialize output
        out = torch.zeros(num_nodes, self.out_channels, device=x.device)
        
        # Compute Q, K, V for all nodes based on their types
        q = torch.zeros(num_nodes, self.out_channels, device=x.device)
        k = torch.zeros(num_nodes, self.out_channels, device=x.device)
        v = torch.zeros(num_nodes, self.out_channels, device=x.device)
        
        for t in range(self.num_node_types):
            mask = node_types == t
            if mask.any():
                q[mask] = self.q_linear[t](x[mask])
                k[mask] = self.k_linear[t](x[mask])
                v[mask] = self.v_linear[t](x[mask])
        
        # Process edges by type
        source_idx = edge_index[0]
        target_idx = edge_index[1]
        
        # Compute attention and messages for each edge type
        for e_type in range(self.num_edge_types):
            e_mask = edge_types == e_type
            if not e_mask.any():
                continue
            
            src = source_idx[e_mask]
            tgt = target_idx[e_mask]
            
            # Get Q for targets and K for sources
            q_t = q[tgt]  # (num_edges_of_type, out_channels)
            k_s = k[src]
            v_s = v[src]
            
            # Apply edge-type specific attention weight
            k_s = self.a_linear[e_type](k_s)
            
            # Compute attention scores
            attention = (q_t * k_s).sum(dim=-1) / math.sqrt(self.head_dim)
            attention = F.softmax(attention, dim=0)
            attention = self.dropout(attention)
            
            # Apply edge-type specific message transformation
            msg = self.m_linear[e_type](v_s)
            msg = msg * attention.unsqueeze(-1)
            
            # Aggregate messages
            out.scatter_add_(0, tgt.unsqueeze(-1).expand_as(msg), msg)
        
        # Apply output projection and skip connection
        out = self.out_proj(out)
        out = self.layer_norm(out + x[:, :self.out_channels] if x.size(1) == self.out_channels else out)
        
        return out


class HeterogeneousGraphTransformer(nn.Module):
    """
    Heterogeneous Graph Transformer for malware classification.
    
    Consists of:
    - Node embedding layer (from tokenization)
    - Multiple HGT convolution layers
    - Graph-level pooling
    - Classification head
    """
    
    def __init__(self,
                 input_dim: int = 256,
                 hidden_dim: int = 256,
                 num_node_types: int = 10,
                 num_edge_types: int = 6,
                 num_layers: int = 4,
                 num_heads: int = 8,
                 num_classes: int = 2,
                 dropout: float = 0.1):
        super().__init__()
        
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        # Input projection
        self.input_proj = nn.Linear(input_dim, hidden_dim)
        
        # HGT layers
        self.layers = nn.ModuleList([
            HGTConv(
                in_channels=hidden_dim,
                out_channels=hidden_dim,
                num_node_types=num_node_types,
                num_edge_types=num_edge_types,
                num_heads=num_heads,
                dropout=dropout
            )
            for _ in range(num_layers)
        ])
        
        # Graph pooling
        self.pool_linear = nn.Linear(hidden_dim, hidden_dim)
        self.pool_gate = nn.Linear(hidden_dim, 1)
        
        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes)
        )
    
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor,
                node_types: torch.Tensor, edge_types: torch.Tensor,
                batch: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: Node features (num_nodes, input_dim)
            edge_index: Edge indices (2, num_edges)
            node_types: Node type IDs (num_nodes,)
            edge_types: Edge type IDs (num_edges,)
            batch: Batch assignment (num_nodes,) - which graph each node belongs to
            
        Returns:
            Classification logits (batch_size, num_classes)
        """
        # Project input
        x = self.input_proj(x)
        
        # Apply HGT layers
        for layer in self.layers:
            x = layer(x, edge_index, node_types, edge_types)
            x = F.relu(x)
        
        # Graph pooling (attention-based)
        if batch is None:
            batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)
        
        # Compute attention weights
        gate = torch.sigmoid(self.pool_gate(x))
        x_weighted = self.pool_linear(x) * gate
        
        # Aggregate by graph
        num_graphs = batch.max().item() + 1
        graph_embeds = torch.zeros(num_graphs, self.hidden_dim, device=x.device)
        graph_embeds.scatter_add_(0, batch.unsqueeze(-1).expand_as(x_weighted), x_weighted)
        
        # Normalize by number of nodes
        counts = torch.bincount(batch, minlength=num_graphs).float().clamp(min=1)
        graph_embeds = graph_embeds / counts.unsqueeze(-1)
        
        # Classification
        logits = self.classifier(graph_embeds)
        
        return logits
    
    def get_graph_embedding(self, x: torch.Tensor, edge_index: torch.Tensor,
                           node_types: torch.Tensor, edge_types: torch.Tensor,
                           batch: Optional[torch.Tensor] = None) -> torch.Tensor:
        """Get graph-level embeddings without classification."""
        x = self.input_proj(x)
        
        for layer in self.layers:
            x = layer(x, edge_index, node_types, edge_types)
            x = F.relu(x)
        
        if batch is None:
            batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)
        
        gate = torch.sigmoid(self.pool_gate(x))
        x_weighted = self.pool_linear(x) * gate
        
        num_graphs = batch.max().item() + 1
        graph_embeds = torch.zeros(num_graphs, self.hidden_dim, device=x.device)
        graph_embeds.scatter_add_(0, batch.unsqueeze(-1).expand_as(x_weighted), x_weighted)
        
        counts = torch.bincount(batch, minlength=num_graphs).float().clamp(min=1)
        graph_embeds = graph_embeds / counts.unsqueeze(-1)
        
        return graph_embeds
