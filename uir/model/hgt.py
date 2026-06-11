"""
Heterogeneous Graph Transformer Module

Implements the HGT model for CPG-based malware classification.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Optional, Tuple
import math


def scatter_softmax(scores: torch.Tensor, index: torch.Tensor, num_nodes: int) -> torch.Tensor:
    """
    Compute softmax of `scores` grouped by `index` (per-target-node normalization).
    
    This is the correct way to normalize attention in graph networks:
    for each target node, softmax is computed over all its incoming edges.
    
    Args:
        scores: Raw attention scores (num_edges,)
        index: Target node indices for each edge (num_edges,)
        num_nodes: Total number of nodes
        
    Returns:
        Normalized attention weights (num_edges,)
    """
    # Numerical stability: subtract max per target node
    score_max = torch.zeros(num_nodes, device=scores.device, dtype=scores.dtype)
    score_max.scatter_reduce_(0, index, scores, reduce='amax', include_self=True)
    scores = scores - score_max[index]
    
    # Compute exp
    exp_scores = torch.exp(scores)
    
    # Sum exp per target node
    exp_sum = torch.zeros(num_nodes, device=scores.device, dtype=scores.dtype)
    exp_sum.scatter_add_(0, index, exp_scores)
    
    # Normalize
    return exp_scores / (exp_sum[index] + 1e-12)


class FeedForward(nn.Module):
    """Position-wise feed-forward network (standard transformer FFN)."""
    
    def __init__(self, dim: int, ff_mult: int = 4, dropout: float = 0.1):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(dim, dim * ff_mult),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(dim * ff_mult, dim),
            nn.Dropout(dropout),
        )
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class HGTConv(nn.Module):
    """
    Heterogeneous Graph Transformer Convolution Layer.
    
    Uses meta-relation aware attention for different node/edge types.
    Fixed: per-target-node softmax, pre-norm residual, FFN block.
    """
    
    def __init__(self, 
                 in_channels: int,
                 out_channels: int,
                 num_node_types: int,
                 num_edge_types: int,
                 num_heads: int = 8,
                 dropout: float = 0.1,
                 drop_path_rate: float = 0.0):
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
        
        # Skip connection projection (handles dimension mismatch)
        self.skip_proj = nn.Linear(in_channels, out_channels) if in_channels != out_channels else nn.Identity()
        
        self.dropout = nn.Dropout(dropout)
        
        # Pre-norm (applied before attention)
        self.attn_norm = nn.LayerNorm(in_channels)
        
        # FFN block with pre-norm
        self.ffn_norm = nn.LayerNorm(out_channels)
        self.ffn = FeedForward(out_channels, ff_mult=4, dropout=dropout)
        
        # Stochastic depth (drop path) for regularization
        self.drop_path_rate = drop_path_rate
        
        self._reset_parameters()
    
    def _reset_parameters(self):
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
    
    def _drop_path(self, x: torch.Tensor) -> torch.Tensor:
        """Stochastic depth: randomly drop entire residual branch during training."""
        if not self.training or self.drop_path_rate == 0.0:
            return x
        keep_prob = 1.0 - self.drop_path_rate
        # Per-sample drop (dim 0 is batch/node dimension)
        shape = (x.shape[0],) + (1,) * (x.ndim - 1)
        mask = torch.bernoulli(torch.full(shape, keep_prob, device=x.device, dtype=x.dtype))
        return x * mask / keep_prob
    
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
        
        # === Attention block with pre-norm residual ===
        residual = self.skip_proj(x)
        
        # Pre-norm
        x_norm = self.attn_norm(x)
        
        # Initialize output
        out = torch.zeros(num_nodes, self.out_channels, device=x.device)
        
        # Compute Q, K, V for all nodes based on their types
        q = torch.zeros(num_nodes, self.out_channels, device=x.device)
        k = torch.zeros(num_nodes, self.out_channels, device=x.device)
        v = torch.zeros(num_nodes, self.out_channels, device=x.device)
        
        for t in range(self.num_node_types):
            mask = node_types == t
            if mask.any():
                q[mask] = self.q_linear[t](x_norm[mask])
                k[mask] = self.k_linear[t](x_norm[mask])
                v[mask] = self.v_linear[t](x_norm[mask])
        
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
            
            # FIXED: Per-target-node softmax (was incorrectly dim=0 globally)
            attention = scatter_softmax(attention, tgt, num_nodes)
            attention = self.dropout(attention)
            
            # Apply edge-type specific message transformation
            msg = self.m_linear[e_type](v_s)
            msg = msg * attention.unsqueeze(-1)
            
            # Aggregate messages
            out.scatter_add_(0, tgt.unsqueeze(-1).expand_as(msg), msg)
        
        # Apply output projection + residual with drop path
        out = self.out_proj(out)
        x = residual + self._drop_path(out)
        
        # === FFN block with pre-norm residual ===
        x = x + self._drop_path(self.ffn(self.ffn_norm(x)))
        
        return x


class MultiHeadAttentionPooling(nn.Module):
    """
    Multi-head attention pooling for graph-level representations.
    
    Uses learnable query vectors to attend over all nodes in a graph,
    producing a richer graph-level embedding than simple gated mean pooling.
    """
    
    def __init__(self, hidden_dim: int, num_heads: int = 4, dropout: float = 0.1):
        super().__init__()
        self.num_heads = num_heads
        self.hidden_dim = hidden_dim
        self.head_dim = hidden_dim // num_heads
        
        # Learnable query vectors (one per head)
        self.query = nn.Parameter(torch.randn(num_heads, self.head_dim))
        
        # Key and Value projections
        self.key_proj = nn.Linear(hidden_dim, hidden_dim)
        self.value_proj = nn.Linear(hidden_dim, hidden_dim)
        
        # Output projection
        self.out_proj = nn.Linear(hidden_dim, hidden_dim)
        self.layer_norm = nn.LayerNorm(hidden_dim)
        self.dropout = nn.Dropout(dropout)
        
        nn.init.normal_(self.query, std=0.02)
    
    def forward(self, x: torch.Tensor, batch: torch.Tensor) -> torch.Tensor:
        """
        Pool node features into graph-level embeddings.
        
        Args:
            x: Node features (num_nodes, hidden_dim)
            batch: Batch assignment (num_nodes,)
            
        Returns:
            Graph embeddings (num_graphs, hidden_dim)
        """
        num_graphs = batch.max().item() + 1
        
        # Project keys and values
        keys = self.key_proj(x)    # (num_nodes, hidden_dim)
        values = self.value_proj(x)  # (num_nodes, hidden_dim)
        
        # Reshape for multi-head: (num_nodes, num_heads, head_dim)
        keys = keys.view(-1, self.num_heads, self.head_dim)
        values = values.view(-1, self.num_heads, self.head_dim)
        
        # Compute attention: query (num_heads, head_dim) @ keys (num_nodes, num_heads, head_dim)
        # -> scores (num_nodes, num_heads)
        scores = (keys * self.query.unsqueeze(0)).sum(dim=-1) / math.sqrt(self.head_dim)
        
        # Per-graph softmax
        attn = scatter_softmax(scores.reshape(-1), 
                               batch.unsqueeze(1).expand(-1, self.num_heads).reshape(-1),
                               num_graphs)
        attn = attn.view(-1, self.num_heads)  # (num_nodes, num_heads)
        attn = self.dropout(attn)
        
        # Weighted sum: (num_nodes, num_heads, head_dim) * (num_nodes, num_heads, 1)
        weighted = values * attn.unsqueeze(-1)
        
        # Aggregate per graph
        weighted_flat = weighted.view(-1, self.hidden_dim)  # (num_nodes, hidden_dim)
        graph_embeds = torch.zeros(num_graphs, self.hidden_dim, device=x.device)
        graph_embeds.scatter_add_(0, batch.unsqueeze(-1).expand_as(weighted_flat), weighted_flat)
        
        # Output projection + norm
        graph_embeds = self.out_proj(graph_embeds)
        graph_embeds = self.layer_norm(graph_embeds)
        
        return graph_embeds


class HeterogeneousGraphTransformer(nn.Module):
    """
    Heterogeneous Graph Transformer for malware classification.
    
    Consists of:
    - Node embedding layer (from tokenization)
    - Multiple HGT convolution layers with pre-norm residuals and FFN
    - Multi-head attention pooling
    - Classification head
    """
    
    def __init__(self,
                 input_dim: int = 320,
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
        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        
        # Stochastic depth rates (linearly increasing)
        drop_path_rates = [0.1 * i / max(num_layers - 1, 1) for i in range(num_layers)]
        
        # HGT layers
        self.layers = nn.ModuleList([
            HGTConv(
                in_channels=hidden_dim,
                out_channels=hidden_dim,
                num_node_types=num_node_types,
                num_edge_types=num_edge_types,
                num_heads=num_heads,
                dropout=dropout,
                drop_path_rate=drop_path_rates[i]
            )
            for i in range(num_layers)
        ])
        
        # Final layer norm after all HGT layers
        self.final_norm = nn.LayerNorm(hidden_dim)
        
        # Multi-head attention pooling (replaces simple gated mean pool)
        self.pool = MultiHeadAttentionPooling(hidden_dim, num_heads=4, dropout=dropout)
        
        # Also keep a simple mean pooling branch and combine
        self.pool_gate = nn.Linear(hidden_dim, 1)
        self.pool_linear = nn.Linear(hidden_dim, hidden_dim)
        
        # Classification head (deeper with residual)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout * 0.5),
            nn.Linear(hidden_dim // 2, num_classes)
        )
    
    def _encode(self, x: torch.Tensor, edge_index: torch.Tensor,
                node_types: torch.Tensor, edge_types: torch.Tensor) -> torch.Tensor:
        """Shared encoder: input projection + HGT layers."""
        x = self.input_proj(x)
        
        for layer in self.layers:
            x = layer(x, edge_index, node_types, edge_types)
        
        x = self.final_norm(x)
        return x
    
    def _pool(self, x: torch.Tensor, batch: torch.Tensor) -> torch.Tensor:
        """Dual-path pooling: multi-head attention + gated mean, concatenated."""
        # Path 1: Multi-head attention pooling
        attn_pool = self.pool(x, batch)
        
        # Path 2: Gated mean pooling (complements attention pooling)
        num_graphs = batch.max().item() + 1
        gate = torch.sigmoid(self.pool_gate(x))
        x_weighted = self.pool_linear(x) * gate
        mean_pool = torch.zeros(num_graphs, self.hidden_dim, device=x.device)
        mean_pool.scatter_add_(0, batch.unsqueeze(-1).expand_as(x_weighted), x_weighted)
        counts = torch.bincount(batch, minlength=num_graphs).float().clamp(min=1)
        mean_pool = mean_pool / counts.unsqueeze(-1)
        
        # Concatenate both pooling paths
        return torch.cat([attn_pool, mean_pool], dim=-1)
    
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
        x = self._encode(x, edge_index, node_types, edge_types)
        
        if batch is None:
            batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)
        
        graph_embeds = self._pool(x, batch)
        
        # Classification
        logits = self.classifier(graph_embeds)
        
        return logits
    
    def get_graph_embedding(self, x: torch.Tensor, edge_index: torch.Tensor,
                           node_types: torch.Tensor, edge_types: torch.Tensor,
                           batch: Optional[torch.Tensor] = None) -> torch.Tensor:
        """Get graph-level embeddings without classification."""
        x = self._encode(x, edge_index, node_types, edge_types)
        
        if batch is None:
            batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)
        
        graph_embeds = self._pool(x, batch)
        
        return graph_embeds
