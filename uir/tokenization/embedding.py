"""
Embedding Module

Creates embeddings for CPG nodes.
"""

import torch
import torch.nn as nn
from typing import Dict, List, Optional, Any
import logging

from .vocabulary import SemanticVocabulary, get_vocabulary
from .bpe_tokenizer import BPETokenizer
from .value_abstractor import ValueAbstractor
from ..cpg.schema import CPGNode, NodeType

logger = logging.getLogger(__name__)


class EmbeddingLayer(nn.Module):
    """
    Creates embeddings for CPG nodes.
    
    Combines:
    - Node type embedding
    - Semantic token embedding
    - BPE embedding for identifiers
    - Positional encoding
    """
    
    def __init__(self, 
                 embedding_dim: int = 256,
                 vocab: Optional[SemanticVocabulary] = None,
                 bpe_tokenizer: Optional[BPETokenizer] = None):
        super().__init__()
        
        self.embedding_dim = embedding_dim
        self.vocab = vocab or get_vocabulary()
        self.bpe = bpe_tokenizer or BPETokenizer()
        self.abstractor = ValueAbstractor()
        
        # Node type embeddings
        self.node_type_embedding = nn.Embedding(
            num_embeddings=len(NodeType),
            embedding_dim=embedding_dim
        )
        
        # Semantic vocabulary embeddings
        self.vocab_embedding = nn.Embedding(
            num_embeddings=self.vocab.size,
            embedding_dim=embedding_dim,
            padding_idx=self.vocab.pad_id
        )
        
        # BPE token embeddings
        self.bpe_embedding = nn.Embedding(
            num_embeddings=self.bpe.size + 1000,  # Extra space for training
            embedding_dim=embedding_dim // 2,
            padding_idx=0
        )
        
        # Projection layers
        self.type_proj = nn.Linear(embedding_dim, embedding_dim)
        self.name_proj = nn.Linear(embedding_dim // 2, embedding_dim // 2)
        self.combine = nn.Linear(embedding_dim + embedding_dim // 2, embedding_dim)
        
        # Layer norm
        self.layer_norm = nn.LayerNorm(embedding_dim)
    
    def forward(self, nodes: List[CPGNode]) -> torch.Tensor:
        """
        Compute embeddings for a list of nodes.
        
        Args:
            nodes: List of CPGNode objects
            
        Returns:
            Tensor of shape (num_nodes, embedding_dim)
        """
        if not nodes:
            return torch.zeros(0, self.embedding_dim)
        
        # Get node type IDs
        type_ids = torch.tensor([
            list(NodeType).index(n.node_type) 
            for n in nodes
        ], dtype=torch.long)
        
        # Get type embeddings
        type_emb = self.node_type_embedding(type_ids)
        type_emb = self.type_proj(type_emb)
        
        # Get semantic embeddings for each node
        semantic_embs = []
        for node in nodes:
            sem_id = self._get_semantic_id(node)
            semantic_embs.append(sem_id)
        
        semantic_ids = torch.tensor(semantic_embs, dtype=torch.long)
        vocab_emb = self.vocab_embedding(semantic_ids)
        
        # Combine type and semantic embeddings
        combined_emb = type_emb + vocab_emb
        
        # Get name embeddings using BPE
        name_embs = []
        for node in nodes:
            name_emb = self._embed_name(node.name)
            name_embs.append(name_emb)
        
        name_emb_tensor = torch.stack(name_embs)
        name_emb_proj = self.name_proj(name_emb_tensor)
        
        # Concatenate and project
        full_emb = torch.cat([combined_emb, name_emb_proj], dim=-1)
        output = self.combine(full_emb)
        output = self.layer_norm(output)
        
        return output
    
    def _get_semantic_id(self, node: CPGNode) -> int:
        """Get semantic vocabulary ID for a node."""
        # Encode based on node type
        if node.operator_type:
            return self.vocab.encode_operator(node.operator_type.value.split('.')[-1])
        
        if node.control_type:
            token = f"<ctrl>.{node.control_type.value}"
            return self.vocab.encode(token)
        
        if node.node_type == NodeType.LITERAL:
            if node.value is not None:
                abstract = self.abstractor.abstract(node.value)
                if self.vocab.contains(abstract):
                    return self.vocab.encode(abstract)
                # Try as integer
                try:
                    val = int(node.value)
                    return self.vocab.encode_integer(val)
                except (ValueError, TypeError):
                    pass
            return self.vocab.unk_id
        
        # Default to node type
        return self.vocab.encode_node_type(node.node_type.value)
    
    def _embed_name(self, name: str) -> torch.Tensor:
        """Embed a node name using BPE."""
        if not name:
            return torch.zeros(self.embedding_dim // 2)
        
        # Get BPE token IDs
        token_ids = self.bpe.encode(name)[:8]  # Limit to 8 subwords
        
        if not token_ids:
            return torch.zeros(self.embedding_dim // 2)
        
        # Get embeddings
        ids = torch.tensor(token_ids, dtype=torch.long)
        embs = self.bpe_embedding(ids)
        
        # Pool (mean)
        return embs.mean(dim=0)
    
    def get_embedding_dim(self) -> int:
        """Get the output embedding dimension."""
        return self.embedding_dim


def create_node_features(nodes: List[CPGNode], embedding_layer: EmbeddingLayer) -> torch.Tensor:
    """
    Create feature tensor for a list of nodes.
    
    Args:
        nodes: List of CPGNode objects
        embedding_layer: EmbeddingLayer instance
        
    Returns:
        Feature tensor of shape (num_nodes, embedding_dim)
    """
    with torch.no_grad():
        return embedding_layer(nodes)
