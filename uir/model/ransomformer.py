"""
RansomFormer Module

Implements the dual-stream cross-modal transformer architecture from:
  "RansomFormer: A Cross-Modal Transformer Architecture for Ransomware
   Detection via the Fusion of Byte and API Features"
  Electronics 14(7):1245, 2025.  DOI: 10.3390/electronics14071245

Architecture:
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                     RansomFormerEncoder                                 │
  │                                                                         │
  │  [B, 1, 1024] ──► ByteEncoder (1D CNN) ──────────────► byte_feat [B,256]│
  │                                                              │           │
  │  [B, max_apis] ─► APIEncoder (Transformer) ──► api_feat [B,256]         │
  │                                                              │           │
  │        CrossModalAttention(Q=byte_feat, K=V=api_feat) ──► [B, 256]      │
  └─────────────────────────────────────────────────────────────────────────┘

Key hyperparameters (paper-matched):
  - ByteEncoder:  Conv1d(64 filters, k=5) → Conv1d(128 filters, k=3) → Linear → 256-dim
  - APIEncoder:   Embedding(4096, 256) + 8-layer Transformer (8 heads, ff=512)
  - CrossAttn:    8 heads, dropout=0.2, embed_dim=256
  - Output:       256-dim fused representation
"""

import math
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# ── Constants (paper-matched) ─────────────────────────────────────────────────
BYTE_SEQ_LEN: int = 1024
API_VOCAB_SIZE: int = 4096
MAX_APIS: int = 256
EMBED_DIM: int = 256
N_HEADS: int = 8
N_LAYERS: int = 8
FF_DIM: int = 512
DROPOUT: float = 0.2


# ── 1. Byte Encoder ───────────────────────────────────────────────────────────

class ByteEncoder(nn.Module):
    """
    1D CNN byte encoder (exact paper architecture).

    Input:  [B, 1, 1024]  (single-channel byte sequence, values in [0,1])
    Output: [B, 256]

    Layers:
      Conv1d(1→64,  k=5, p=2) → BatchNorm → ReLU → MaxPool(2)  → [B, 64, 512]
      Conv1d(64→128, k=3, p=1) → BatchNorm → ReLU → MaxPool(2)  → [B, 128, 256]
      AdaptiveAvgPool1d(64)                                       → [B, 128, 64]
      Flatten                                                     → [B, 8192]
      Linear(8192 → 256)                                         → [B, 256]
    """

    def __init__(self, seq_len: int = BYTE_SEQ_LEN, out_dim: int = EMBED_DIM):
        super().__init__()
        self.conv1 = nn.Sequential(
            nn.Conv1d(1, 64, kernel_size=5, padding=2),
            nn.BatchNorm1d(64),
            nn.ReLU(inplace=True),
            nn.MaxPool1d(2),           # → [B, 64, seq_len/2]
        )
        self.conv2 = nn.Sequential(
            nn.Conv1d(64, 128, kernel_size=3, padding=1),
            nn.BatchNorm1d(128),
            nn.ReLU(inplace=True),
            nn.MaxPool1d(2),           # → [B, 128, seq_len/4]
        )
        self.pool = nn.AdaptiveAvgPool1d(64)   # → [B, 128, 64]
        self.fc = nn.Linear(128 * 64, out_dim)
        self.dropout = nn.Dropout(DROPOUT)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [B, 1, seq_len]
        x = self.conv1(x)             # [B, 64, seq_len/2]
        x = self.conv2(x)             # [B, 128, seq_len/4]
        x = self.pool(x)              # [B, 128, 64]
        x = x.flatten(1)             # [B, 8192]
        x = self.dropout(x)
        x = self.fc(x)                # [B, 256]
        return x


# ── 2. API Encoder ────────────────────────────────────────────────────────────

class PositionalEncoding(nn.Module):
    """Standard sinusoidal positional encoding."""

    def __init__(self, d_model: int, max_len: int = 512, dropout: float = DROPOUT):
        super().__init__()
        self.dropout = nn.Dropout(dropout)
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len).unsqueeze(1).float()
        div_term = torch.exp(
            torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model)
        )
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)           # [1, max_len, d_model]
        self.register_buffer("pe", pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [B, seq, d_model]
        x = x + self.pe[:, : x.size(1), :]
        return self.dropout(x)


class APIEncoder(nn.Module):
    """
    Transformer-based API import encoder (exact paper architecture).

    Input:  [B, max_apis]  (token IDs, 0 = padding)
    Output: [B, 256]

    Architecture:
      Embedding(vocab=4096, dim=256)
      PositionalEncoding
      TransformerEncoder(d_model=256, nhead=8, num_layers=8, dim_ff=512)
      Mean pool over non-padding positions → [B, 256]
    """

    def __init__(self,
                 vocab_size: int = API_VOCAB_SIZE,
                 embed_dim: int = EMBED_DIM,
                 n_heads: int = N_HEADS,
                 n_layers: int = N_LAYERS,
                 ff_dim: int = FF_DIM,
                 max_len: int = MAX_APIS,
                 dropout: float = DROPOUT):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.pos_enc = PositionalEncoding(embed_dim, max_len=max_len + 1, dropout=dropout)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=n_heads,
            dim_feedforward=ff_dim,
            dropout=dropout,
            activation="relu",
            batch_first=True,
            norm_first=False,
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=n_layers)
        self.dropout = nn.Dropout(dropout)

    def forward(self, api_tokens: torch.Tensor) -> torch.Tensor:
        # api_tokens: [B, max_apis]  (int64, 0 = padding)
        pad_mask = (api_tokens == 0)                    # [B, max_apis]  True = ignore

        # Guard: if every position is masked PyTorch nested-tensor fast-path
        # raises 'at least one constituent tensor should have non-zero numel'.
        # Force position 0 to be unmasked so every sequence has ≥1 real token.
        pad_mask = pad_mask.clone()
        pad_mask[:, 0] = False                          # position 0 always visible

        x = self.embedding(api_tokens)                  # [B, max_apis, 256]
        x = self.pos_enc(x)                             # [B, max_apis, 256]
        x = self.transformer(x, src_key_padding_mask=pad_mask)  # [B, max_apis, 256]

        # Mean pool over non-padding positions (use the original mask for pooling)
        orig_pad = (api_tokens == 0)
        non_pad  = (~orig_pad).unsqueeze(-1).float()    # [B, max_apis, 1]
        # If truly all-padding, fall back to full mean
        denom = non_pad.sum(dim=1).clamp(min=1)
        x = (x * non_pad).sum(dim=1) / denom           # [B, 256]
        return x


# ── 3. Cross-Modal Attention ──────────────────────────────────────────────────

class CrossModalAttention(nn.Module):
    """
    Single cross-modal attention layer.

    Q = byte features (query)
    K = V = API features (key, value)

    Both inputs are [B, 256] vectors expanded to sequence length 1 for MHA,
    then squeezed back to [B, 256].

    Paper: 8 attention heads, dropout=0.2, embed_dim=256.
    """

    def __init__(self, embed_dim: int = EMBED_DIM, n_heads: int = N_HEADS,
                 dropout: float = DROPOUT):
        super().__init__()
        self.attn = nn.MultiheadAttention(
            embed_dim=embed_dim,
            num_heads=n_heads,
            dropout=dropout,
            batch_first=True,
        )
        self.norm = nn.LayerNorm(embed_dim)
        self.dropout = nn.Dropout(dropout)

        # Optional projection gates to help each modality attend better
        self.q_proj = nn.Linear(embed_dim, embed_dim)
        self.k_proj = nn.Linear(embed_dim, embed_dim)
        self.v_proj = nn.Linear(embed_dim, embed_dim)

    def forward(self, byte_feat: torch.Tensor, api_feat: torch.Tensor) -> torch.Tensor:
        """
        Args:
            byte_feat: [B, 256] — byte encoder output (acts as Query)
            api_feat:  [B, 256] — API encoder output  (acts as Key & Value)

        Returns:
            fused: [B, 256]
        """
        Q = self.q_proj(byte_feat).unsqueeze(1)   # [B, 1, 256]
        K = self.k_proj(api_feat).unsqueeze(1)    # [B, 1, 256]
        V = self.v_proj(api_feat).unsqueeze(1)    # [B, 1, 256]

        attn_out, _ = self.attn(Q, K, V)          # [B, 1, 256]
        attn_out = attn_out.squeeze(1)             # [B, 256]

        # Residual + LayerNorm (add byte_feat as residual connection)
        out = self.norm(byte_feat + self.dropout(attn_out))
        return out


# ── 4. RansomFormerEncoder — full fused module ────────────────────────────────

class RansomFormerEncoder(nn.Module):
    """
    Full RansomFormer dual-stream encoder.

    Inputs:
        pe_bytes   [B, 1, 1024]   — sliding-window byte sequence tensor
        api_tokens [B, max_apis]  — hashed API import token IDs

    Output:
        fused [B, 256]  — multimodal byte+API representation

    This output is concatenated with HGT (512-dim) and LeViT (384-dim)
    embeddings to form the 1152-dim input to the BNN classifier.
    """

    def __init__(self,
                 byte_seq_len: int = BYTE_SEQ_LEN,
                 api_vocab_size: int = API_VOCAB_SIZE,
                 max_apis: int = MAX_APIS,
                 embed_dim: int = EMBED_DIM,
                 n_heads: int = N_HEADS,
                 n_layers: int = N_LAYERS,
                 ff_dim: int = FF_DIM,
                 dropout: float = DROPOUT):
        super().__init__()
        self.byte_encoder = ByteEncoder(seq_len=byte_seq_len, out_dim=embed_dim)
        self.api_encoder = APIEncoder(
            vocab_size=api_vocab_size,
            embed_dim=embed_dim,
            n_heads=n_heads,
            n_layers=n_layers,
            ff_dim=ff_dim,
            max_len=max_apis,
            dropout=dropout,
        )
        self.cross_attn = CrossModalAttention(
            embed_dim=embed_dim,
            n_heads=n_heads,
            dropout=dropout,
        )
        self.out_proj = nn.Sequential(
            nn.Linear(embed_dim, embed_dim),
            nn.LayerNorm(embed_dim),
            nn.GELU(),
        )

    def forward(self, pe_bytes: torch.Tensor, api_tokens: torch.Tensor) -> torch.Tensor:
        """
        Args:
            pe_bytes:   [B, 1, 1024]  float32, values in [0, 1]
            api_tokens: [B, max_apis] int64,   0 = padding

        Returns:
            [B, 256]  fused embedding
        """
        byte_feat = self.byte_encoder(pe_bytes)    # [B, 256]
        api_feat  = self.api_encoder(api_tokens)   # [B, 256]
        fused     = self.cross_attn(byte_feat, api_feat)  # [B, 256]
        return self.out_proj(fused)                # [B, 256]
