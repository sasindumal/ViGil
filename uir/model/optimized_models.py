"""
optimized_models.py — Notebook-Accurate Model Definitions

Contains the exact classes used in traning_notebook/vigil.ipynb:

  OptimizedCNN             — ConvNeXt-Tiny image encoder  → 512-dim
  OptimizedByteEncoder     — 3-layer 1D CNN + attention pool → 256-dim
  OptimizedAPIEncoder      — Pre-LN Transformer + CLS token   → 256-dim
  OptimizedRansomFormerEncoder — ByteEncoder + APIEncoder + cross-attn → 256-dim
  OptimizedHGTLayer        — Single HGT layer (JK connections, learned node/edge type embeddings)
  OptimizedHGT             — Stacked HGT + attention pool → hidden*2 dim  (hidden=384 → 768-dim)
  OptimizedFusion          — Deep Residual MLP classifier
  RestOfModel              — Wraps CNN + RansomFormer + Fusion
  JointMalwareModel        — Full quad-modal model

Hyper-parameters (from vigil.ipynb):
  IN_DIM  = 320   (node feature dim from .feat.pt files)
  HIDDEN  = 384
  LAYERS  = 6
  HEADS   = 8
  FUSED   = 1536   (HGT: 768 + CNN: 512 + RF: 256)
  N_CLS   = 2

MODEL_CONFIG (matches the zip written by the notebook):
  embedding_dim: 320
  hidden_dim:    384
  num_heads:     8
  num_layers:    6
  num_classes:   2
  fused_dim:     1536
  byte_seq_len:  1024
  max_apis:      256
  api_vocab_size:4096
"""

import math
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple
import logging

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# 1.  Image Encoder  —  ConvNeXt-Tiny → 512-dim
# ──────────────────────────────────────────────────────────────────────────────

class OptimizedCNN(nn.Module):
    """ConvNeXt-Tiny image encoder for malware texture extraction.

    Input : [B, 3, 224, 224]  (ImageNet-normalised RGB)
    Output: [B, 512]
    """

    OUT_DIM: int = 512

    def __init__(self, pretrained: bool = True):
        super().__init__()
        import torchvision.models as models

        try:
            base = models.convnext_tiny(
                weights=models.ConvNeXt_Tiny_Weights.IMAGENET1K_V1 if pretrained else None
            )
        except Exception:
            base = models.convnext_tiny(pretrained=pretrained)

        self.features = base.features
        
        # Freeze early stages (stages 0 to 5 of the 8 blocks in ConvNeXt-Tiny features)
        # to prevent overfitting and retain pre-trained low/mid-level representations.
        for i in range(6):
            for param in self.features[i].parameters():
                param.requires_grad = False
                
        self.pool = nn.AdaptiveAvgPool2d((1, 1))
        self.proj = nn.Sequential(
            nn.Linear(768, self.OUT_DIM),
            nn.LayerNorm(self.OUT_DIM),
            nn.GELU(),
            nn.Dropout(0.2),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.features(x)
        x = self.pool(x).flatten(1)   # [B, 768]
        return self.proj(x)            # [B, 512]


# ──────────────────────────────────────────────────────────────────────────────
# 2.  Byte Encoder  —  3-layer 1D CNN + Attention Pooling → 256-dim
# ──────────────────────────────────────────────────────────────────────────────

class OptimizedByteEncoder(nn.Module):
    """1D CNN + Attention Pooling byte encoder.

    Input : [B, 1, 1024]
    Output: [B, 256]
    """

    def __init__(self):
        super().__init__()
        self.cnn = nn.Sequential(
            nn.Conv1d(1, 64, 7, padding=3), nn.BatchNorm1d(64), nn.GELU(), nn.MaxPool1d(2),
            nn.Conv1d(64, 128, 5, padding=2), nn.BatchNorm1d(128), nn.GELU(), nn.MaxPool1d(2),
            nn.Conv1d(128, 256, 3, padding=1), nn.BatchNorm1d(256), nn.GELU(), nn.MaxPool1d(2),
        )
        self.attn_pool = nn.Sequential(
            nn.Linear(256, 128), nn.GELU(), nn.Linear(128, 1)
        )
        self.fc = nn.Sequential(
            nn.Linear(256, 512), nn.GELU(), nn.LayerNorm(512), nn.Dropout(0.3),
            nn.Linear(512, 256),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if x.dim() == 2:
            x = x.unsqueeze(1)        # [B, 1, 1024]
        x = self.cnn(x)               # [B, 256, 128]
        x = x.transpose(1, 2)         # [B, 128, 256]

        scores = self.attn_pool(x).squeeze(-1)          # [B, 128]
        weights = F.softmax(scores, dim=1).unsqueeze(-1) # [B, 128, 1]
        pooled = (x * weights).sum(dim=1)               # [B, 256]

        return self.fc(pooled)         # [B, 256]


# ──────────────────────────────────────────────────────────────────────────────
# 3.  API Encoder  —  Pre-LN Transformer + CLS Token + Local CNN → 256-dim
# ──────────────────────────────────────────────────────────────────────────────

class OptimizedAPIEncoder(nn.Module):
    """Pre-LN Transformer + Local 1D CNN + CLS Token API import encoder.

    Input : [B, max_apis]  (int64, 0 = padding)
    Output: [B, 256]
    """

    def __init__(self, max_len: int = 256):
        super().__init__()
        self.cls_token = nn.Parameter(torch.randn(1, 1, 256) * 0.02)
        self.emb = nn.Embedding(4096, 256, padding_idx=0)
        self.pos_emb = nn.Parameter(torch.randn(1, max_len + 1, 256) * 0.02)

        self.cnn = nn.Sequential(
            nn.Conv1d(256, 256, kernel_size=3, padding=1),
            nn.BatchNorm1d(256), nn.GELU(),
            nn.Conv1d(256, 256, kernel_size=3, padding=1),
            nn.BatchNorm1d(256), nn.GELU(),
        )
        enc_layer = nn.TransformerEncoderLayer(
            256, 8, 1024, 0.2, "gelu", batch_first=True, norm_first=True
        )
        self.tr = nn.TransformerEncoder(enc_layer, num_layers=4)
        self.drop = nn.Dropout(0.3)
        self.norm = nn.LayerNorm(256)

    def forward(self, t: torch.Tensor) -> torch.Tensor:
        B, L = t.shape
        pm = t == 0                                      # [B, L]  True = padding

        x = self.emb(t)                                  # [B, L, 256]
        cls_tokens = self.cls_token.expand(B, -1, -1)    # [B, 1, 256]
        x = torch.cat([cls_tokens, x], dim=1)            # [B, L+1, 256]

        x = x + self.pos_emb[:, : L + 1, :]
        x = self.drop(x)

        # Local CNN branch (on token embeddings only, no CLS)
        x_cnn = self.cnn(self.emb(t).transpose(1, 2)).transpose(1, 2)  # [B, L, 256]
        x[:, 1:, :] = x[:, 1:, :] + x_cnn

        # Extend padding mask to cover the CLS position
        pm_cls = torch.zeros(B, 1, dtype=torch.bool, device=t.device)
        pm_full = torch.cat([pm_cls, pm], dim=1)         # [B, L+1]

        x = self.tr(x, src_key_padding_mask=pm_full)
        x = self.norm(x)

        return x[:, 0, :]                                # [B, 256]  ← CLS output


# ──────────────────────────────────────────────────────────────────────────────
# 4.  RansomFormer Encoder  —  ByteEncoder + APIEncoder + Cross-Attention → 256-dim
# ──────────────────────────────────────────────────────────────────────────────

class OptimizedRansomFormerEncoder(nn.Module):
    """Dual-stream cross-modal encoder (bytes + API imports).

    Inputs:
        pe_bytes   [B, 1, 1024]  float32
        api_tokens [B, 256]      int64
    Output:
        [B, 256]
    """

    def __init__(self):
        super().__init__()
        self.be = OptimizedByteEncoder()
        self.ae = OptimizedAPIEncoder()
        self.attn = nn.MultiheadAttention(256, 8, dropout=0.2, batch_first=True)
        self.norm = nn.LayerNorm(256)
        self.drop = nn.Dropout(0.3)
        self.qp = nn.Linear(256, 256)
        self.kp = nn.Linear(256, 256)
        self.vp = nn.Linear(256, 256)
        self.out = nn.Sequential(
            nn.Linear(256, 256), nn.LayerNorm(256), nn.GELU(), nn.Dropout(0.2)
        )

    def forward(self, b: torch.Tensor, a: torch.Tensor) -> torch.Tensor:
        bf = self.be(b)                                  # [B, 256]
        af = self.ae(a)                                  # [B, 256]
        Q = self.qp(bf).unsqueeze(1)                     # [B, 1, 256]
        K = self.kp(af).unsqueeze(1)
        V = self.vp(af).unsqueeze(1)
        ao, _ = self.attn(Q, K, V)
        ao = ao.squeeze(1)                               # [B, 256]
        return self.out(self.norm(bf + self.drop(ao)))   # [B, 256]


# ──────────────────────────────────────────────────────────────────────────────
# 5.  Optimized HGT
# ──────────────────────────────────────────────────────────────────────────────

class OptimizedHGTLayer(nn.Module):
    """Single HGT layer with learned node/edge-type embeddings and JK residual."""

    def __init__(self, h: int, heads: int,
                 num_node_types: int = 64, num_edge_types: int = 64):
        super().__init__()
        self.heads = heads
        self.d = h // heads
        assert h % heads == 0

        self.nt_emb  = nn.Embedding(num_node_types, h)
        self.et_bias = nn.Embedding(num_edge_types, heads)

        self.WQ  = nn.Linear(h, h)
        self.WK  = nn.Linear(h, h)
        self.WV  = nn.Linear(h, h)
        self.out = nn.Linear(h, h)

        self.norm1 = nn.LayerNorm(h)
        self.norm2 = nn.LayerNorm(h)
        self.drop  = nn.Dropout(0.1)

        self.alpha = nn.Parameter(torch.ones(1) * 0.1)

    def forward(self, x: torch.Tensor,
                ei: torch.Tensor,
                nt: torch.Tensor,
                et: torch.Tensor) -> torch.Tensor:
        if ei.size(1) == 0:
            return x

        nt = nt.clamp(0, self.nt_emb.num_embeddings - 1)
        x  = x + self.nt_emb(nt)
        res = x
        x  = self.norm1(x)

        s, d = ei[0], ei[1]

        q_all = self.WQ(x).view(-1, self.heads, self.d)
        k_all = self.WK(x).view(-1, self.heads, self.d)
        v_all = self.WV(x).view(-1, self.heads, self.d)

        q = q_all[d]; k = k_all[s]; v = v_all[s]

        attn = (q * k).sum(-1) / math.sqrt(self.d)      # [E, H]

        if et is not None and et.numel() > 0:
            et = et.clamp(0, self.et_bias.num_embeddings - 1)
            attn = attn + self.et_bias(et)

        # Force float32 to prevent AMP underflow
        attn = attn.float()
        attn_max = torch.full(
            (x.size(0), self.heads), -1e9, device=x.device, dtype=torch.float32
        )
        attn_max.scatter_reduce_(
            0, d.unsqueeze(-1).expand_as(attn), attn, reduce="amax"
        )

        attn_exp = torch.exp(attn - attn_max[d])

        attn_sum = torch.zeros(
            x.size(0), self.heads, device=x.device, dtype=torch.float32
        )
        attn_sum.scatter_add_(0, d.unsqueeze(-1).expand_as(attn), attn_exp)

        attn_norm = attn_exp / (attn_sum[d] + 1e-8)
        attn_norm = self.drop(attn_norm)

        msg = v * attn_norm.unsqueeze(-1)

        agg = torch.zeros(
            x.size(0), self.heads, self.d,
            device=x.device, dtype=msg.dtype
        )
        agg.scatter_add_(
            0, d.unsqueeze(-1).unsqueeze(-1).expand_as(msg), msg
        )
        agg = agg.view(x.size(0), -1)

        return self.norm2(res + self.alpha * self.out(agg))


class OptimizedHGT(nn.Module):
    """Optimized Heterogeneous Graph Transformer with JK connections.

    Input : node features [N, in_d]
    Output: graph embeddings [B, hidden * 2]   (attention pool + JK)

    With HIDDEN=384: output is [B, 768].
    """

    def __init__(self, in_d: int, hidden: int, layers: int, heads: int,
                 num_node_types: int = 64, num_edge_types: int = 64):
        super().__init__()
        self.proj = nn.Sequential(
            nn.Linear(in_d, hidden), nn.GELU(), nn.LayerNorm(hidden), nn.Dropout(0.1)
        )
        self.layers_ = nn.ModuleList([
            OptimizedHGTLayer(hidden, heads, num_node_types, num_edge_types)
            for _ in range(layers)
        ])

        self.jk_weight = nn.Parameter(torch.ones(layers + 1))

        self.pool_q = nn.Linear(hidden, hidden)
        self.pool_k = nn.Linear(hidden, 1)
        
        # Projection layer to map concatenated pooling (Attention + Mean + Max) back to hidden space
        self.pool_proj = nn.Linear(hidden * 3, hidden)

        self.out = nn.Sequential(
            nn.Linear(hidden, hidden), nn.GELU(), nn.LayerNorm(hidden), nn.Dropout(0.2),
            nn.Linear(hidden, hidden * 2),          # → 768-dim when hidden=384
        )

    def get_graph_embedding(self,
                            x: torch.Tensor,
                            ei: torch.Tensor,
                            nt: torch.Tensor,
                            et: torch.Tensor,
                            batch: torch.Tensor) -> torch.Tensor:
        x = self.proj(x)
        layer_outs = [x]
        for layer in self.layers_:
            x = layer(x, ei, nt, et)
            layer_outs.append(x)

        jk_w = F.softmax(self.jk_weight, dim=0)
        x = sum(layer_outs[i] * jk_w[i] for i in range(len(layer_outs)))

        B = int(batch.max().item()) + 1

        # 1. Gated Attention pooling
        k = self.pool_k(x).float()                       # [N, 1]
        k_max = torch.full((B, 1), -1e9, device=x.device, dtype=torch.float32)
        k_max.scatter_reduce_(0, batch.unsqueeze(-1), k, reduce="amax")

        k_exp = torch.exp(k - k_max[batch])
        k_sum = torch.zeros(B, 1, device=x.device, dtype=torch.float32)
        k_sum.scatter_add_(0, batch.unsqueeze(-1).expand_as(k), k_exp)

        attn = k_exp / (k_sum[batch] + 1e-8)

        msg = x * attn
        p_attn = torch.zeros(B, x.size(1), device=x.device, dtype=msg.dtype)
        p_attn.scatter_add_(0, batch.unsqueeze(-1).expand_as(msg), msg)

        # 2. Mean pooling
        ones = torch.ones_like(k)
        counts = torch.zeros(B, 1, device=x.device, dtype=x.dtype)
        counts.scatter_add_(0, batch.unsqueeze(-1), ones)
        p_mean = torch.zeros(B, x.size(1), device=x.device, dtype=x.dtype)
        p_mean.scatter_add_(0, batch.unsqueeze(-1).expand_as(x), x)
        p_mean = p_mean / (counts + 1e-8)

        # 3. Max pooling
        p_max = torch.full((B, x.size(1)), -1e9, device=x.device, dtype=x.dtype)
        p_max.scatter_reduce_(0, batch.unsqueeze(-1).expand_as(x), x, reduce="amax")
        p_max = torch.where(p_max == -1e9, torch.zeros_like(p_max), p_max)

        # Combine pooling strategies and project back to hidden
        p_combined = torch.cat([p_attn, p_mean, p_max], dim=-1)
        p = self.pool_proj(p_combined)

        return self.out(p)                               # [B, hidden*2]


# ──────────────────────────────────────────────────────────────────────────────
# 6.  Deep Residual MLP Fusion Head
# ──────────────────────────────────────────────────────────────────────────────

class SEBlock(nn.Module):
    """Squeeze-and-Excitation block for Channel-wise Multi-modal Attention."""

    def __init__(self, channels: int, reduction: int = 16):
        super().__init__()
        self.fc = nn.Sequential(
            nn.Linear(channels, channels // reduction, bias=False),
            nn.GELU(),
            nn.Linear(channels // reduction, channels, bias=False),
            nn.Sigmoid()
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x * self.fc(x)


class OptimizedFusion(nn.Module):
    """Deep Residual MLP classifier (replaces BNN for notebook-trained models).

    Input : [B, fused_dim]  (default fused_dim=1536)
    Output: [B, n_cls]
    """

    def __init__(self, in_f: int, n_cls: int = 2, hidden: int = 1024):
        super().__init__()
        self.se    = SEBlock(in_f, reduction=16)
        self.fc1   = nn.Linear(in_f, hidden)
        self.act1  = nn.GELU()
        self.norm1 = nn.LayerNorm(hidden)
        self.drop1 = nn.Dropout(0.4)

        self.fc2   = nn.Linear(hidden, hidden)
        self.act2  = nn.GELU()
        self.norm2 = nn.LayerNorm(hidden)
        self.drop2 = nn.Dropout(0.4)

        self.fc3   = nn.Linear(hidden, hidden // 2)
        self.act3  = nn.GELU()
        self.norm3 = nn.LayerNorm(hidden // 2)

        self.head  = nn.Linear(hidden // 2, n_cls)

    def forward(self, x: torch.Tensor, sample: bool = True) -> torch.Tensor:
        x   = self.se(x)
        res = self.fc1(x)
        x   = self.drop1(self.norm1(self.act1(res)))
        res2 = self.fc2(x)
        if res.shape == res2.shape:
            x = res + res2
        x = self.drop2(self.norm2(self.act2(x)))
        x = self.norm3(self.act3(self.fc3(x)))
        return self.head(x)


# ──────────────────────────────────────────────────────────────────────────────
# 7.  RestOfModel + JointMalwareModel
# ──────────────────────────────────────────────────────────────────────────────

class RestOfModel(nn.Module):
    """Groups the three non-HGT encoders + fusion head (runs on dense device)."""

    def __init__(self, cnn: nn.Module, rf: nn.Module, dnn: nn.Module):
        super().__init__()
        self.cnn = cnn
        self.rf  = rf
        self.dnn = dnn

    def forward(self,
                g: torch.Tensor,
                imgs: torch.Tensor,
                pb: torch.Tensor,
                at: torch.Tensor,
                sample: bool = True) -> torch.Tensor:
        i = self.cnn(imgs)            # [B, 512]
        r = self.rf(pb, at)           # [B, 256]
        return self.dnn(torch.cat([g, i, r], dim=-1), sample)  # [B, 2]


class JointMalwareModel(nn.Module):
    """Full Quad-Modal JointMalwareModel matching vigil.ipynb.

    Forward signature:
        forward(x, ei, nt, et, bi, imgs, pb, at, sample=True) → logits [B, 2]

    predict_with_confidence:
        Returns (preds, confidence, variance) via Monte Carlo sampling.
    """

    def __init__(self, hgt: nn.Module, rest: nn.Module):
        super().__init__()
        self.hgt  = hgt
        self.rest = rest
        try:
            self.rest_device = next(self.rest.parameters()).device
        except StopIteration:
            self.rest_device = torch.device("cpu")

    def forward(self,
                x: torch.Tensor,
                ei: torch.Tensor,
                nt: torch.Tensor,
                et: torch.Tensor,
                bi: torch.Tensor,
                imgs: torch.Tensor,
                pb: torch.Tensor,
                at: torch.Tensor,
                sample: bool = True) -> torch.Tensor:
        g = self.hgt.get_graph_embedding(x, ei, nt, et, bi)
        if g.device != self.rest_device:
            g = g.to(self.rest_device)
        return self.rest(g, imgs, pb, at, sample)

    @torch.no_grad()
    def predict_with_confidence(self,
                                x: torch.Tensor,
                                ei: torch.Tensor,
                                nt: torch.Tensor,
                                et: torch.Tensor,
                                bi: torch.Tensor,
                                imgs: torch.Tensor,
                                pb: torch.Tensor,
                                at: torch.Tensor,
                                num_samples: int = 20
                                ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Monte Carlo inference (dropout active → uncertainty estimate).

        Returns:
            preds      [B]  — predicted class index
            confidence [B]  — probability of predicted class
            variance   [B]  — epistemic uncertainty variance
        """
        self.eval()
        probs = [
            torch.softmax(self.forward(x, ei, nt, et, bi, imgs, pb, at, sample=True), dim=-1)
            for _ in range(num_samples)
        ]
        probs = torch.stack(probs)           # [T, B, C]
        mp    = probs.mean(0)                # [B, C]
        pred  = mp.argmax(-1)                # [B]
        conf  = mp[torch.arange(pred.size(0)), pred]
        var   = probs[:, torch.arange(pred.size(0)), pred].var(0)
        return pred, conf, var


# ──────────────────────────────────────────────────────────────────────────────
# 8.  Factory helper
# ──────────────────────────────────────────────────────────────────────────────

# Canonical hyper-parameters (from vigil.ipynb MODEL_CONFIG)
NOTEBOOK_CFG = {
    "embedding_dim":  320,
    "hidden_dim":     384,
    "num_heads":      8,
    "num_layers":     6,
    "num_classes":    2,
    "fused_dim":      1536,   # 768 (HGT) + 512 (CNN) + 256 (RF)
    "byte_seq_len":   1024,
    "max_apis":       256,
    "api_vocab_size": 4096,
    "label_map":      {"0": "BENIGN", "1": "MALWARE"},
    "architecture":   "OptimizedHGT + ConvNeXt + AttentionByte + CLSTransformerAPI → DeepResMLP",
}


def build_model(cfg: dict = None, device: torch.device = None) -> JointMalwareModel:
    """Build a JointMalwareModel from config dict.

    Args:
        cfg:    Config dict (keys as in NOTEBOOK_CFG).
                Defaults to NOTEBOOK_CFG if None.
        device: Target device for all sub-models.

    Returns:
        JointMalwareModel ready for load_state_dict.
    """
    if cfg is None:
        cfg = NOTEBOOK_CFG

    if device is None:
        device = torch.device("cpu")

    in_d   = cfg.get("embedding_dim", 320)
    hidden = cfg.get("hidden_dim",    384)
    layers = cfg.get("num_layers",      6)
    heads  = cfg.get("num_heads",       8)
    fused  = cfg.get("fused_dim",    1536)
    n_cls  = cfg.get("num_classes",     2)

    hgt_model = OptimizedHGT(in_d, hidden, layers, heads).to(device)
    cnn_model = OptimizedCNN(pretrained=False).to(device)
    rf_model  = OptimizedRansomFormerEncoder().to(device)
    dnn_model = OptimizedFusion(fused, n_cls, hidden=1024).to(device)

    rest_model = RestOfModel(cnn_model, rf_model, dnn_model)
    model      = JointMalwareModel(hgt_model, rest_model)
    return model
