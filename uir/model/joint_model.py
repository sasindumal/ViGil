"""
Joint Quad-Modal Malware Detection Model

Four complementary representations of a PE binary:
  1. CPG Graph         → HeterogeneousGraphTransformer (HGT)        → 512-dim
  2. Grayscale Image   → ResNet-50 (pretrained, fine-tune layer4)   → 384-dim
  3. PE Byte Sequence  → RansomFormer ByteEncoder (1D CNN)          ┐
  4. API Import Names  → RansomFormer APIEncoder (Transformer)      ┘ → 256-dim
                         Cross-Modal Attention (bytes ↔ API)

Fused embedding: 512 + 384 + 256 = 1152-dim → BNN → prediction + confidence

References:
  - RansomFormer: Electronics 14(7):1245, 2025. DOI: 10.3390/electronics14071245
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple, Optional
import math
import logging

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Bayesian Neural Network (classification head)
# ─────────────────────────────────────────────────────────────────────────────

class BayesianLinear(nn.Module):
    """Mean-Field Variational Bayesian Linear Layer."""

    def __init__(self, in_features: int, out_features: int, prior_sigma: float = 0.1):
        super().__init__()
        self.in_features = in_features
        self.out_features = out_features
        self.prior_sigma = prior_sigma

        self.weight_mu  = nn.Parameter(torch.Tensor(out_features, in_features))
        self.weight_rho = nn.Parameter(torch.Tensor(out_features, in_features))
        self.bias_mu    = nn.Parameter(torch.Tensor(out_features))
        self.bias_rho   = nn.Parameter(torch.Tensor(out_features))
        self.reset_parameters()

    def reset_parameters(self):
        nn.init.kaiming_uniform_(self.weight_mu, a=math.sqrt(5))
        nn.init.constant_(self.weight_rho, -3.0)
        fan_in, _ = nn.init._calculate_fan_in_and_fan_out(self.weight_mu)
        bound = 1 / math.sqrt(fan_in) if fan_in > 0 else 0
        nn.init.uniform_(self.bias_mu, -bound, bound)
        nn.init.constant_(self.bias_rho, -3.0)

    def forward(self, x: torch.Tensor, sample: bool = True) -> torch.Tensor:
        if self.training or sample:
            weight_sigma = torch.log1p(torch.exp(self.weight_rho))
            weight       = self.weight_mu + weight_sigma * torch.randn_like(self.weight_mu)
            bias_sigma   = torch.log1p(torch.exp(self.bias_rho))
            bias         = self.bias_mu + bias_sigma * torch.randn_like(self.bias_mu)
        else:
            weight, bias = self.weight_mu, self.bias_mu
        return F.linear(x, weight, bias)

    def kl_divergence(self) -> torch.Tensor:
        weight_sigma = torch.log1p(torch.exp(self.weight_rho))
        bias_sigma   = torch.log1p(torch.exp(self.bias_rho))
        kl_w = 0.5 * (2 * torch.log(self.prior_sigma / (weight_sigma + 1e-8))
                       + (weight_sigma**2 + self.weight_mu**2) / self.prior_sigma**2 - 1.0).sum()
        kl_b = 0.5 * (2 * torch.log(self.prior_sigma / (bias_sigma + 1e-8))
                       + (bias_sigma**2 + self.bias_mu**2) / self.prior_sigma**2 - 1.0).sum()
        return kl_w + kl_b


class BayesianClassifier(nn.Module):
    """Two-layer BNN classification head."""

    def __init__(self, in_features: int, num_classes: int = 2,
                 hidden_dim: int = 256, prior_sigma: float = 0.1):
        super().__init__()
        self.fc1  = BayesianLinear(in_features, hidden_dim, prior_sigma)
        self.act1 = nn.GELU()
        self.fc2  = BayesianLinear(hidden_dim, num_classes, prior_sigma)

    def forward(self, x: torch.Tensor, sample: bool = True) -> torch.Tensor:
        return self.fc2(self.act1(self.fc1(x, sample)), sample)

    def kl_divergence(self) -> torch.Tensor:
        return self.fc1.kl_divergence() + self.fc2.kl_divergence()


# ─────────────────────────────────────────────────────────────────────────────
# Quad-Modal Joint Model
# ─────────────────────────────────────────────────────────────────────────────

class JointMalwareModel(nn.Module):
    """
    Unified quad-modal malware detection model.

    Streams:
      hgt          — HGT over CPG graph                   → [B, 512]
      resnet       — ResNet-50 over grayscale image        → [B, 384]
      ransomformer — RansomFormer (bytes + API imports)   → [B, 256]

    Fused dim: 512 + 384 + 256 = 1152  → BNN → [B, num_classes]
    """

    def __init__(self,
                 hgt_model: nn.Module,
                 resnet_model: nn.Module,
                 ransomformer_model: nn.Module,
                 bnn_classifier: nn.Module):
        super().__init__()
        self.hgt          = hgt_model
        self.resnet       = resnet_model
        self.ransomformer = ransomformer_model
        self.bnn          = bnn_classifier

    def forward(self,
                x: torch.Tensor,
                edge_index: torch.Tensor,
                node_types: torch.Tensor,
                edge_types: torch.Tensor,
                batch_idx: torch.Tensor,
                images: torch.Tensor,
                pe_bytes: torch.Tensor,
                api_tokens: torch.Tensor,
                sample: bool = True) -> torch.Tensor:
        """
        Args:
            x:           Node features          [N, in_dim]
            edge_index:  Graph edges             [2, E]
            node_types:  Node type IDs           [N]
            edge_types:  Edge type IDs           [E]
            batch_idx:   Batch index per node    [N]
            images:      RGB grayscale images    [B, 3, 224, 224]
            pe_bytes:    Byte sequences          [B, 1, 1024]
            api_tokens:  API import token IDs   [B, max_apis]
            sample:      Whether to sample BNN weights

        Returns:
            logits  [B, num_classes]
        """
        # Stream 1: CPG graph → HGT
        graph_embeds = self.hgt.get_graph_embedding(
            x, edge_index, node_types, edge_types, batch_idx)          # [B, 512]

        # Stream 2: Grayscale image → ResNet-50
        image_embeds = self.resnet(images)                             # [B, 384]

        # Stream 3: PE bytes + API imports → RansomFormer
        ransomformer_embeds = self.ransomformer(pe_bytes, api_tokens)  # [B, 256]

        # Fusion & BNN classification
        fused  = torch.cat([graph_embeds, image_embeds, ransomformer_embeds], dim=-1)  # [B, 1152]
        logits = self.bnn(fused, sample=sample)
        return logits

    @torch.no_grad()
    def predict_with_confidence(self,
                                x: torch.Tensor,
                                edge_index: torch.Tensor,
                                node_types: torch.Tensor,
                                edge_types: torch.Tensor,
                                batch_idx: torch.Tensor,
                                images: torch.Tensor,
                                pe_bytes: torch.Tensor,
                                api_tokens: torch.Tensor,
                                num_samples: int = 20
                                ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Monte Carlo BNN inference.

        Returns:
            preds:      Class predictions (0=benign, 1=malware)  [B]
            confidence: Probability of predicted class            [B]
            variance:   Epistemic uncertainty variance            [B]
        """
        self.eval()
        all_probs = []
        for _ in range(num_samples):
            logits = self.forward(x, edge_index, node_types, edge_types,
                                  batch_idx, images, pe_bytes, api_tokens,
                                  sample=True)
            all_probs.append(torch.softmax(logits, dim=-1))

        all_probs  = torch.stack(all_probs, dim=0)   # [T, B, C]
        mean_probs = all_probs.mean(dim=0)            # [B, C]
        preds      = mean_probs.argmax(dim=-1)        # [B]
        confidence = mean_probs[torch.arange(preds.size(0)), preds]

        chosen_probs = all_probs[:, torch.arange(preds.size(0)), preds]
        variance     = chosen_probs.var(dim=0)        # [B]

        return preds, confidence, variance
