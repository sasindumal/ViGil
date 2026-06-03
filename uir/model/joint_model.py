"""
Joint Multimodal Malware Detection Model

Combines CPG graph representation (HGT) and Grayscale Image representation (LeViT-128S with LoRA).
The fused embeddings are classified using a Bayesian Neural Network (BNN) with Monte Carlo sampling.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple, Dict, Any, Optional
import math
import logging

logger = logging.getLogger(__name__)


class LoraLevitFeatureExtractor(nn.Module):
    """
    Feature extractor utilizing facebook/levit-128S pretrained model.
    Includes PEFT LoRA tuning for parameter efficiency and high accuracy.
    Includes a fallback CNN model for offline/local standalone robustness.
    """
    
    def __init__(self, pretrained_model_name: str = "facebook/levit-128S", lora_r: int = 8, lora_alpha: int = 16):
        super().__init__()
        self.is_fallback = False
        
        try:
            from transformers import LevitModel
            from peft import LoraConfig, get_peft_model
            
            logger.info(f"Loading pretrained model: {pretrained_model_name}")
            base_model = LevitModel.from_pretrained(pretrained_model_name)
            
            # Configure LoRA targeting query, key, value, and projection linear blocks
            peft_config = LoraConfig(
                r=lora_r,
                lora_alpha=lora_alpha,
                target_modules=["qkv", "projection", "linear", "keyval", "attention.queries", "attention.keys", "attention.values"],
                lora_dropout=0.1,
                bias="none"
            )
            
            self.model = get_peft_model(base_model, peft_config)
            logger.info("Successfully loaded LeViT model with PEFT LoRA")
            
        except Exception as e:
            logger.warning(f"Could not load LeViT model or PEFT from HuggingFace hub ({e}). Falling back to dynamic CNN feature extractor.")
            self.is_fallback = True
            
            # Dynamic CNN fallback that outputs identical 384 dimensions
            self.fallback_conv = nn.Sequential(
                nn.Conv2d(3, 16, 3, padding=1),
                nn.BatchNorm2d(16),
                nn.GELU(),
                nn.MaxPool2d(2), # 112
                
                nn.Conv2d(16, 32, 3, padding=1),
                nn.BatchNorm2d(32),
                nn.GELU(),
                nn.MaxPool2d(2), # 56
                
                nn.Conv2d(32, 64, 3, padding=1),
                nn.BatchNorm2d(64),
                nn.GELU(),
                nn.MaxPool2d(2), # 28
                
                nn.Conv2d(64, 128, 3, padding=1),
                nn.BatchNorm2d(128),
                nn.GELU(),
                nn.AdaptiveAvgPool2d((1, 1))
            )
            self.fallback_fc = nn.Linear(128, 384)
            
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x shape: [B, 3, 224, 224]
        if self.is_fallback:
            features = self.fallback_conv(x).squeeze(-1).squeeze(-1)
            return self.fallback_fc(features)
        else:
            outputs = self.model(x)
            # Levit last_hidden_state is of shape [B, N, 384]
            # Perform global average pool over spatial/sequence dimensions
            features = outputs.last_hidden_state.mean(dim=1)
            return features


class BayesianLinear(nn.Module):
    """
    Mean-Field Variational Bayesian Linear Layer.
    Weights and biases are represented as Gaussian distributions.
    """
    
    def __init__(self, in_features: int, out_features: int, prior_sigma: float = 0.1):
        super().__init__()
        self.in_features = in_features
        self.out_features = out_features
        self.prior_sigma = prior_sigma
        
        # Variational parameters: Mean (mu) and Log-variance (rho)
        self.weight_mu = nn.Parameter(torch.Tensor(out_features, in_features))
        self.weight_rho = nn.Parameter(torch.Tensor(out_features, in_features))
        
        self.bias_mu = nn.Parameter(torch.Tensor(out_features))
        self.bias_rho = nn.Parameter(torch.Tensor(out_features))
        
        self.reset_parameters()
        
    def reset_parameters(self):
        # Kaiming uniform init for mu
        nn.init.kaiming_uniform_(self.weight_mu, a=math.sqrt(5))
        # Start variance small (rho = -3.0 corresponds to standard deviation around 0.05)
        nn.init.constant_(self.weight_rho, -3.0)
        
        fan_in, _ = nn.init._calculate_fan_in_and_fan_out(self.weight_mu)
        bound = 1 / math.sqrt(fan_in) if fan_in > 0 else 0
        nn.init.uniform_(self.bias_mu, -bound, bound)
        nn.init.constant_(self.bias_rho, -3.0)
        
    def forward(self, x: torch.Tensor, sample: bool = True) -> torch.Tensor:
        if self.training or sample:
            # Reparameterization trick: w = mu + sigma * epsilon
            weight_sigma = torch.log1p(torch.exp(self.weight_rho))
            weight_epsilon = torch.randn_like(self.weight_mu)
            weight = self.weight_mu + weight_sigma * weight_epsilon
            
            bias_sigma = torch.log1p(torch.exp(self.bias_rho))
            bias_epsilon = torch.randn_like(self.bias_mu)
            bias = self.bias_mu + bias_sigma * bias_epsilon
        else:
            # Use posterior mean for deterministic evaluation
            weight = self.weight_mu
            bias = self.bias_mu
            
        return F.linear(x, weight, bias)
        
    def kl_divergence(self) -> torch.Tensor:
        """
        Calculates analytical KL divergence between q(w) and prior p(w) = N(0, prior_sigma^2).
        """
        weight_sigma = torch.log1p(torch.exp(self.weight_rho))
        bias_sigma = torch.log1p(torch.exp(self.bias_rho))
        
        # KL divergence for weights
        kl_w = 0.5 * (
            2 * torch.log(self.prior_sigma / (weight_sigma + 1e-8))
            + (weight_sigma**2 + self.weight_mu**2) / (self.prior_sigma**2)
            - 1.0
        ).sum()
        
        # KL divergence for biases
        kl_b = 0.5 * (
            2 * torch.log(self.prior_sigma / (bias_sigma + 1e-8))
            + (bias_sigma**2 + self.bias_mu**2) / (self.prior_sigma**2)
            - 1.0
        ).sum()
        
        return kl_w + kl_b


class BayesianClassifier(nn.Module):
    """
    Bayesian Neural Network classification head.
    Combines input features and performs classification using Bayesian linear layers.
    """
    
    def __init__(self, in_features: int, num_classes: int = 2, hidden_dim: int = 256, prior_sigma: float = 0.1):
        super().__init__()
        self.fc1 = BayesianLinear(in_features, hidden_dim, prior_sigma)
        self.act1 = nn.GELU()
        self.fc2 = BayesianLinear(hidden_dim, num_classes, prior_sigma)
        
    def forward(self, x: torch.Tensor, sample: bool = True) -> torch.Tensor:
        x = self.fc1(x, sample)
        x = self.act1(x)
        x = self.fc2(x, sample)
        return x
        
    def kl_divergence(self) -> torch.Tensor:
        """Total KL divergence from both layers."""
        return self.fc1.kl_divergence() + self.fc2.kl_divergence()


class JointMalwareModel(nn.Module):
    """
    Unified multimodal model combining HGT and LeViT-LoRA encoders with BNN classification.
    """
    
    def __init__(self, hgt_model: nn.Module, levit_model: nn.Module, bnn_classifier: nn.Module):
        super().__init__()
        self.hgt = hgt_model
        self.levit = levit_model
        self.bnn = bnn_classifier
        
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor,
                node_types: torch.Tensor, edge_types: torch.Tensor,
                batch_idx: torch.Tensor, images: torch.Tensor,
                sample: bool = True) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: Node features [N, in_dim]
            edge_index: Graph edge indices [2, E]
            node_types: Node type IDs [N]
            edge_types: Edge type IDs [E]
            batch_idx: Batch indices mapping nodes to graphs [N]
            images: Batched grayscale images [B, 3, 224, 224]
            sample: True to sample weights from variational posterior distributions
            
        Returns:
            Logits tensor [B, num_classes]
        """
        # HGT graph embedding path (512-dim output)
        graph_embeds = self.hgt.get_graph_embedding(x, edge_index, node_types, edge_types, batch_idx)
        
        # LeViT image embedding path (384-dim output)
        image_embeds = self.levit(images)
        
        # Multimodal feature fusion
        fused_embeds = torch.cat([graph_embeds, image_embeds], dim=-1) # [B, 896]
        
        # BNN Classification
        logits = self.bnn(fused_embeds, sample=sample)
        return logits
        
    @torch.no_grad()
    def predict_with_confidence(self, x: torch.Tensor, edge_index: torch.Tensor,
                                node_types: torch.Tensor, edge_types: torch.Tensor,
                                batch_idx: torch.Tensor, images: torch.Tensor,
                                num_samples: int = 20) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Runs Monte Carlo forward passes to get class prediction, confidence level, and epistemic variance.
        
        Returns:
            preds: Class predictions (0 = benign, 1 = malware) [B]
            confidence: Choice confidence score (probability of the chosen class) [B]
            variance: Epistemic uncertainty variance of classification probability [B]
        """
        self.eval()
        all_probs = []
        for _ in range(num_samples):
            logits = self.forward(x, edge_index, node_types, edge_types, batch_idx, images, sample=True)
            probs = torch.softmax(logits, dim=-1)
            all_probs.append(probs)
            
        # Stack probabilities [num_samples, B, num_classes]
        all_probs = torch.stack(all_probs, dim=0)
        
        # Average probability across runs [B, num_classes]
        mean_probs = all_probs.mean(dim=0)
        
        # Class with maximum average probability [B]
        preds = mean_probs.argmax(dim=-1)
        
        # Probability of chosen class
        confidence = mean_probs[torch.arange(preds.size(0)), preds]
        
        # Variance of the predicted class probabilities across runs [B]
        chosen_probs = all_probs[:, torch.arange(preds.size(0)), preds]
        variance = chosen_probs.var(dim=0)
        
        return preds, confidence, variance
