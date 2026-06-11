"""
Ensemble and Test-Time Augmentation (TTA) Module

Implements ensemble voting and test-time augmentation for ultra-high accuracy.
"""

import torch
import torch.nn as nn
from typing import List, Tuple, Dict, Any, Optional
from pathlib import Path

from .hgt import HeterogeneousGraphTransformer
from .dataset import CPGData, EMBEDDING_DIM
from ..config import default_config


class EnsembleModel:
    """Ensemble model that combines multiple checkpoints and optionally applies Test-Time Augmentation."""
    
    def __init__(self, model_paths: List[Path], device: torch.device):
        self.device = device
        self.models = []
        
        # Determine architecture settings from config
        hidden_dim = default_config.model.hidden_dim
        num_layers = default_config.model.num_layers
        num_heads = default_config.model.num_heads
        num_classes = default_config.model.num_classes
        input_dim = default_config.model.embedding_dim
        
        for path in model_paths:
            path = Path(path)
            if not path.exists():
                raise FileNotFoundError(f"Model checkpoint not found: {path}")
                
            checkpoint = torch.load(path, map_location=device)
            model = HeterogeneousGraphTransformer(
                input_dim=input_dim,
                hidden_dim=hidden_dim,
                num_layers=num_layers,
                num_heads=num_heads,
                num_classes=num_classes
            )
            model.load_state_dict(checkpoint['model_state'])
            model.eval()
            model.to(device)
            self.models.append(model)
            
    @torch.no_grad()
    def predict_proba(self, 
                      batch_data: CPGData, 
                      batch_idx: torch.Tensor, 
                      tta_steps: int = 5, 
                      drop_rate: float = 0.05) -> torch.Tensor:
        """
        Predict class probabilities using all ensemble models and Test-Time Augmentation (TTA).
        
        Args:
            batch_data: Batch of CPG data
            batch_idx: Batch indices mapping nodes to graphs
            tta_steps: Number of TTA passes (1 means no TTA)
            drop_rate: Edge drop rate for TTA perturbations
            
        Returns:
            Class probabilities of shape (batch_size, num_classes)
        """
        all_probs = []
        
        for model in self.models:
            model_probs = []
            
            for t in range(tta_steps if tta_steps > 0 else 1):
                # perturb edge index if doing TTA
                x = batch_data.x.to(self.device)
                edge_index = batch_data.edge_index.to(self.device)
                edge_types = batch_data.edge_types.to(self.device)
                node_types = batch_data.node_types.to(self.device)
                b_idx = batch_idx.to(self.device)
                
                if tta_steps > 1 and drop_rate > 0 and edge_index.size(1) > 0:
                    mask = torch.rand(edge_index.size(1), device=self.device) >= drop_rate
                    edge_index = edge_index[:, mask]
                    edge_types = edge_types[mask]
                    
                logits = model(x, edge_index, node_types, edge_types, b_idx)
                probs = torch.softmax(logits, dim=-1)
                model_probs.append(probs)
                
            # Average TTA predictions for this model
            model_probs = torch.stack(model_probs).mean(dim=0)
            all_probs.append(model_probs)
            
        # Average across all models in ensemble
        ensemble_probs = torch.stack(all_probs).mean(dim=0)
        return ensemble_probs
        
    def predict(self, 
                batch_data: CPGData, 
                batch_idx: torch.Tensor, 
                tta_steps: int = 5, 
                drop_rate: float = 0.05, 
                threshold: float = 0.5) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Classify samples, computing confidence and flagging low-confidence inputs.
        
        Returns:
            predictions: Predicted class labels (batch_size,)
            confidence: Probability of the chosen class (batch_size,)
            is_confident: Boolean mask indicating if confidence exceeds threshold (batch_size,)
        """
        probs = self.predict_proba(batch_data, batch_idx, tta_steps=tta_steps, drop_rate=drop_rate)
        
        # Binary classification target class is 1 (malware)
        probs_malware = probs[:, 1]
        preds = (probs_malware >= threshold).long()
        
        # Confidence is probability of the predicted class
        confidence = torch.where(preds == 1, probs_malware, 1.0 - probs_malware)
        
        # We flag low confidence if prediction probability is near 0.5 (e.g. within [0.4, 0.6])
        # Let's say if confidence < 0.85, we tag it as low confidence (flag for manual review)
        is_confident = confidence >= 0.85
        
        return preds, confidence, is_confident
