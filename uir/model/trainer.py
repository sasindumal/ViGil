"""
Trainer Module

Training loop for the HGT model with contrastive learning.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader
from pathlib import Path
from typing import Dict, Optional, Tuple
import logging
from tqdm import tqdm

from .hgt import HeterogeneousGraphTransformer
from .dataset import CPGDataset, CPGData, collate_cpg_batch
from ..config import TrainingConfig

logger = logging.getLogger(__name__)


class ContrastiveLoss(nn.Module):
    """Supervised contrastive loss for malware classification."""
    
    def __init__(self, temperature: float = 0.07):
        super().__init__()
        self.temperature = temperature
    
    def forward(self, embeddings: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """
        Compute contrastive loss.
        
        Args:
            embeddings: Graph embeddings (batch_size, hidden_dim)
            labels: Binary labels (batch_size,)
        """
        batch_size = embeddings.size(0)
        if batch_size <= 1:
            return torch.tensor(0.0, device=embeddings.device)
        
        # Normalize embeddings
        embeddings = F.normalize(embeddings, p=2, dim=1)
        
        # Compute similarity matrix
        sim_matrix = torch.mm(embeddings, embeddings.t()) / self.temperature
        
        # Mask for positive pairs (same label)
        labels = labels.view(-1, 1)
        mask = (labels == labels.t()).float()
        mask.fill_diagonal_(0)  # Remove self-similarity
        
        # Log-sum-exp trick for stability
        logits_max, _ = torch.max(sim_matrix, dim=1, keepdim=True)
        logits = sim_matrix - logits_max.detach()
        
        # Compute log-softmax
        exp_logits = torch.exp(logits)
        log_prob = logits - torch.log(exp_logits.sum(dim=1, keepdim=True))
        
        # Mean log-likelihood over positive pairs
        mask_sum = mask.sum(dim=1)
        mask_sum = torch.where(mask_sum > 0, mask_sum, torch.ones_like(mask_sum))
        mean_log_prob_pos = (mask * log_prob).sum(dim=1) / mask_sum
        
        loss = -mean_log_prob_pos.mean()
        return loss


class Trainer:
    """Trainer for HGT model."""
    
    def __init__(self, 
                 model: HeterogeneousGraphTransformer,
                 config: Optional[TrainingConfig] = None,
                 device: Optional[torch.device] = None):
        self.model = model
        self.config = config or TrainingConfig()
        self.device = device or torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        self.model.to(self.device)
        
        self.optimizer = torch.optim.AdamW(
            model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=0.01
        )
        
        self.ce_loss = nn.CrossEntropyLoss()
        self.contrastive_loss = ContrastiveLoss(self.config.contrastive_temperature)
        
        self.best_val_acc = 0.0
        self.patience_counter = 0
    
    def train_epoch(self, train_loader: DataLoader) -> Dict[str, float]:
        """Train for one epoch."""
        self.model.train()
        
        total_loss = 0.0
        total_correct = 0
        total_samples = 0
        
        pbar = tqdm(train_loader, desc="Training")
        for batch_data, batch_idx in pbar:
            batch_data = batch_data.to(self.device)
            batch_idx = batch_idx.to(self.device)
            
            self.optimizer.zero_grad()
            
            # Forward pass
            logits = self.model(
                batch_data.x, batch_data.edge_index,
                batch_data.node_types, batch_data.edge_types,
                batch_idx
            )
            
            # Classification loss
            labels = batch_data.y.squeeze()
            loss = self.ce_loss(logits, labels)
            
            # Contrastive loss
            if self.config.use_contrastive_loss:
                embeddings = self.model.get_graph_embedding(
                    batch_data.x, batch_data.edge_index,
                    batch_data.node_types, batch_data.edge_types,
                    batch_idx
                )
                cont_loss = self.contrastive_loss(embeddings, labels)
                loss = loss + 0.5 * cont_loss
            
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
            self.optimizer.step()
            
            # Metrics
            total_loss += loss.item()
            preds = logits.argmax(dim=1)
            total_correct += (preds == labels).sum().item()
            total_samples += labels.size(0)
            
            pbar.set_postfix({'loss': loss.item(), 'acc': total_correct / max(total_samples, 1)})
        
        return {
            'loss': total_loss / len(train_loader),
            'accuracy': total_correct / max(total_samples, 1)
        }
    
    @torch.no_grad()
    def evaluate(self, val_loader: DataLoader) -> Dict[str, float]:
        """Evaluate on validation set."""
        self.model.eval()
        
        total_loss = 0.0
        total_correct = 0
        total_samples = 0
        all_preds = []
        all_labels = []
        
        for batch_data, batch_idx in val_loader:
            batch_data = batch_data.to(self.device)
            batch_idx = batch_idx.to(self.device)
            
            logits = self.model(
                batch_data.x, batch_data.edge_index,
                batch_data.node_types, batch_data.edge_types,
                batch_idx
            )
            
            labels = batch_data.y.squeeze()
            loss = self.ce_loss(logits, labels)
            
            total_loss += loss.item()
            preds = logits.argmax(dim=1)
            total_correct += (preds == labels).sum().item()
            total_samples += labels.size(0)
            
            all_preds.extend(preds.cpu().tolist())
            all_labels.extend(labels.cpu().tolist())
        
        # Compute metrics
        accuracy = total_correct / max(total_samples, 1)
        
        return {
            'loss': total_loss / max(len(val_loader), 1),
            'accuracy': accuracy,
            'predictions': all_preds,
            'labels': all_labels
        }
    
    def train(self, train_dataset: CPGDataset, 
              val_dataset: Optional[CPGDataset] = None) -> Dict[str, list]:
        """Full training loop."""
        train_loader = DataLoader(
            train_dataset, batch_size=self.config.batch_size,
            shuffle=True, collate_fn=collate_cpg_batch
        )
        
        val_loader = None
        if val_dataset:
            val_loader = DataLoader(
                val_dataset, batch_size=self.config.batch_size,
                shuffle=False, collate_fn=collate_cpg_batch
            )
        
        history = {'train_loss': [], 'train_acc': [], 'val_loss': [], 'val_acc': []}
        
        for epoch in range(self.config.num_epochs):
            logger.info(f"Epoch {epoch + 1}/{self.config.num_epochs}")
            
            train_metrics = self.train_epoch(train_loader)
            history['train_loss'].append(train_metrics['loss'])
            history['train_acc'].append(train_metrics['accuracy'])
            
            logger.info(f"Train Loss: {train_metrics['loss']:.4f}, Acc: {train_metrics['accuracy']:.4f}")
            
            if val_loader:
                val_metrics = self.evaluate(val_loader)
                history['val_loss'].append(val_metrics['loss'])
                history['val_acc'].append(val_metrics['accuracy'])
                
                logger.info(f"Val Loss: {val_metrics['loss']:.4f}, Acc: {val_metrics['accuracy']:.4f}")
                
                # Early stopping
                if val_metrics['accuracy'] > self.best_val_acc:
                    self.best_val_acc = val_metrics['accuracy']
                    self.patience_counter = 0
                    self.save_checkpoint(self.config.checkpoint_dir / "best_model.pt")
                else:
                    self.patience_counter += 1
                    if self.patience_counter >= self.config.early_stopping_patience:
                        logger.info(f"Early stopping at epoch {epoch + 1}")
                        break
        
        return history
    
    def save_checkpoint(self, path: Path):
        """Save model checkpoint."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save({
            'model_state': self.model.state_dict(),
            'optimizer_state': self.optimizer.state_dict(),
            'best_val_acc': self.best_val_acc,
        }, path)
        logger.info(f"Saved checkpoint to {path}")
    
    def load_checkpoint(self, path: Path):
        """Load model checkpoint."""
        checkpoint = torch.load(path, map_location=self.device)
        self.model.load_state_dict(checkpoint['model_state'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state'])
        self.best_val_acc = checkpoint.get('best_val_acc', 0.0)
        logger.info(f"Loaded checkpoint from {path}")
