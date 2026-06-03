"""
Trainer Module

Training loop for the HGT model with contrastive learning, LR scheduling, Focal loss, Label smoothing, EMA, and data augmentation.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader
from pathlib import Path
from typing import Dict, Optional, Tuple, List
import logging
import math
from tqdm import tqdm

from .hgt import HeterogeneousGraphTransformer
from .dataset import CPGDataset, CPGData, collate_cpg_batch
from ..config import TrainingConfig
from .evaluator import Evaluator

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


class FocalLoss(nn.Module):
    """Focal Loss with label smoothing for binary/multi-class classification."""
    
    def __init__(self, gamma: float = 2.0, label_smoothing: float = 0.0):
        super().__init__()
        self.gamma = gamma
        self.label_smoothing = label_smoothing
        
    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        log_probs = F.log_softmax(logits, dim=-1)
        probs = torch.exp(log_probs)
        
        num_classes = logits.size(-1)
        one_hot = F.one_hot(targets, num_classes=num_classes).float()
        
        if self.label_smoothing > 0:
            one_hot = one_hot * (1.0 - self.label_smoothing) + self.label_smoothing / num_classes
            
        focal_weight = torch.pow(1.0 - probs, self.gamma)
        loss = - (focal_weight * one_hot * log_probs).sum(dim=-1)
        return loss.mean()


class EMA:
    """Exponential Moving Average of model parameters."""
    
    def __init__(self, model: nn.Module, decay: float = 0.999):
        self.model = model
        self.decay = decay
        self.shadow = {}
        self.backup = {}
        
    def register(self):
        for name, param in self.model.named_parameters():
            if param.requires_grad:
                self.shadow[name] = param.data.clone()
                
    def update(self):
        for name, param in self.model.named_parameters():
            if param.requires_grad:
                assert name in self.shadow
                new_average = (1.0 - self.decay) * param.data + self.decay * self.shadow[name]
                self.shadow[name] = new_average.clone()
                
    def apply_shadow(self):
        for name, param in self.model.named_parameters():
            if param.requires_grad:
                self.backup[name] = param.data.clone()
                param.data.copy_(self.shadow[name])
                
    def restore(self):
        for name, param in self.model.named_parameters():
            if param.requires_grad:
                assert name in self.backup
                param.data.copy_(self.backup[name])
        self.backup = {}


class Trainer:
    """Trainer for HGT model supporting LR scheduling, Focal loss, Label smoothing, EMA, and GPU acceleration."""
    
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
        
        # Initialize Loss functions (Phase 4)
        if self.config.use_focal_loss:
            self.ce_loss = FocalLoss(gamma=self.config.focal_loss_gamma, label_smoothing=self.config.label_smoothing)
        else:
            self.ce_loss = nn.CrossEntropyLoss(label_smoothing=self.config.label_smoothing)
            
        self.contrastive_loss = ContrastiveLoss(self.config.contrastive_temperature)
        
        # Initialize EMA (Phase 4)
        self.ema = None
        if self.config.use_ema:
            self.ema = EMA(self.model, decay=self.config.ema_decay)
            self.ema.register()
            
        self.best_val_f1 = 0.0
        self.patience_counter = 0
        
        # Unique timestamped model filename for this training run
        import datetime
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.checkpoint_filename = f"best_model_{self.timestamp}.pt"
        
    def get_lr(self, epoch: int) -> float:
        """Compute training learning rate with warmup and cosine decay."""
        if epoch < self.config.warmup_epochs:
            return self.config.learning_rate * (epoch + 1) / self.config.warmup_epochs
        
        total_decay_epochs = max(1, self.config.num_epochs - 1 - self.config.warmup_epochs)
        progress = min(1.0, (epoch - self.config.warmup_epochs) / total_decay_epochs)
        cosine_decay = 0.5 * (1.0 + math.cos(math.pi * progress))
        lr = self.config.min_lr + (self.config.learning_rate - self.config.min_lr) * cosine_decay
        return lr
        
    def train_epoch(self, train_loader: DataLoader, epoch: int) -> Dict[str, float]:
        """Train for one epoch."""
        self.model.train()
        
        # Update LR if using scheduler
        if self.config.use_lr_scheduler:
            lr = self.get_lr(epoch)
            for param_group in self.optimizer.param_groups:
                param_group['lr'] = lr
        
        total_loss = 0.0
        total_correct = 0
        total_samples = 0
        
        use_amp = self.device.type == 'cuda'
        scaler = torch.cuda.amp.GradScaler() if use_amp else None
        
        pbar = tqdm(train_loader, desc=f"Training Epoch {epoch+1}")
        for batch_data, batch_idx in pbar:
            batch_data = batch_data.to(self.device)
            batch_idx = batch_idx.to(self.device)
            
            # Apply Vectorized Data Augmentations (Phase 5)
            if self.config.use_augmentation:
                # 1. Feature Masking
                if self.config.aug_feature_mask_rate > 0:
                    mask = (torch.rand_like(batch_data.x) >= self.config.aug_feature_mask_rate).float()
                    batch_data.x = batch_data.x * mask
                # 2. Edge Dropout
                if self.config.aug_edge_drop_rate > 0 and batch_data.edge_index.size(1) > 0:
                    edge_mask = torch.rand(batch_data.edge_index.size(1), device=self.device) >= self.config.aug_edge_drop_rate
                    batch_data.edge_index = batch_data.edge_index[:, edge_mask]
                    batch_data.edge_types = batch_data.edge_types[edge_mask]
            
            self.optimizer.zero_grad()
            
            # Forward pass with optional Mixed Precision
            if use_amp:
                with torch.cuda.amp.autocast():
                    logits = self.model(
                        batch_data.x, batch_data.edge_index,
                        batch_data.node_types, batch_data.edge_types,
                        batch_idx
                    )
                    labels = batch_data.y.squeeze()
                    loss = self.ce_loss(logits, labels)
                    
                    if self.config.use_contrastive_loss:
                        embeddings = self.model.get_graph_embedding(
                            batch_data.x, batch_data.edge_index,
                            batch_data.node_types, batch_data.edge_types,
                            batch_idx
                        )
                        cont_loss = self.contrastive_loss(embeddings, labels)
                        loss = loss + 0.5 * cont_loss
                
                scaler.scale(loss).backward()
                scaler.unscale_(self.optimizer)
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                scaler.step(self.optimizer)
                scaler.update()
            else:
                logits = self.model(
                    batch_data.x, batch_data.edge_index,
                    batch_data.node_types, batch_data.edge_types,
                    batch_idx
                )
                labels = batch_data.y.squeeze()
                loss = self.ce_loss(logits, labels)
                
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
                
            # Update EMA weights
            if self.ema is not None:
                self.ema.update()
            
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
        
        # Apply EMA shadow weights for evaluation
        if self.ema is not None:
            self.ema.apply_shadow()
            
        total_loss = 0.0
        all_preds = []
        all_labels = []
        
        try:
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
                
                all_preds.extend(preds.cpu().tolist())
                all_labels.extend(labels.cpu().tolist())
        finally:
            # Restore original weights if EMA was active
            if self.ema is not None:
                self.ema.restore()
        
        # Compute metrics using Evaluator
        evaluator = Evaluator()
        metrics = evaluator.compute_metrics(all_preds, all_labels)
        
        return {
            'loss': total_loss / max(len(val_loader), 1),
            'accuracy': metrics.get('accuracy', 0.0),
            'f1': metrics.get('f1', 0.0),
            'precision': metrics.get('precision', 0.0),
            'recall': metrics.get('recall', 0.0),
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
        
        history = {'train_loss': [], 'train_acc': [], 'val_loss': [], 'val_acc': [], 'val_f1': []}
        
        for epoch in range(self.config.num_epochs):
            logger.info(f"Epoch {epoch + 1}/{self.config.num_epochs}")
            
            train_metrics = self.train_epoch(train_loader, epoch)
            history['train_loss'].append(train_metrics['loss'])
            history['train_acc'].append(train_metrics['accuracy'])
            
            logger.info(f"Train Loss: {train_metrics['loss']:.4f}, Acc: {train_metrics['accuracy']:.4f}")
            
            if val_loader:
                val_metrics = self.evaluate(val_loader)
                history['val_loss'].append(val_metrics['loss'])
                history['val_acc'].append(val_metrics['accuracy'])
                history['val_f1'].append(val_metrics['f1'])
                
                logger.info(f"Val Loss: {val_metrics['loss']:.4f}, Acc: {val_metrics['accuracy']:.4f}, F1: {val_metrics['f1']:.4f}")
                
                # Early stopping tracking Validation F1 (Phase 4)
                val_f1 = val_metrics['f1']
                if val_f1 > self.best_val_f1:
                    self.best_val_f1 = val_f1
                    self.patience_counter = 0
                    self.save_checkpoint(self.config.checkpoint_dir / self.checkpoint_filename)
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
        state = {
            'model_state': self.model.state_dict(),
            'optimizer_state': self.optimizer.state_dict(),
            'best_val_f1': self.best_val_f1,
        }
        if self.ema is not None:
            state['ema_shadow'] = self.ema.shadow
        torch.save(state, path)
        logger.info(f"Saved checkpoint to {path}")
    
    def load_checkpoint(self, path: Path):
        """Load model checkpoint."""
        checkpoint = torch.load(path, map_location=self.device)
        self.model.load_state_dict(checkpoint['model_state'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state'])
        self.best_val_f1 = checkpoint.get('best_val_f1', checkpoint.get('best_val_acc', 0.0))
        if self.ema is not None and 'ema_shadow' in checkpoint:
            self.ema.shadow = checkpoint['ema_shadow']
        logger.info(f"Loaded checkpoint from {path}")
