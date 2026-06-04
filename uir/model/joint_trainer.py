"""
Joint Trainer Module

Training loop for the Joint Malware Detection model (HGT + LeViT-LoRA + BNN Classifier).
Incorporates BNN weight KL divergence into the loss, and supports LR scheduling, Focal loss, EMA, and GPU acceleration.
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

from .joint_model import JointMalwareModel
from .dataset import CPGDataset, CPGData, collate_cpg_batch
from ..config import TrainingConfig
from .evaluator import Evaluator
from .trainer import EMA, FocalLoss

logger = logging.getLogger(__name__)


class JointTrainer:
    """Trainer for the Quad-Modal Joint Model: HGT + LeViT + RansomFormer + BNN."""
    
    def __init__(self, 
                 model: JointMalwareModel,
                 config: Optional[TrainingConfig] = None,
                 device: Optional[torch.device] = None,
                 kl_weight: float = 1e-4):
        """
        Initialize the joint trainer.
        
        Args:
            model: JointMalwareModel instance
            config: TrainingConfig parameters
            device: Computing device
            kl_weight: Weight coefficient for the BNN KL divergence loss term
        """
        self.model = model
        self.config = config or TrainingConfig()
        self.device = device or torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.kl_weight = kl_weight
        
        self.model.to(self.device)
        
        # Optimize all trainable weights (HGT parameters, LeViT LoRA adapters, BNN parameters)
        self.optimizer = torch.optim.AdamW(
            filter(lambda p: p.requires_grad, model.parameters()),
            lr=self.config.learning_rate,
            weight_decay=0.01
        )
        
        # Initialize Classification Loss
        if self.config.use_focal_loss:
            self.classification_loss = FocalLoss(gamma=self.config.focal_loss_gamma, label_smoothing=self.config.label_smoothing)
        else:
            self.classification_loss = nn.CrossEntropyLoss(label_smoothing=self.config.label_smoothing)
            
        # Initialize EMA for parameters
        self.ema = None
        if self.config.use_ema:
            self.ema = EMA(self.model, decay=self.config.ema_decay)
            self.ema.register()
            
        self.best_val_f1 = 0.0
        self.patience_counter = 0
        
        # Unique timestamped model filename for this training run
        import datetime
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.checkpoint_filename = f"best_joint_model_{self.timestamp}.pt"
        
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
        total_class_loss = 0.0
        total_kl_loss = 0.0
        total_correct = 0
        total_samples = 0
        
        use_amp = self.device.type == 'cuda'
        scaler = torch.cuda.amp.GradScaler() if use_amp else None
        
        pbar = tqdm(train_loader, desc=f"Joint Training Epoch {epoch+1}")
        for batch_data, batch_idx in pbar:
            batch_data = batch_data.to(self.device)
            batch_idx = batch_idx.to(self.device)
            
            # Apply Vectorized Data Augmentations (to HGT node features and edge list)
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
                        batch_idx, batch_data.image,
                        batch_data.pe_bytes, batch_data.api_tokens,
                        sample=True
                    )
                    labels = batch_data.y.squeeze()

                    # Classification Loss (Cross Entropy or Focal)
                    class_loss = self.classification_loss(logits, labels)

                    # Bayesian Neural Network KL Divergence regularization term
                    kl_div = self.model.bnn.kl_divergence()
                    loss = class_loss + self.kl_weight * kl_div

                scaler.scale(loss).backward()
                scaler.unscale_(self.optimizer)
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                scaler.step(self.optimizer)
                scaler.update()
            else:
                logits = self.model(
                    batch_data.x, batch_data.edge_index,
                    batch_data.node_types, batch_data.edge_types,
                    batch_idx, batch_data.image,
                    batch_data.pe_bytes, batch_data.api_tokens,
                    sample=True
                )
                labels = batch_data.y.squeeze()

                class_loss = self.classification_loss(logits, labels)
                kl_div = self.model.bnn.kl_divergence()
                loss = class_loss + self.kl_weight * kl_div

                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                self.optimizer.step()
                
            # Update EMA weights
            if self.ema is not None:
                self.ema.update()
            
            # Metrics
            total_loss += loss.item()
            total_class_loss += class_loss.item()
            total_kl_loss += kl_div.item()
            preds = logits.argmax(dim=1)
            total_correct += (preds == labels).sum().item()
            total_samples += labels.size(0)
            
            pbar.set_postfix({
                'loss': loss.item(), 
                'c_loss': class_loss.item(),
                'kl': kl_div.item(),
                'acc': total_correct / max(total_samples, 1)
            })
        
        return {
            'loss': total_loss / len(train_loader),
            'class_loss': total_class_loss / len(train_loader),
            'kl_loss': total_kl_loss / len(train_loader),
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
                
                # During evaluation, run BNN predictions deterministically (sample=False)
                logits = self.model(
                    batch_data.x, batch_data.edge_index,
                    batch_data.node_types, batch_data.edge_types,
                    batch_idx, batch_data.image,
                    batch_data.pe_bytes, batch_data.api_tokens,
                    sample=False
                )
                
                labels = batch_data.y.squeeze()
                loss = self.classification_loss(logits, labels)
                
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
        
        history = {
            'train_loss': [], 'train_acc': [], 
            'val_loss': [], 'val_acc': [], 'val_f1': []
        }
        
        for epoch in range(self.config.num_epochs):
            logger.info(f"Epoch {epoch + 1}/{self.config.num_epochs}")
            
            train_metrics = self.train_epoch(train_loader, epoch)
            history['train_loss'].append(train_metrics['loss'])
            history['train_acc'].append(train_metrics['accuracy'])
            
            logger.info(
                f"Train Loss: {train_metrics['loss']:.4f} "
                f"(Class: {train_metrics['class_loss']:.4f}, KL: {train_metrics['kl_loss']:.4f}), "
                f"Acc: {train_metrics['accuracy']:.4f}"
            )
            
            if val_loader:
                val_metrics = self.evaluate(val_loader)
                history['val_loss'].append(val_metrics['loss'])
                history['val_acc'].append(val_metrics['accuracy'])
                history['val_f1'].append(val_metrics['f1'])
                
                logger.info(f"Val Loss: {val_metrics['loss']:.4f}, Acc: {val_metrics['accuracy']:.4f}, F1: {val_metrics['f1']:.4f}")
                
                # Early stopping tracking Validation F1
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
        self.best_val_f1 = checkpoint.get('best_val_f1', 0.0)
        if self.ema is not None and 'ema_shadow' in checkpoint:
            self.ema.shadow = checkpoint['ema_shadow']
        logger.info(f"Loaded checkpoint from {path}")
