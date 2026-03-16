"""
Evaluator Module

Evaluation metrics and analysis for malware classification.
"""

import torch
from typing import Dict, List, Optional, Tuple
from collections import Counter
import logging

logger = logging.getLogger(__name__)


class Evaluator:
    """Evaluator for malware classification results."""
    
    def __init__(self, num_classes: int = 2):
        self.num_classes = num_classes
        self.class_names = ['benign', 'malware'] if num_classes == 2 else [f'class_{i}' for i in range(num_classes)]
    
    def compute_metrics(self, predictions: List[int], labels: List[int]) -> Dict[str, float]:
        """Compute classification metrics."""
        if not predictions or not labels:
            return {}
        
        # Basic counts
        tp = sum(1 for p, l in zip(predictions, labels) if p == 1 and l == 1)
        tn = sum(1 for p, l in zip(predictions, labels) if p == 0 and l == 0)
        fp = sum(1 for p, l in zip(predictions, labels) if p == 1 and l == 0)
        fn = sum(1 for p, l in zip(predictions, labels) if p == 0 and l == 1)
        
        total = len(predictions)
        
        # Metrics
        accuracy = (tp + tn) / total if total > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        # False positive/negative rates
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'true_positives': tp,
            'true_negatives': tn,
            'false_positives': fp,
            'false_negatives': fn,
            'false_positive_rate': fpr,
            'false_negative_rate': fnr,
        }
    
    def confusion_matrix(self, predictions: List[int], labels: List[int]) -> List[List[int]]:
        """Compute confusion matrix."""
        matrix = [[0] * self.num_classes for _ in range(self.num_classes)]
        for p, l in zip(predictions, labels):
            if 0 <= p < self.num_classes and 0 <= l < self.num_classes:
                matrix[l][p] += 1
        return matrix
    
    def print_report(self, predictions: List[int], labels: List[int]):
        """Print classification report."""
        metrics = self.compute_metrics(predictions, labels)
        cm = self.confusion_matrix(predictions, labels)
        
        print("\n" + "=" * 50)
        print("Classification Report")
        print("=" * 50)
        
        print(f"\nAccuracy:  {metrics.get('accuracy', 0):.4f}")
        print(f"Precision: {metrics.get('precision', 0):.4f}")
        print(f"Recall:    {metrics.get('recall', 0):.4f}")
        print(f"F1 Score:  {metrics.get('f1', 0):.4f}")
        
        print("\nConfusion Matrix:")
        print("              Predicted")
        print("              " + "  ".join(f"{n:>8}" for n in self.class_names))
        print("Actual")
        for i, row in enumerate(cm):
            print(f"  {self.class_names[i]:>8}  " + "  ".join(f"{v:>8}" for v in row))
        
        print("\nDetailed:")
        print(f"  True Positives:  {metrics.get('true_positives', 0)}")
        print(f"  True Negatives:  {metrics.get('true_negatives', 0)}")
        print(f"  False Positives: {metrics.get('false_positives', 0)}")
        print(f"  False Negatives: {metrics.get('false_negatives', 0)}")
        print(f"  FPR: {metrics.get('false_positive_rate', 0):.4f}")
        print(f"  FNR: {metrics.get('false_negative_rate', 0):.4f}")
        print("=" * 50)
    
    def analyze_errors(self, predictions: List[int], labels: List[int], 
                      file_paths: Optional[List[str]] = None) -> Dict[str, List[str]]:
        """Analyze misclassified samples."""
        errors = {
            'false_positives': [],  # Benign predicted as malware
            'false_negatives': [],  # Malware predicted as benign
        }
        
        for i, (p, l) in enumerate(zip(predictions, labels)):
            path = file_paths[i] if file_paths and i < len(file_paths) else f"sample_{i}"
            
            if p == 1 and l == 0:
                errors['false_positives'].append(path)
            elif p == 0 and l == 1:
                errors['false_negatives'].append(path)
        
        return errors


def compute_roc_auc(predictions: torch.Tensor, labels: torch.Tensor) -> float:
    """Compute ROC-AUC score."""
    try:
        from sklearn.metrics import roc_auc_score
        if predictions.dim() > 1:
            probs = torch.softmax(predictions, dim=1)[:, 1]
        else:
            probs = predictions
        return roc_auc_score(labels.cpu().numpy(), probs.cpu().numpy())
    except Exception:
        return 0.0
