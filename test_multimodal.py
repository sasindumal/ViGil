"""
Test Suite for Multimodal Joint Model

Verifies correctness of:
- Grayscale image converter
- Joint model forward pass (HGT + LeViT + BNN)
- Bayesian layers KL divergence calculation
- Monte Carlo confidence and variance estimation
"""

import torch
import torch.nn as nn
import unittest
from pathlib import Path
import os
import shutil
from PIL import Image

import sys
sys.path.insert(0, str(Path(__file__).parent))

from uir.model.joint_model import LoraLevitFeatureExtractor, BayesianLinear, BayesianClassifier, JointMalwareModel
from uir.model.hgt import HeterogeneousGraphTransformer
from uir.extraction.image_generator import pe_to_grayscale_image


class TestMultimodalBNN(unittest.TestCase):
    
    def test_image_generator(self):
        """Verify pe_to_grayscale_image outputs a valid normalized 224x224 PIL image."""
        # Create a mock binary file
        temp_file = Path("temp_mock_binary.exe")
        with open(temp_file, "wb") as f:
            f.write(os.urandom(50000)) # 50 KB dummy bytes
            
        try:
            img = pe_to_grayscale_image(temp_file, target_size=224)
            self.assertIsInstance(img, Image.Image)
            self.assertEqual(img.size, (224, 224))
            self.assertEqual(img.mode, 'L')
        finally:
            if temp_file.exists():
                temp_file.unlink()
                
    def test_bayesian_linear_layer(self):
        """Verify BayesianLinear forward shapes and KL divergence analytical calculations."""
        layer = BayesianLinear(in_features=256, out_features=128, prior_sigma=0.1)
        x = torch.randn(10, 256)
        
        # Test training (sampling) pass
        layer.train()
        out_train = layer(x, sample=True)
        self.assertEqual(out_train.shape, (10, 128))
        
        # Test evaluation (posterior mean) pass
        layer.eval()
        out_eval = layer(x, sample=False)
        self.assertEqual(out_eval.shape, (10, 128))
        
        # Verify KL divergence outputs a scalar tensor greater than 0
        kl = layer.kl_divergence()
        self.assertEqual(kl.shape, ())
        self.assertTrue(kl.item() > 0.0)
        
    def test_joint_model_forward_and_mc_inference(self):
        """Verify JointMalwareModel forward pass, target shapes, and Monte Carlo confidence estimation."""
        hgt = HeterogeneousGraphTransformer(
            input_dim=320,
            hidden_dim=256,
            num_node_types=11,
            num_edge_types=8,
            num_layers=2,
            num_heads=4,
            num_classes=2
        )
        # Use fallback feature extractor for unit test compatibility
        levit = LoraLevitFeatureExtractor()
        levit.is_fallback = True
        
        bnn = BayesianClassifier(in_features=256 * 2 + 384, num_classes=2)
        model = JointMalwareModel(hgt, levit, bnn)
        
        # Mock Graph data
        num_nodes = 20
        x = torch.randn(num_nodes, 320)
        edge_index = torch.stack([
            torch.randint(0, num_nodes, (60,)),
            torch.randint(0, num_nodes, (60,))
        ])
        node_types = torch.randint(0, 11, (num_nodes,))
        edge_types = torch.randint(0, 8, (60,))
        batch_idx = torch.zeros(num_nodes, dtype=torch.long)
        
        # Mock batch images (batch size = 1)
        images = torch.randn(1, 3, 224, 224)
        
        # Run forward pass (evaluation mode)
        model.eval()
        logits = model(x, edge_index, node_types, edge_types, batch_idx, images, sample=False)
        self.assertEqual(logits.shape, (1, 2))
        
        # Run BNN Monte Carlo sampling predictions with confidence level estimation
        preds, confidence, variance = model.predict_with_confidence(
            x, edge_index, node_types, edge_types, batch_idx, images, num_samples=5
        )
        
        self.assertEqual(preds.shape, (1,))
        self.assertEqual(confidence.shape, (1,))
        self.assertEqual(variance.shape, (1,))
        
        # Assert confidence is a probability within [0, 1]
        self.assertTrue(0.0 <= confidence.item() <= 1.0)
        self.assertTrue(variance.item() >= 0.0)


if __name__ == "__main__":
    unittest.main()
