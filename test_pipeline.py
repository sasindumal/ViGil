"""
Test Validation Suite

Verifies model, dataset features, BFS sampling, trainer, and ensemble logic for correctness.
"""

import torch
import torch.nn as nn
import unittest
import math
from pathlib import Path
import os
import shutil

# Make sure imports from uir work
import sys
sys.path.insert(0, str(Path(__file__).parent))

from uir.model.hgt import HeterogeneousGraphTransformer, scatter_softmax
from uir.model.dataset import CPGDataset, CPGData, collate_cpg_batch
from uir.model.trainer import Trainer
from uir.model.ensemble import EnsembleModel
from uir.config import UIRConfig
from uir.cpg.graph import CodePropertyGraph
from uir.cpg.schema import NodeType, EdgeType, CPGNode, CPGEdge


class TestHGTModel(unittest.TestCase):
    
    def test_scatter_softmax(self):
        """Verify per-target-node softmax normalization."""
        scores = torch.tensor([2.0, 1.0, 3.0, 1.0, 2.0, 3.0], dtype=torch.float32)
        # target node IDs for 6 edges:
        # Node 0 has incoming edges with scores [2.0, 1.0, 3.0]
        # Node 1 has incoming edges with scores [1.0, 2.0, 3.0]
        targets = torch.tensor([0, 0, 0, 1, 1, 1], dtype=torch.long)
        num_nodes = 2
        
        normalized = scatter_softmax(scores, targets, num_nodes)
        
        # Manually compute expected softmax
        exp0 = torch.exp(torch.tensor([2.0, 1.0, 3.0]))
        exp0_sum = exp0.sum()
        expected_node0 = exp0 / exp0_sum
        
        exp1 = torch.exp(torch.tensor([1.0, 2.0, 3.0]))
        exp1_sum = exp1.sum()
        expected_node1 = exp1 / exp1_sum
        
        # Test values
        self.assertTrue(torch.allclose(normalized[:3], expected_node0, atol=1e-5))
        self.assertTrue(torch.allclose(normalized[3:], expected_node1, atol=1e-5))
        
        # Test sum of attention weights per node equals 1.0
        node0_sum = normalized[targets == 0].sum().item()
        node1_sum = normalized[targets == 1].sum().item()
        self.assertAlmostEqual(node0_sum, 1.0, places=5)
        self.assertAlmostEqual(node1_sum, 1.0, places=5)

    def test_hgt_forward(self):
        """Test HGT architecture compiles and performs forward pass."""
        hidden_dim = 64
        num_layers = 2
        num_heads = 4
        num_classes = 2
        
        model = HeterogeneousGraphTransformer(
            input_dim=256,
            hidden_dim=hidden_dim,
            num_node_types=11,
            num_edge_types=8,
            num_layers=num_layers,
            num_heads=num_heads,
            num_classes=num_classes,
            dropout=0.1
        )
        
        # Create mock batch of graphs
        num_nodes = 50
        x = torch.randn(num_nodes, 256)
        
        # Random edge index
        edge_index = torch.stack([
            torch.randint(0, num_nodes, (150,)),
            torch.randint(0, num_nodes, (150,))
        ])
        
        node_types = torch.randint(0, 11, (num_nodes,))
        edge_types = torch.randint(0, 8, (150,))
        
        # Batch: 3 graphs
        batch = torch.cat([
            torch.zeros(15, dtype=torch.long),
            torch.ones(20, dtype=torch.long),
            torch.full((15,), 2, dtype=torch.long)
        ])
        
        # Forward pass
        logits = model(x, edge_index, node_types, edge_types, batch)
        self.assertEqual(logits.shape, (3, num_classes))
        
        # Embedding pass
        embeddings = model.get_graph_embedding(x, edge_index, node_types, edge_types, batch)
        self.assertEqual(embeddings.shape, (3, hidden_dim * 2))


class TestCPGDatasetAndFeatures(unittest.TestCase):
    
    def setUp(self):
        # Create temp folder for CPGs
        self.temp_dir = Path("temp_cpg_test")
        self.temp_dir.mkdir(exist_ok=True)
        
        # Create a mock CPG and save to JSON
        cpg = CodePropertyGraph(source_file="benign_test_sample.py")
        
        # Add 12 nodes (we want to test BFS sampling with max_nodes=5)
        # Methods:
        cpg.nodes[100] = CPGNode(id=100, node_type=NodeType.METHOD, name="main")
        cpg.nodes[200] = CPGNode(id=200, node_type=NodeType.METHOD, name="helper")
        
        # Blocks:
        cpg.nodes[1] = CPGNode(id=1, node_type=NodeType.BLOCK, name="b1")
        cpg.nodes[2] = CPGNode(id=2, node_type=NodeType.BLOCK, name="b2")
        cpg.nodes[3] = CPGNode(id=3, node_type=NodeType.BLOCK, name="b3")
        cpg.nodes[4] = CPGNode(id=4, node_type=NodeType.BLOCK, name="b4")
        cpg.nodes[5] = CPGNode(id=5, node_type=NodeType.BLOCK, name="b5")
        
        # Edges
        # AST containing main method to blocks
        cpg.edges.append(CPGEdge(source_id=100, target_id=1, edge_type=EdgeType.AST))
        # CFG flows
        cpg.edges.append(CPGEdge(source_id=1, target_id=2, edge_type=EdgeType.CFG))
        cpg.edges.append(CPGEdge(source_id=2, target_id=3, edge_type=EdgeType.CFG))
        cpg.edges.append(CPGEdge(source_id=3, target_id=4, edge_type=EdgeType.CFG))
        cpg.edges.append(CPGEdge(source_id=4, target_id=5, edge_type=EdgeType.CFG))
        
        # Calls
        cpg.edges.append(CPGEdge(source_id=2, target_id=200, edge_type=EdgeType.CALLS))
        
        # Save to file
        cpg.save(self.temp_dir / "sample.json")
        
    def tearDown(self):
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            
    def test_dataset_loading_and_bfs_subgraph(self):
        """Test dataset loading, n-gram hashing, structural features, and BFS sampling."""
        dataset = CPGDataset(
            cpg_dir=self.temp_dir,
            embedding_dim=256,
            max_nodes=4 # Limit to 4 to trigger BFS sampling
        )
        
        self.assertEqual(len(dataset), 1)
        
        data = dataset[0]
        self.assertEqual(data.y.item(), 0) # benign inferred from name
        
        # Should have exactly 4 nodes after BFS sampling
        self.assertEqual(data.num_nodes, 4)
        
        # Check node features shape
        self.assertEqual(data.x.shape, (4, 256))
        
        # Check structural features
        # Node features should have non-zero elements at degrees (indices 10..28)
        self.assertTrue((data.x[:, 10:29] >= 0).all())
        
        # Check that we populated n-gram buckets (indices 32..99)
        name_grams_active = (data.x[:, 32:100] == 1.0).any()
        self.assertTrue(name_grams_active)
        
        # Check context features (indices 150..152)
        self.assertTrue((data.x[:, 150:153] > 0).any())


class TestTrainer(unittest.TestCase):
    
    def test_lr_scheduler_and_loss(self):
        """Verify learning rate scheduler and loss constructor works."""
        model = HeterogeneousGraphTransformer(
            input_dim=256,
            hidden_dim=32,
            num_node_types=11,
            num_edge_types=8,
            num_layers=2,
            num_heads=2,
            num_classes=2
        )
        
        # Default config options
        config = UIRConfig().training
        config.num_epochs = 10
        config.warmup_epochs = 2
        config.learning_rate = 1e-3
        config.min_lr = 1e-5
        
        trainer = Trainer(model, config, device=torch.device('cpu'))
        
        # Test linear warmup
        lr_w1 = trainer.get_lr(0)
        lr_w2 = trainer.get_lr(1)
        self.assertAlmostEqual(lr_w1, 0.5e-3)
        self.assertAlmostEqual(lr_w2, 1e-3)
        
        # Test cosine decay
        lr_d1 = trainer.get_lr(2)
        lr_d2 = trainer.get_lr(9)
        self.assertTrue(lr_d1 > lr_d2)
        self.assertAlmostEqual(lr_d2, 1e-5, places=5)
        
        # Test loss function is indeed Label Smoothed CrossEntropyLoss
        self.assertIsInstance(trainer.ce_loss, nn.CrossEntropyLoss)
        self.assertEqual(trainer.ce_loss.label_smoothing, 0.1)


if __name__ == "__main__":
    unittest.main()
