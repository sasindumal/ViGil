import sys
from pathlib import Path
import torch

# Ensure uir is in the python path
workspace_dir = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(workspace_dir))

from uir.model.optimized_models import build_model, NOTEBOOK_CFG

def check_model():
    print("Initializing optimized model...")
    device = torch.device("cpu")
    model = build_model(NOTEBOOK_CFG, device)
    
    # 1. Print parameter count and verify ConvNeXt layer freezing
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"Total parameters: {total_params:,}")
    print(f"Trainable parameters: {trainable_params:,}")
    print(f"Frozen parameters: {total_params - trainable_params:,}")
    
    # Verify some ConvNeXt weights are frozen (requires_grad = False)
    frozen_cnn_count = 0
    total_cnn_count = 0
    for name, param in model.rest.cnn.features.named_parameters():
        total_cnn_count += 1
        if not param.requires_grad:
            frozen_cnn_count += 1
    print(f"ConvNeXt-Tiny feature parameters: total={total_cnn_count}, frozen={frozen_cnn_count}")
    assert frozen_cnn_count > 0, "ConvNeXt features should have frozen parameters"
    
    # 2. Prepare mock inputs for a batch of size B = 2
    print("Preparing mock batch...")
    B = 2
    N = 100 # Total nodes in the batch (50 per graph)
    E = 150 # Total edges in the batch
    
    x = torch.randn(N, 320)
    edge_index = torch.randint(0, N, (2, E))
    node_types = torch.randint(0, 10, (N,))
    edge_types = torch.randint(0, 8, (E,))
    
    # Batch indices (50 nodes for graph 0, 50 nodes for graph 1)
    batch_idx = torch.cat([torch.zeros(50, dtype=torch.long), torch.ones(50, dtype=torch.long)])
    
    images = torch.randn(B, 3, 224, 224)
    pe_bytes = torch.randn(B, 1, 1024)
    api_tokens = torch.randint(0, 4096, (B, 256))
    
    # 3. Test forward pass
    print("Running forward pass...")
    logits = model(x, edge_index, node_types, edge_types, batch_idx, images, pe_bytes, api_tokens, sample=True)
    print(f"Output shape: {logits.shape}")
    assert logits.shape == (B, 2), f"Expected shape {(B, 2)}, got {logits.shape}"
    
    # 4. Test Monte Carlo prediction with confidence
    print("Running predict_with_confidence...")
    preds, confidence, variance = model.predict_with_confidence(
        x, edge_index, node_types, edge_types, batch_idx, images, pe_bytes, api_tokens, num_samples=5
    )
    print(f"Predictions: {preds}")
    print(f"Confidences: {confidence}")
    print(f"Variances: {variance}")
    
    assert preds.shape == (B,), f"Expected shape {(B,)}, got {preds.shape}"
    assert confidence.shape == (B,), f"Expected shape {(B,)}, got {confidence.shape}"
    assert variance.shape == (B,), f"Expected shape {(B,)}, got {variance.shape}"
    
    print("\n✅ Verification Successful: Optimized model operates perfectly!")

if __name__ == "__main__":
    check_model()
