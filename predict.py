import argparse
import sys
from pathlib import Path
import torch
import torch.nn.functional as F

# Add current directory to Python path so uir package is found
script_dir = Path(__file__).parent.resolve()
if str(script_dir) not in sys.path:
    sys.path.insert(0, str(script_dir))

from uir.pipeline.processor import FileProcessor
from uir.model.dataset import CPGDataset, CPGData, collate_cpg_batch
from uir.model.hgt import HeterogeneousGraphTransformer

def load_model(checkpoint_path: Path, device: torch.device):
    if not checkpoint_path.exists():
        print(f"[!] Checkpoint not found at {checkpoint_path}")
        sys.exit(1)
        
    print(f"[*] Loading model from {checkpoint_path}...")
    checkpoint = torch.load(checkpoint_path, map_location=device)
    
    config = checkpoint.get('model_config', {})
    
    model = HeterogeneousGraphTransformer(
        input_dim=config.get('input_dim', 320),
        hidden_dim=config.get('hidden_dim', 256),
        num_node_types=config.get('num_node_types', 11),
        num_edge_types=config.get('num_edge_types', 8),
        num_layers=config.get('num_layers', 4),
        num_heads=config.get('num_heads', 8),
        num_classes=config.get('num_classes', 2),
        dropout=config.get('dropout', 0.1)
    )
    
    # Handle DataParallel prefix if present in checkpoint
    state_dict = checkpoint['model_state']
    new_state_dict = {}
    for k, v in state_dict.items():
        name = k[7:] if k.startswith('module.') else k
        new_state_dict[name] = v
        
    model.load_state_dict(new_state_dict)
    model.to(device)
    model.eval()
    
    return model

def predict(target_file: str, model_path: str = 'final_model.pt'):
    target_path = Path(target_file).resolve()
    checkpoint_path = Path(model_path).resolve()
    
    if not checkpoint_path.exists():
        # Fallback for running within original repository
        repo_checkpoint = Path('checkpoints') / model_path
        if repo_checkpoint.exists():
            checkpoint_path = repo_checkpoint.resolve()
            
    if not target_path.exists():
        print(f"[!] Target file not found: {target_path}")
        sys.exit(1)
        
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"[*] Using device: {device}")
    
    # 1. Lift and generate CPG
    print(f"[*] Processing file: {target_path.name}")
    processor = FileProcessor()
    
    cpg = processor.process(target_path, use_cache=False)
    
    if cpg is None or len(cpg.nodes) == 0:
        print("[!] Failed to generate CPG or CPG is empty.")
        sys.exit(1)
        
    print(f"[*] CPG generated: {len(cpg.nodes)} nodes, {len(cpg.edges)} edges")
    
    # 2. Convert to Model Tensor Data
    # Initialize a dummy dataset just to use its parsing logic
    # (Since we don't need a cpg_dir, we pass an empty/current directory)
    dataset = CPGDataset(cpg_dir=".", embedding_dim=320, max_nodes=10000)
    data = dataset._cpg_to_data(cpg)
    
    if data.num_nodes == 0:
        print("[!] Failed to convert CPG to tensor features.")
        sys.exit(1)
    
    # Add dummy batch index
    batch_idx = torch.zeros(data.num_nodes, dtype=torch.long)
    
    # Move to device
    x = data.x.to(device)
    edge_index = data.edge_index.to(device) if data.edge_index is not None else torch.zeros((2, 0), dtype=torch.long).to(device)
    node_types = data.node_types.to(device)
    edge_types = data.edge_types.to(device) if data.edge_types is not None else torch.zeros(0, dtype=torch.long).to(device)
    batch_idx = batch_idx.to(device)
    
    # 3. Load Model
    model = load_model(checkpoint_path, device)
    
    # 4. Predict
    print("[*] Running inference...")
    with torch.no_grad():
        logits = model(x, edge_index, node_types, edge_types, batch_idx)
        probs = F.softmax(logits, dim=1)
        pred_class = logits.argmax(dim=1).item()
        
    classes = ['Benign', 'Malware']
    predicted_label = classes[pred_class]
    confidence = probs[0][pred_class].item() * 100
    
    print("\n" + "="*50)
    print(f"  PREDICTION RESULT")
    print("="*50)
    print(f"  File       : {target_path.name}")
    print(f"  Result     : {predicted_label}")
    print(f"  Confidence : {confidence:.2f}%")
    print("="*50)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Predict Malware/Benign using UIR model")
    parser.add_argument("file", help="Path to the PE file to analyze")
    parser.add_argument("-m", "--model", default="final_model.pt", help="Path to the saved model (default: final_model.pt)")
    
    args = parser.parse_args()
    predict(args.file, args.model)
