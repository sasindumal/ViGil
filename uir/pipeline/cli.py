"""
UIR Command-Line Interface

CLI for malware analysis using the Unified Instruction Representation system.
"""

import argparse
import sys
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def cmd_process(args):
    """Process a single file."""
    from .processor import FileProcessor
    from ..config import UIRConfig
    
    config = UIRConfig()
    processor = FileProcessor(config)
    
    input_path = Path(args.input)
    
    if not input_path.exists():
        logger.error(f"File not found: {input_path}")
        return 1
    
    # Get file info
    if args.info:
        info = processor.get_file_info(input_path)
        print("\nFile Information:")
        for key, value in info.items():
            print(f"  {key}: {value}")
        return 0
    
    # Process file
    logger.info(f"Processing: {input_path}")
    cpg = processor.process(input_path)
    
    if cpg:
        logger.info(f"CPG generated: {cpg.num_nodes} nodes, {cpg.num_edges} edges")
        
        if args.output:
            output_path = Path(args.output)
            cpg.save(output_path)
            logger.info(f"Saved to: {output_path}")
        
        if args.verbose:
            print(f"\nMethods: {len(cpg.get_methods())}")
            print(f"Calls: {len(cpg.get_calls())}")
            if cpg.metadata.get('imports'):
                print(f"Imports: {len(cpg.metadata['imports'])}")
        
        return 0
    else:
        logger.error("Failed to generate CPG")
        return 1


def cmd_batch(args):
    """Process a directory of files."""
    from .batch_processor import BatchProcessor
    from ..config import UIRConfig
    
    config = UIRConfig()
    device_profile = getattr(args, 'device_profile', None)
    processor = BatchProcessor(
        config,
        max_workers=args.workers,
        device_profile=device_profile
    )
    
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir) if args.output_dir else None
    
    if not input_dir.exists():
        logger.error(f"Directory not found: {input_dir}")
        return 1
    
    # Get stats first
    if args.stats:
        stats = processor.get_dataset_stats(input_dir)
        print("\nDataset Statistics:")
        print(f"  Total files: {stats['total_files']}")
        print(f"  Total size: {stats['total_size_mb']:.2f} MB")
        print(f"  Device profile: {stats.get('device_profile', 'unknown')}")
        print(f"  Recommended workers: {stats.get('recommended_workers', 'N/A')}")
        print("\nBy extension:")
        for ext, count in sorted(stats['by_extension'].items(), key=lambda x: -x[1])[:20]:
            print(f"  {ext or '(none)'}: {count}")
        return 0
    
    # Process
    logger.info(f"Processing directory: {input_dir}")
    result = processor.process_directory(
        input_dir,
        output_dir,
        recursive=not args.no_recursive,
        extensions=args.extensions.split(',') if args.extensions else None
    )
    
    print(f"\nResults:")
    print(f"  Total: {result.total}")
    print(f"  Successful: {result.successful}")
    print(f"  Failed: {result.failed}")
    print(f"  Device profile: {result.device_profile}")
    if result.elapsed_seconds > 0:
        print(f"  Speed: {result.total / result.elapsed_seconds:.1f} files/sec")
        print(f"  Elapsed: {result.elapsed_seconds:.1f}s")
    
    if args.verbose and result.errors:
        print("\nErrors:")
        for path, error in list(result.errors.items())[:10]:
            print(f"  {path}: {error}")
    
    return 0 if result.failed == 0 else 1


def cmd_train(args):
    """Train the HGT model."""
    import torch
    from ..model.hgt import HeterogeneousGraphTransformer
    from ..model.dataset import CPGDataset
    from ..model.trainer import Trainer
    from ..model.evaluator import Evaluator
    from ..config import UIRConfig
    
    data_dir = Path(args.data_dir)
    
    if not data_dir.exists():
        logger.error(f"Data directory not found: {data_dir}")
        return 1
    
    # Initialize config (automatically loads from .env)
    config = UIRConfig()
    
    # Resolve Model parameters
    hidden_dim = args.hidden_dim if args.hidden_dim is not None else config.model.hidden_dim
    num_layers = args.num_layers if args.num_layers is not None else config.model.num_layers
    num_heads = args.num_heads if args.num_heads is not None else config.model.num_heads
    
    model_config = config.model.model_copy(update={
        'hidden_dim': hidden_dim,
        'num_layers': num_layers,
        'num_heads': num_heads
    })
    
    # Resolve Training parameters
    epochs = args.epochs if args.epochs is not None else config.training.num_epochs
    batch_size = args.batch_size if args.batch_size is not None else config.training.batch_size
    lr = args.lr if args.lr is not None else config.training.learning_rate
    checkpoint_dir = Path(args.checkpoint_dir) if args.checkpoint_dir is not None else config.training.checkpoint_dir
    
    train_config = config.training.model_copy(update={
        'num_epochs': epochs,
        'batch_size': batch_size,
        'learning_rate': lr,
        'checkpoint_dir': checkpoint_dir
    })
    
    # ── Auto-detect dataset type ──────────────────────────────────────────────
    # If .feat.pt files exist → use fast PreExtractedDataset (no CPG parsing)
    # Otherwise fall back to CPGDataset (reads .cpg.json files)
    from ..model.dataset import CPGDataset, PreExtractedDataset
    feat_files = list(data_dir.rglob("*.feat.pt"))
    if feat_files:
        logger.info(f"Found {len(feat_files)} .feat.pt files — using PreExtractedDataset")
        dataset = PreExtractedDataset(data_dir)
    else:
        logger.info("No .feat.pt files found — using CPGDataset (reads .cpg.json)")
        dataset = CPGDataset(data_dir, embedding_dim=model_config.embedding_dim)
    logger.info(f"Dataset size: {len(dataset)}")
    
    # Get labels for stratified split
    labels = []
    for i in range(len(dataset)):
        data = dataset[i]
        labels.append(data.y.item())
    
    # Count class distribution
    num_malware = sum(labels)
    num_benign = len(labels) - num_malware
    logger.info(f"Class distribution: {num_benign} benign, {num_malware} malware")
    
    # Stratified 3-way split: Train, Val, Test to maintain class balance
    from sklearn.model_selection import train_test_split
    indices = list(range(len(dataset)))
    
    # Step 1: Split off the test set
    train_val_indices, test_indices = train_test_split(
        indices,
        test_size=train_config.test_ratio,
        stratify=labels,
        random_state=42
    )
    
    # Step 2: Split the remaining into train and validation
    relative_val_ratio = train_config.val_ratio / (train_config.train_ratio + train_config.val_ratio)
    train_val_labels = [labels[idx] for idx in train_val_indices]
    
    train_indices, val_indices = train_test_split(
        train_val_indices,
        test_size=relative_val_ratio,
        stratify=train_val_labels,
        random_state=42
    )
    
    train_dataset = torch.utils.data.Subset(dataset, train_indices)
    val_dataset = torch.utils.data.Subset(dataset, val_indices)
    test_dataset = torch.utils.data.Subset(dataset, test_indices)
    
    logger.info(f"Train: {len(train_indices)}, Val: {len(val_indices)}, Test: {len(test_indices)} (stratified)")
    
    # Create quad-modal joint model components
    from ..model.joint_model import BayesianClassifier, JointMalwareModel
    from ..model.resnet_extractor import ResNetFeatureExtractor
    from ..model.ransomformer import RansomFormerEncoder
    from ..model.joint_trainer import JointTrainer

    hgt_model    = HeterogeneousGraphTransformer(
        input_dim=model_config.embedding_dim,
        hidden_dim=model_config.hidden_dim,
        num_layers=model_config.num_layers,
        num_heads=model_config.num_heads,
        num_classes=model_config.num_classes
    )
    resnet_extractor = ResNetFeatureExtractor(pretrained=True)
    ransomformer     = RansomFormerEncoder()

    # Fused dim: HGT(512) + ResNet(384) + RansomFormer(256) = 1152
    bnn_classifier = BayesianClassifier(
        in_features=model_config.hidden_dim * 2 + 384 + 256,
        num_classes=model_config.num_classes
    )

    model = JointMalwareModel(hgt_model, resnet_extractor, ransomformer, bnn_classifier)
    
    # Train
    trainer = JointTrainer(model, train_config)
    history = trainer.train(train_dataset, val_dataset)
    
    logger.info(f"Training complete. Best val F1 score: {trainer.best_val_f1:.4f}")
    
    # Evaluate on the held-out test set
    if args.test:
        from torch.utils.data import DataLoader
        from ..model.dataset import collate_cpg_batch
        
        test_loader = DataLoader(test_dataset, batch_size=train_config.batch_size, collate_fn=collate_cpg_batch)
        metrics = trainer.evaluate(test_loader)
        
        evaluator = Evaluator()
        evaluator.print_report(metrics['predictions'], metrics['labels'])
    
    return 0


def cmd_predict(args):
    """Run prediction using the quad-modal joint model (HGT+ResNet+RansomFormer+BNN)."""
    import torch
    import torchvision.transforms as transforms
    from .processor import FileProcessor
    from ..model.hgt import HeterogeneousGraphTransformer
    from ..model.joint_model import BayesianClassifier, JointMalwareModel
    from ..model.resnet_extractor import ResNetFeatureExtractor
    from ..model.ransomformer import RansomFormerEncoder
    from ..model.dataset import CPGDataset, collate_cpg_batch
    from ..extraction.image_generator import pe_to_grayscale_image
    from ..extraction.pe_feature_extractor import extract_ransomformer_features
    from ..config import UIRConfig
    
    model_path = Path(args.model)
    input_path = Path(args.input)
    
    if not model_path.exists():
        logger.error(f"Model not found: {model_path}")
        return 1
    
    config = UIRConfig()
    
    # Reconstruct identical joint architecture for loading state
    hgt_model = HeterogeneousGraphTransformer(
        input_dim=config.model.embedding_dim,
        hidden_dim=config.model.hidden_dim,
        num_layers=config.model.num_layers,
        num_heads=config.model.num_heads,
        num_classes=config.model.num_classes
    )
    resnet_extractor = ResNetFeatureExtractor(pretrained=False)  # weights loaded from checkpoint
    ransomformer     = RansomFormerEncoder()
    bnn_classifier   = BayesianClassifier(
        in_features=config.model.hidden_dim * 2 + 384 + 256,  # 512+384+256 = 1152
        num_classes=config.model.num_classes
    )
    model = JointMalwareModel(hgt_model, resnet_extractor, ransomformer, bnn_classifier)
    
    # Load model checkpoint
    logger.info(f"Loading joint model checkpoint from {model_path}")
    checkpoint = torch.load(model_path, map_location='cpu')
    
    # Auto-detect if checkpoint was trained using fallback CNN or LeViT LoRA
    checkpoint_keys = checkpoint['model_state'].keys()
    has_fallback = any(k.startswith('levit.fallback_conv') for k in checkpoint_keys)
    has_peft = any('lora_' in k for k in checkpoint_keys)
    
    if has_fallback and not has_peft:
        logger.info("Checkpoint matches Fallback CNN mode. Toggling fallback in LeViT extractor.")
        model.levit.is_fallback = True
        
    model.load_state_dict(checkpoint['model_state'], strict=False)
    model.eval()
    
    # Process single file (CPG extraction)
    processor = FileProcessor(config)
    logger.info(f"Processing CPG for: {input_path}")
    cpg = processor.process(input_path, use_cache=False)
    
    if not cpg:
        logger.error("Failed to build CPG")
        return 1
        
    # Convert CPG to features using CPGDataset converter
    dataset = CPGDataset(cpg_dir=Path("./cpg_cache")) # Dummy target dir
    data = dataset._cpg_to_data(cpg)
    
    # Generate and load corresponding grayscale image
    logger.info(f"Generating grayscale image representation...")
    img = pe_to_grayscale_image(input_path, target_size=224)
    # Convert single-channel 'L' grayscale to 3-channel 'RGB' so that
    # transforms.ToTensor() produces shape [3, 224, 224] as expected by
    # the ImageNet-normalisation stats and the LeViT/CNN feature extractor.
    img = img.convert('RGB')
    img_transform = transforms.Compose([
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])
    ])
    data.image = img_transform(img)

    # ── RansomFormer inputs: sliding-window bytes + API tokens ────────────────
    logger.info("Extracting PE byte sequence and API import tokens...")
    api_names = list(cpg.metadata.get('imports', [])) if cpg.metadata else []
    pe_bytes_tensor, api_tokens_tensor = extract_ransomformer_features(
        input_path, api_names=api_names
    )
    data.pe_bytes   = pe_bytes_tensor    # [1, 1024]
    data.api_tokens = api_tokens_tensor  # [max_apis]
    
    # Collate single element into a batch
    batch_data, batch_idx = collate_cpg_batch([data])
    
    # Run BNN inference with Monte Carlo sampling (T = 20)
    logger.info("Running Bayesian Neural Network Monte Carlo sampling (quad-modal)...")
    preds, confidence, variance = model.predict_with_confidence(
        batch_data.x, batch_data.edge_index,
        batch_data.node_types, batch_data.edge_types,
        batch_idx, batch_data.image,
        batch_data.pe_bytes, batch_data.api_tokens,
        num_samples=20
    )
    
    pred_class = preds[0].item()
    conf_score = confidence[0].item()
    epistemic_var = variance[0].item()
    
    label_map = {0: "BENIGN", 1: "MALWARE"}
    print("\n" + "=" * 62)
    print("   QUAD-MODAL MALWARE DETECTION  (HGT+ResNet+RansomFormer+BNN)")
    print("=" * 62)
    print(f"  Target File:       {input_path.name}")
    print(f"  Malware Detection: {label_map.get(pred_class, 'UNKNOWN')}")
    print(f"  Confidence Level:  {conf_score * 100:.2f}%")
    print(f"  Epistemic Var:     {epistemic_var:.6f}")
    print("=" * 62 + "\n")
    
    return 0

def cmd_export_zip(args):
    """Package trained models and standalone predictor into a deployment ZIP."""
    from pathlib import Path as _P
    checkpoint = _P(args.checkpoint)
    output_zip = _P(args.output) if args.output else _P("vigil_deploy.zip")
    # Delegate to export_zip script at project root
    import sys, importlib.util
    spec = importlib.util.spec_from_file_location(
        "export_zip",
        _P(__file__).resolve().parent.parent.parent / "export_zip.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.create_deploy_zip(checkpoint, output_zip)
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="UIR - Unified Instruction Representation for Malware Analysis"
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Process command
    process_parser = subparsers.add_parser('process', help='Process a single file')
    process_parser.add_argument('--input', '-i', required=True, help='Input file')
    process_parser.add_argument('--output', '-o', help='Output CPG file')
    process_parser.add_argument('--info', action='store_true', help='Show file info only')
    process_parser.add_argument('--verbose', '-v', action='store_true')
    process_parser.add_argument(
        '--device-profile',
        choices=['auto', 'm4', 'gtx_1650_ti', 'cpu_default'],
        default='auto',
        help='Hardware optimization profile (default: auto-detect)'
    )
    
    # Batch command
    batch_parser = subparsers.add_parser('batch', help='Process a directory')
    batch_parser.add_argument('--input-dir', '-i', required=True, help='Input directory')
    batch_parser.add_argument('--output-dir', '-o', help='Output directory')
    batch_parser.add_argument('--workers', type=int, default=4, help='Number of workers')
    batch_parser.add_argument('--extensions', help='Comma-separated extensions to include')
    batch_parser.add_argument('--no-recursive', action='store_true')
    batch_parser.add_argument('--stats', action='store_true', help='Show stats only')
    batch_parser.add_argument('--verbose', '-v', action='store_true')
    batch_parser.add_argument(
        '--device-profile',
        choices=['auto', 'm4', 'gtx_1650_ti', 'cpu_default'],
        default='auto',
        help='Hardware optimization profile (default: auto-detect)'
    )
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train the model')
    train_parser.add_argument('--data-dir', '-d', required=True, help='CPG data directory')
    train_parser.add_argument('--epochs', type=int, default=None)
    train_parser.add_argument('--batch-size', type=int, default=None)
    train_parser.add_argument('--lr', type=float, default=None)
    train_parser.add_argument('--hidden-dim', type=int, default=None)
    train_parser.add_argument('--num-layers', type=int, default=None)
    train_parser.add_argument('--num-heads', type=int, default=None)
    train_parser.add_argument('--checkpoint-dir', default=None)
    train_parser.add_argument('--test', action='store_true', help='Run evaluation')
    
    # Predict command
    predict_parser = subparsers.add_parser('predict', help='Run prediction')
    predict_parser.add_argument('--model', '-m', required=True, help='Model checkpoint')
    predict_parser.add_argument('--input', '-i', required=True, help='Input file')
    
    # Export-zip command
    export_parser = subparsers.add_parser('export-zip', help='Package models into a deployment ZIP')
    export_parser.add_argument('--checkpoint', '-c', required=True, help='Path to best_joint_model_*.pt')
    export_parser.add_argument('--output', '-o', default='vigil_deploy.zip', help='Output ZIP path')

    args = parser.parse_args()

    if args.command == 'process':
        return cmd_process(args)
    elif args.command == 'batch':
        return cmd_batch(args)
    elif args.command == 'train':
        return cmd_train(args)
    elif args.command == 'predict':
        return cmd_predict(args)
    elif args.command == 'export-zip':
        return cmd_export_zip(args)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
