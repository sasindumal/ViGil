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
    from ..config import TrainingConfig, ModelConfig
    
    data_dir = Path(args.data_dir)
    
    if not data_dir.exists():
        logger.error(f"Data directory not found: {data_dir}")
        return 1
    
    # Create dataset
    logger.info(f"Loading dataset from: {data_dir}")
    dataset = CPGDataset(data_dir)
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
    
    # Stratified split to maintain class balance
    from sklearn.model_selection import train_test_split
    indices = list(range(len(dataset)))
    
    train_indices, val_indices = train_test_split(
        indices,
        test_size=0.2,
        stratify=labels,
        random_state=42
    )
    
    train_dataset = torch.utils.data.Subset(dataset, train_indices)
    val_dataset = torch.utils.data.Subset(dataset, val_indices)
    
    logger.info(f"Train: {len(train_indices)}, Val: {len(val_indices)} (stratified)")
    
    # Create model
    model_config = ModelConfig(
        hidden_dim=args.hidden_dim,
        num_layers=args.num_layers,
        num_heads=args.num_heads,
        num_classes=2
    )
    
    model = HeterogeneousGraphTransformer(
        input_dim=256,
        hidden_dim=model_config.hidden_dim,
        num_layers=model_config.num_layers,
        num_heads=model_config.num_heads,
        num_classes=model_config.num_classes
    )
    
    # Training config
    train_config = TrainingConfig(
        batch_size=args.batch_size,
        learning_rate=args.lr,
        num_epochs=args.epochs,
        checkpoint_dir=Path(args.checkpoint_dir)
    )
    
    # Train
    trainer = Trainer(model, train_config)
    history = trainer.train(train_dataset, val_dataset)
    
    logger.info(f"Training complete. Best val accuracy: {trainer.best_val_acc:.4f}")
    
    # Evaluate
    if args.test:
        from torch.utils.data import DataLoader
        from ..model.dataset import collate_cpg_batch
        
        val_loader = DataLoader(val_dataset, batch_size=args.batch_size, collate_fn=collate_cpg_batch)
        metrics = trainer.evaluate(val_loader)
        
        evaluator = Evaluator()
        evaluator.print_report(metrics['predictions'], metrics['labels'])
    
    return 0


def cmd_predict(args):
    """Run prediction on a file."""
    import torch
    from .processor import FileProcessor
    from ..model.hgt import HeterogeneousGraphTransformer
    from ..model.dataset import CPGData
    from ..config import UIRConfig
    
    model_path = Path(args.model)
    input_path = Path(args.input)
    
    if not model_path.exists():
        logger.error(f"Model not found: {model_path}")
        return 1
    
    # Load model
    checkpoint = torch.load(model_path, map_location='cpu')
    model = HeterogeneousGraphTransformer()
    model.load_state_dict(checkpoint['model_state'])
    model.eval()
    
    # Process file
    config = UIRConfig()
    processor = FileProcessor(config)
    cpg = processor.process(input_path)
    
    if not cpg:
        logger.error("Failed to process file")
        return 1
    
    # TODO: Convert CPG to tensor data and run prediction
    # This requires implementing the full embedding pipeline
    
    logger.info("Prediction complete")
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
    train_parser.add_argument('--epochs', type=int, default=100)
    train_parser.add_argument('--batch-size', type=int, default=32)
    train_parser.add_argument('--lr', type=float, default=1e-4)
    train_parser.add_argument('--hidden-dim', type=int, default=256)
    train_parser.add_argument('--num-layers', type=int, default=4)
    train_parser.add_argument('--num-heads', type=int, default=8)
    train_parser.add_argument('--checkpoint-dir', default='./checkpoints')
    train_parser.add_argument('--test', action='store_true', help='Run evaluation')
    
    # Predict command
    predict_parser = subparsers.add_parser('predict', help='Run prediction')
    predict_parser.add_argument('--model', '-m', required=True, help='Model checkpoint')
    predict_parser.add_argument('--input', '-i', required=True, help='Input file')
    
    args = parser.parse_args()
    
    if args.command == 'process':
        return cmd_process(args)
    elif args.command == 'batch':
        return cmd_batch(args)
    elif args.command == 'train':
        return cmd_train(args)
    elif args.command == 'predict':
        return cmd_predict(args)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
