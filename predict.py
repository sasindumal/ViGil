"""
predict.py — ViGil Standalone Malware Predictor

Run inference with the trained JointMalwareModel on a single file.

Architecture matches traning_notebook/vigil.ipynb exactly:
  OptimizedHGT   (CPG graph,  HIDDEN=384, LAYERS=6) → 768-dim
  OptimizedCNN   (ConvNeXt-Tiny grayscale image)     → 512-dim
  OptimizedRansomFormerEncoder (bytes + API imports) → 256-dim
  OptimizedFusion (Deep Residual MLP)    fused 1536  → 2-class

Usage:
    python predict.py --file suspicious.exe
    python predict.py --file sample.dll --model models/01/models/joint_model.pt --samples 30
    python predict.py --file document.pdf --verbose
    python predict.py --file sample.exe --json

Requirements:
    pip install torch torchvision pillow numpy
"""

import argparse
import sys
import json
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("vigil.predict")

# ── Default paths ─────────────────────────────────────────────────────────────
_PROJECT_ROOT  = Path(__file__).resolve().parent
_DEFAULT_MODEL = _PROJECT_ROOT / "models" / "01" / "models" / "joint_model.pt"
_MODEL_CONFIG  = _PROJECT_ROOT / "models" / "01" / "model_config.json"

# ── Canonical architecture config (notebook values, used as safe fallback) ────
_NOTEBOOK_CFG = {
    "embedding_dim":  320,
    "hidden_dim":     384,
    "num_heads":      8,
    "num_layers":     6,
    "num_classes":    2,
    "fused_dim":      1536,   # HGT(768) + CNN(512) + RF(256)
    "byte_seq_len":   1024,
    "max_apis":       256,
    "api_vocab_size": 4096,
    "label_map":      {"0": "BENIGN", "1": "MALWARE"},
}


def _load_model_cfg(checkpoint_path: Path = None) -> dict:
    """Read model_config.json if available, fall back to notebook defaults."""
    cfg = {**_NOTEBOOK_CFG}
    if _MODEL_CONFIG.exists():
        with open(_MODEL_CONFIG) as fh:
            on_disk = json.load(fh)
        cfg.update(on_disk)

    if checkpoint_path and checkpoint_path.exists():
        try:
            import torch
            ckpt = torch.load(checkpoint_path, map_location="cpu")
            state = ckpt.get("model_state", ckpt)
            if "hgt.proj.0.weight" in state:
                weight_shape = state["hgt.proj.0.weight"].shape
                if len(weight_shape) == 2:
                    detected_dim = weight_shape[1]
                    if detected_dim != cfg.get("embedding_dim"):
                        logger.info(f"Auto-detected embedding_dim={detected_dim} from checkpoint (was {cfg.get('embedding_dim')})")
                        cfg["embedding_dim"] = detected_dim
        except Exception as e:
            logger.warning(f"Could not auto-detect embedding_dim from checkpoint: {e}")
    return cfg


def _build_model(cfg: dict, device: "torch.device"):
    """Reconstruct the exact notebook architecture."""
    from uir.model.optimized_models import build_model
    return build_model(cfg, device)


def _load_checkpoint(model, checkpoint_path: Path, device):
    """Load model weights from a .pt checkpoint."""
    import torch

    if not checkpoint_path.exists():
        raise FileNotFoundError(
            f"Checkpoint not found: {checkpoint_path}\n"
            "Train the model first via traning_notebook/vigil.ipynb on Kaggle, "
            "then place the checkpoint at models/01/models/joint_model.pt"
        )

    logger.info(f"Loading checkpoint: {checkpoint_path}")
    ckpt  = torch.load(checkpoint_path, map_location=device)
    state = ckpt.get("model_state", ckpt)   # handle both wrapped and bare state_dict
    model.load_state_dict(state, strict=False)
    model.eval()
    logger.info("Checkpoint loaded.")
    return model


def _extract_features(file_path: Path, cfg: dict, device, verbose: bool):
    """
    Extract all four modality features from a single file.

    Returns a namespace with:
        .x, .edge_index, .node_types, .edge_types  — CPG / HGT inputs
        .image                                      — [3, 224, 224]
        .pe_bytes                                   — [1, 1024]
        .api_tokens                                 — [max_apis]
    """
    import torch
    import torchvision.transforms as T
    from uir.pipeline.processor import FileProcessor
    from uir.config import UIRConfig
    from uir.model.dataset import CPGDataset
    from uir.extraction.image_generator import pe_to_grayscale_image
    from uir.extraction.pe_feature_extractor import extract_ransomformer_features

    config    = UIRConfig()
    processor = FileProcessor(config)

    # ── 1. CPG extraction ─────────────────────────────────────────────────────
    if verbose:
        logger.info("Extracting Code Property Graph …")
    cpg = processor.process(file_path, use_cache=False)
    if cpg is None:
        raise RuntimeError(
            f"CPG extraction failed for {file_path}. "
            "Ensure the uir package and its dependencies are installed."
        )

    # Convert CPG → tensor data (node features, edge index, etc.)
    _dummy = CPGDataset(cpg_dir=file_path.parent, embedding_dim=cfg.get("embedding_dim", 320))
    data   = _dummy._cpg_to_data(cpg)

    # ── 2. Grayscale byte-image ───────────────────────────────────────────────
    if verbose:
        logger.info("Generating grayscale byte-image …")
    img    = pe_to_grayscale_image(file_path, target_size=224).convert("RGB")
    img_tf = T.Compose([
        T.ToTensor(),
        T.Normalize(mean=[0.485, 0.456, 0.406],
                    std=[0.229, 0.224, 0.225]),
    ])
    data.image = img_tf(img)                              # [3, 224, 224]

    # ── 3. RansomFormer inputs ────────────────────────────────────────────────
    if verbose:
        logger.info("Extracting byte sequence and API import tokens …")
    api_names = list(cpg.metadata.get("imports", [])) if cpg.metadata else []
    pe_bytes, api_tokens = extract_ransomformer_features(
        file_path,
        api_names = api_names,
        seq_len   = cfg.get("byte_seq_len", 1024),
        max_apis  = cfg.get("max_apis",      256),
    )
    data.pe_bytes   = pe_bytes    # [1, 1024]
    data.api_tokens = api_tokens  # [max_apis]

    return data


def _collate_single(data, device):
    """Wrap a single CPGData into a batch-1 tuple for the model."""
    from uir.model.dataset import collate_cpg_batch
    batch_data, batch_idx = collate_cpg_batch([data])
    batch_data = batch_data.to(device)
    batch_idx  = batch_idx.to(device)
    return batch_data, batch_idx


def predict(
    file_path: Path,
    checkpoint_path: Path = _DEFAULT_MODEL,
    num_samples: int = 20,
    verbose: bool = False,
    device_str: str = "auto",
) -> dict:
    """
    Run quad-modal BNN inference on a single file.

    Args:
        file_path:       Path to the file to analyse.
        checkpoint_path: Path to joint_model.pt checkpoint.
        num_samples:     Monte Carlo dropout sampling iterations.
        verbose:         Log intermediate steps.
        device_str:      'auto' | 'cpu' | 'cuda' | 'mps'.

    Returns:
        dict with keys: file, prediction, label, confidence, variance
    """
    import torch

    # ── Device selection ──────────────────────────────────────────────────────
    if device_str == "auto":
        if torch.cuda.is_available():
            device = torch.device("cuda")
        elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            device = torch.device("mps")
        else:
            device = torch.device("cpu")
    else:
        device = torch.device(device_str)

    logger.info(f"Device: {device}")

    # ── Config + model ────────────────────────────────────────────────────────
    cfg   = _load_model_cfg(checkpoint_path)
    model = _build_model(cfg, device)
    model = _load_checkpoint(model, checkpoint_path, device)

    # ── Validate input file ───────────────────────────────────────────────────
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"Target file not found: {file_path}")

    # ── Feature extraction ────────────────────────────────────────────────────
    data = _extract_features(file_path, cfg, device, verbose)
    batch_data, batch_idx = _collate_single(data, device)

    # ── Monte Carlo inference ─────────────────────────────────────────────────
    if verbose:
        logger.info(f"Running Monte Carlo inference (T={num_samples} samples) …")

    preds, confidence, variance = model.predict_with_confidence(
        batch_data.x,          batch_data.edge_index,
        batch_data.node_types, batch_data.edge_types,
        batch_idx,             batch_data.image,
        batch_data.pe_bytes,   batch_data.api_tokens,
        num_samples=num_samples,
    )

    label_map  = cfg.get("label_map", {"0": "BENIGN", "1": "MALWARE"})
    pred_class = preds[0].item()
    label      = label_map.get(str(pred_class), "UNKNOWN")
    conf       = confidence[0].item()
    var        = variance[0].item()

    return {
        "file":       str(file_path),
        "prediction": pred_class,
        "label":      label,
        "confidence": conf,
        "variance":   var,
    }


def _print_result(result: dict):
    """Pretty-print the prediction result to stdout."""
    label = result["label"]
    conf  = result["confidence"] * 100
    var   = result["variance"]

    try:
        import os
        supports_color = os.isatty(sys.stdout.fileno())
    except Exception:
        supports_color = False

    G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; RESET = "\033[0m"
    if not supports_color:
        G = R = Y = RESET = ""

    label_col = f"{G}{label}{RESET}" if label == "BENIGN" else f"{R}{label}{RESET}"

    border = "=" * 66
    print(f"\n{border}")
    print("  ViGil — Quad-Modal Malware Detection")
    print("  Architecture: OptimizedHGT + ConvNeXt + AttentionByte + CLSTransformerAPI → DeepResMLP")
    print(border)
    print(f"  File:        {Path(result['file']).name}")
    print(f"  Verdict:     {label_col}")
    print(f"  Confidence:  {Y}{conf:.2f}%{RESET}")
    print(f"  Uncertainty: {var:.6f}  (epistemic variance, MC dropout)")
    print(f"{border}\n")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "ViGil — Quad-Modal Malware Detector\n"
            "Architecture: OptimizedHGT + ConvNeXt-Tiny + AttentionByteEncoder"
            " + CLSTransformerAPI → DeepResMLP"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python predict.py --file suspicious.exe
  python predict.py --file sample.dll --samples 30 --verbose
  python predict.py --file doc.pdf --model models/01/models/joint_model.pt --json
        """,
    )
    parser.add_argument("--file",    "-f", required=True,
                        help="Path to the file to analyse.")
    parser.add_argument("--model",   "-m", default=str(_DEFAULT_MODEL),
                        help=f"Checkpoint path (default: {_DEFAULT_MODEL}).")
    parser.add_argument("--samples", "-s", type=int, default=20,
                        help="Monte Carlo dropout samples (default: 20).")
    parser.add_argument("--device",  default="auto",
                        choices=["auto", "cpu", "cuda", "mps"],
                        help="Compute device (default: auto).")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose progress logging.")
    parser.add_argument("--json",    action="store_true",
                        help="Output result as JSON.")

    args = parser.parse_args()

    if not args.verbose:
        logging.getLogger().setLevel(logging.WARNING)

    try:
        result = predict(
            file_path       = Path(args.file),
            checkpoint_path = Path(args.model),
            num_samples     = args.samples,
            verbose         = args.verbose,
            device_str      = args.device,
        )
    except FileNotFoundError as exc:
        print(f"\n[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"\n[ERROR] Prediction failed: {exc}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_result(result)


if __name__ == "__main__":
    main()
