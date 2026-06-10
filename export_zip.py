"""
export_zip.py — ViGil Deployment Packager

Creates a self-contained vigil_deploy.zip after Kaggle training.
The ZIP contains model weights + predict.py + all required source files.

Architecture (matches traning_notebook/vigil.ipynb):
  OptimizedHGT + ConvNeXt-Tiny + AttentionByte + CLSTransformerAPI → DeepResMLP
  Fused dim: 768 (HGT) + 512 (CNN) + 256 (RF) = 1536

Usage:
    python export_zip.py --checkpoint models/01/models/joint_model.pt \
                         --output vigil_deploy.zip

Or via CLI:
    python -m uir.pipeline.cli export-zip \
        --checkpoint models/01/models/joint_model.pt \
        --output vigil_deploy.zip
"""

import argparse
import json
import shutil
import zipfile
from pathlib import Path

# Source files to bundle inside the ZIP (relative to project root)
# optimized_models.py contains the exact notebook architecture classes.
_MODEL_SOURCES = [
    "uir/model/optimized_models.py",
    "uir/extraction/pe_feature_extractor.py",
]

_STANDALONE_PREDICTOR = "predict.py"

# Matches MODEL_CONFIG written by traning_notebook/vigil.ipynb
_MODEL_CONFIG = {
    "embedding_dim": 256,
    "hidden_dim":    384,
    "num_heads":     8,
    "num_layers":    6,
    "num_classes":   2,
    "fused_dim":     1536,  # HGT(768) + ConvNeXt(512) + RF(256)
    "byte_seq_len":  1024,
    "max_apis":      256,
    "api_vocab_size": 4096,
    "label_map":     {"0": "BENIGN", "1": "MALWARE"},
    "architecture":  "OptimizedHGT + ConvNeXt + AttentionByte + CLSTransformerAPI → DeepResMLP",
}


def create_deploy_zip(checkpoint_path: Path, output_zip: Path):
    """
    Build vigil_deploy.zip containing:

      vigil_deploy/
        models/
          joint_model.pt          ← full state_dict
        src/
          joint_model.py
          resnet_extractor.py
          ransomformer.py
          hgt.py
          pe_feature_extractor.py
        predict.py                ← standalone predictor
        model_config.json         ← architecture params
        README.md                 ← usage guide
    """
    checkpoint_path = Path(checkpoint_path)
    output_zip      = Path(output_zip)
    project_root    = Path(__file__).resolve().parent

    if not checkpoint_path.exists():
        raise FileNotFoundError(f"Checkpoint not found: {checkpoint_path}")

    print(f"📦  Building deployment ZIP from {checkpoint_path}")

    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:

        # ── Model weights ─────────────────────────────────────────────────────
        zf.write(checkpoint_path, "vigil_deploy/models/joint_model.pt")
        print(f"   ✓  models/joint_model.pt ({checkpoint_path.stat().st_size / 1e6:.1f} MB)")

        # ── Source files ──────────────────────────────────────────────────────
        for rel_src in _MODEL_SOURCES:
            src = project_root / rel_src
            dst = f"vigil_deploy/src/{src.name}"
            if src.exists():
                zf.write(src, dst)
                print(f"   ✓  src/{src.name}")
            else:
                print(f"   ⚠  src/{src.name} not found — skipping")

        # ── Standalone predictor ──────────────────────────────────────────────
        predictor = project_root / _STANDALONE_PREDICTOR
        if predictor.exists():
            zf.write(predictor, "vigil_deploy/predict.py")
            print("   ✓  predict.py")
        else:
            print("   ⚠  predict.py not found — skipping")

        # ── model_config.json ─────────────────────────────────────────────────
        cfg = dict(_MODEL_CONFIG)
        try:
            import torch
            ckpt = torch.load(checkpoint_path, map_location="cpu")
            state = ckpt.get("model_state", ckpt)
            if "hgt.proj.0.weight" in state:
                weight_shape = state["hgt.proj.0.weight"].shape
                if len(weight_shape) == 2:
                    detected_dim = weight_shape[1]
                    if detected_dim != cfg["embedding_dim"]:
                        print(f"   ✓  detected embedding_dim = {detected_dim} from checkpoint (updating config)")
                        cfg["embedding_dim"] = detected_dim
        except Exception as e:
            print(f"   ⚠  Could not load checkpoint for config auto-detect: {e}")

        zf.writestr(
            "vigil_deploy/model_config.json",
            json.dumps(cfg, indent=2),
        )
        print("   ✓  model_config.json")

        # ── README ────────────────────────────────────────────────────────────
        readme = _build_readme()
        zf.writestr("vigil_deploy/README.md", readme)
        print("   ✓  README.md")

    size_mb = output_zip.stat().st_size / 1e6
    print(f"\n✅  vigil_deploy.zip created: {output_zip}  ({size_mb:.1f} MB)")
    print("    Usage:  unzip vigil_deploy.zip")
    print("            python vigil_deploy/predict.py --model vigil_deploy/models/joint_model.pt "
          "--file suspicious.exe")


def _build_readme() -> str:
    return """\
# ViGil Deployment Package

## Quad-Modal Malware Detection
**Architecture:** OptimizedHGT + ConvNeXt-Tiny + AttentionByteEncoder + CLSTransformerAPI → DeepResMLP

### Requirements
```
pip install torch torchvision numpy pillow
```

### Predict on a single file
```bash
python predict.py --file suspicious.exe
# or from extracted zip:
python vigil_deploy/predict.py --model vigil_deploy/models/joint_model.pt --file suspicious.exe
```

### Output
```
==================================================================
  ViGil — Quad-Modal Malware Detection
  Architecture: OptimizedHGT + ConvNeXt + AttentionByte + CLSTransformerAPI → DeepResMLP
==================================================================
  File:        suspicious.exe
  Verdict:     MALWARE
  Confidence:  94.23%
  Uncertainty: 0.000412  (epistemic variance, MC dropout)
==================================================================
```

### Architecture Details
| Stream         | Input               | Encoder                          | Output   |
|----------------|---------------------|----------------------------------|----------|
| CPG Graph      | Node/edge tensors   | OptimizedHGT (6 layers, 8 heads) | 768-dim  |
| Grayscale Img  | 224×224 RGB tensor  | ConvNeXt-Tiny                    | 512-dim  |
| PE Bytes       | [1×1024] float      | 3-layer 1D CNN + attention pool  | 256-dim  |
| API Imports    | 256 token IDs       | Pre-LN Transformer + CLS token   | 256-dim  |
| **Fusion**     | concat [B, 1536]    | DeepResMLP (MC dropout)          | 2-class  |
"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ViGil Deployment Packager")
    parser.add_argument("--checkpoint", "-c", required=True,
                        help="Path to best_joint_model_*.pt checkpoint")
    parser.add_argument("--output", "-o", default="vigil_deploy.zip",
                        help="Output ZIP file path")
    args = parser.parse_args()
    create_deploy_zip(Path(args.checkpoint), Path(args.output))
