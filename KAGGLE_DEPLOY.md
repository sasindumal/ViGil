# 🚀 ViGil — Kaggle Training Guide

## Overview

**Workflow** — no PE binaries needed on Kaggle:
1. Extract features **locally** → `.feat.pt` files (via `uir batch`)
2. Zip `.feat.pt` files and upload to Kaggle dataset
3. Open `traning_notebook/vigil.ipynb` on Kaggle GPU and run it
4. Download `joint_model.pt` → place in `models/01/models/`
5. Run `python predict.py --file suspicious.exe` locally

> **Training is exclusively done via `traning_notebook/vigil.ipynb`.**

---

## Step 1: Extract Features Locally

Run the batch processor on your machine to generate `.feat.pt` feature bundles:

```bash
cd /path/to/ViGil

# Apple M4
uir batch --input-dir ./dataset/malwares --output-dir ./features/malwares --device-profile m4
uir batch --input-dir ./dataset/benigns  --output-dir ./features/benigns  --device-profile m4

# NVIDIA GPU
uir batch --input-dir ./dataset --output-dir ./features --device-profile gtx_1650_ti

# CPU fallback
uir batch --input-dir ./dataset --output-dir ./features --device-profile cpu_default
```

Each processed sample produces three files:
```
features/
  benigns/
    sample_a.cpg.json    ← Code Property Graph (optional, local only)
    sample_a.png         ← Grayscale byte-image (optional, local only)
    sample_a.feat.pt     ← ✅ All 4 modality tensors — upload this
  malwares/
    sample_x.feat.pt     ← ✅ Upload this
```

**Only `.feat.pt` files are uploaded to Kaggle.** The `.cpg.json` and `.png` files stay local.

---

## Step 2: Zip and Upload to Kaggle

```bash
# Zip only feature bundles
zip -r vigil_features.zip features/**/*.feat.pt
```

1. Go to [kaggle.com/datasets](https://www.kaggle.com/datasets) → **New Dataset**
2. Upload `vigil_features.zip`, name it **`vigil-features`**
3. Wait for processing → files will appear at `/kaggle/input/vigil-features/`

---

## Step 3: Upload Source Code

```bash
zip -r vigil_src.zip uir/ predict.py export_zip.py setup.py traning_notebook/
```

Upload as Kaggle dataset **`vigil-src`** → available at `/kaggle/input/vigil-src/`

---

## Step 4: Open Training Notebook on Kaggle

1. Go to [kaggle.com/code](https://www.kaggle.com/code) → **New Notebook**
2. Upload `traning_notebook/vigil.ipynb`
3. Click **Add Data** → add **`vigil-features`** and **`vigil-src`** datasets
4. Set **Accelerator → GPU T4 x2** (or P100)
5. Enable **Internet** in Settings (for `pip install pydantic tqdm`)

In **Cell 1**, set the correct input path:
```python
FEAT_DIR = Path('/kaggle/input/vigil-features')
```

---

## Step 5: Run & Download

1. Click **Run All**
2. Training runs for the configured number of epochs (~3–5h on T4 GPU)
3. After completion, go to the **Output** tab
4. Download **`joint_model.pt`**

---

## Step 6: Deploy the Trained Model Locally

```bash
# Place the checkpoint in the correct location
mkdir -p models/01/models
mv joint_model.pt models/01/models/joint_model.pt

# Run prediction
python predict.py --file suspicious.exe
```

### Example output

```
==================================================================
  ViGil — Quad-Modal Malware Detection
  Architecture: HGT + ResNet-50 + RansomFormer + BNN
==================================================================
  File:        suspicious.exe
  Verdict:     MALWARE
  Confidence:  94.23%
  Uncertainty: 0.000412  (epistemic variance)
==================================================================
```

---

## Step 7: (Optional) Create a Deployment ZIP

```bash
python export_zip.py \
    --checkpoint models/01/models/joint_model.pt \
    --output vigil_deploy.zip
```

This bundles all model source files + weights + `predict.py` into a portable archive.

---

## Quick Reference

| Item | Detail |
|------|--------|
| **GPU** | T4 x2 or P100 — enable for training |
| **Upload size** | ~30–100 MB for `.feat.pt` files (not GBs of PE files) |
| **Training time** | ~3–5h (50 epochs, ~9,500 samples, T4) |
| **Pre-installed** | `torch`, `torchvision`, `numpy`, `sklearn`, `matplotlib` |
| **Need to install** | `pydantic`, `tqdm` |
| **Session limit** | ~12h GPU / ~9h with internet |

## Architecture Summary

```
PE Binary
 ├─ CPG Graph     → HGT (4 layers, 8 heads)     → [B, 512]  ─┐
 ├─ Grayscale PNG → ResNet-50 (layer4 fine-tune) → [B, 384]  ─┤ → BNN → Prediction
 └─ Raw Bytes     → RansomFormer 1D CNN          → [B, 256]  ─┘   + Confidence %
    └─ API Imports   └─ Transformer (8L × 8H)                       + Uncertainty
                        └─ Cross-Modal Attention
```

| Stream | Encoder | Output |
|--------|---------|--------|
| CPG Graph | HGT Transformer | 512-dim |
| Grayscale Image | ResNet-50 (pretrained) | 384-dim |
| PE Bytes | 1D CNN (64→128 filters) | 256-dim |
| API Imports | Transformer (8L, 8H, 256-dim) | merged with bytes |
| **Fusion** | Concat → BNN (MC sampling) | 2-class + confidence |
