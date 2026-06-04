# 🚀 ViGil — Kaggle Training Guide

## Overview

**New workflow** — no PE binaries needed on Kaggle:
1. Extract features **locally** (Mac M4) → `.feat.pt` files
2. Upload only `.feat.pt` files to Kaggle
3. Train on Kaggle GPU
4. Download `vigil_deploy.zip`

---

## Step 1: Extract Features Locally

Run the batch processor on your Mac:

```bash
cd /Users/sasindumalhara/Workspace/ViGil

python -m uir.pipeline.cli batch \
    --input-dir ./malware_dataset \
    --output-dir ./output/ \
    --device-profile m4
```

This generates three files per PE binary:
```
output/
  benigns/
    sample_a.cpg.json    ← Code Property Graph
    sample_a.png         ← Grayscale image
    sample_a.feat.pt     ← ✅ All 4 modality tensors (for Kaggle)
  malwares/
    sample_x.feat.pt     ← ✅ Upload this
```

**Only the `.feat.pt` files are needed for Kaggle training.**

---

## Step 2: Upload Feature Files to Kaggle

1. Zip only the `.feat.pt` files:
```bash
cd /Users/sasindumalhara/Workspace/ViGil
zip -r vigil_features.zip output/**/*.feat.pt
```

2. Go to [kaggle.com/datasets](https://www.kaggle.com/datasets) → **New Dataset**
3. Upload `vigil_features.zip`, name it **`vigil-features`**
4. Wait for processing to complete

> Your files will be at `/kaggle/input/vigil-features/`

---

## Step 3: Upload Source Code (Optional)

If you want to use the uir package on Kaggle:
```bash
zip -r vigil_src.zip uir/ predict.py export_zip.py setup.py
```
Upload as dataset **`vigil-src`** → available at `/kaggle/input/vigil-src/`

---

## Step 4: Create Kaggle Notebook

1. Go to [kaggle.com/code](https://www.kaggle.com/code) → **New Notebook**
2. **Import notebook**: Upload `vigil_kaggle.ipynb` (in project root)
3. Click **Add Data** → add your **`vigil-features`** dataset
4. Set **Accelerator → GPU T4 x2** (or P100)
5. Enable **Internet** in Settings (for `pip install pydantic`)

---

## Step 5: Configure Notebook Paths

In **Cell 1**, update the dataset name if you used a different name:
```python
INPUT_DIR = Path('/kaggle/input/vigil-features')   # ← your dataset slug
```

---

## Step 6: Run & Download

1. Click **Run All**
2. Training runs for 50 epochs (~3–5h on T4 GPU)
3. After completion, go to **Output** tab
4. Download **`vigil_deploy.zip`**

---

## Step 7: Use vigil_deploy.zip for Prediction

```bash
unzip vigil_deploy.zip

python vigil_deploy/predict.py \
    --model  vigil_deploy/models/joint_model.pt \
    --file   suspicious.exe

# Output:
# ================================================================
#    QUAD-MODAL MALWARE DETECTION  (HGT+ResNet+RansomFormer+BNN)
# ================================================================
#   File:        suspicious.exe
#   Prediction:  MALWARE
#   Confidence:  94.23%
#   Uncertainty: 0.000412
# ================================================================
```

---

## Step 8: Or Export ZIP Locally (After Local Training)

```bash
python -m uir.pipeline.cli export-zip \
    --checkpoint checkpoints/best_joint_model_*.pt \
    --output vigil_deploy.zip
```

---

## Quick Reference

| Item | Detail |
|------|--------|
| **GPU** | T4 x2 or P100 — always enable |
| **Upload size** | ~30–100 MB for `.feat.pt` files (not GBs of PE files) |
| **Training time** | ~3–5h (50 epochs, 9,499 samples, T4) |
| **Pre-installed** | `torch`, `torchvision`, `numpy`, `sklearn`, `matplotlib`, `seaborn` |
| **Need to install** | `pydantic`, `tqdm` |
| **Session limit** | ~12h GPU / ~9h with internet |
| **Output** | `vigil_deploy.zip` — self-contained, ~50–200MB |

## Architecture

```
PE Binary
 ├─ CPG Graph     → HGT (4 layers, 8 heads)     → [B, 512]  ─┐
 ├─ Grayscale PNG → ResNet-50 (layer4 fine-tune) → [B, 384]  ─┤ → BNN → Prediction
 └─ Raw Bytes     → RansomFormer 1D CNN          → [B, 256]  ─┘   + Confidence
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
