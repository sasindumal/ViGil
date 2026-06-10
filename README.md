# ViGil — Quad-Modal Malware Detection

A deep learning framework for heterogeneous malware analysis combining **Code Property Graphs** (CPG) with an **Optimized Heterogeneous Graph Transformer** (OptimizedHGT), grayscale byte-images (ConvNeXt-Tiny), and byte + API-import features (AttentionByteEncoder + CLSTransformerAPI) fused through a **Deep Residual MLP** with Monte Carlo dropout uncertainty.

## Architecture

```
                   ┌────────────────────────────────────────────────────────────┐
  File             │                 ViGil Quad-Modal Model                      │
  ──────►  CPG  ──►│  OptimizedHGT   (768-dim, JK+attn pool)                   │
         Image ──►│  ConvNeXt-Tiny  (512-dim)                                  ├──► DeepResMLP ──► BENIGN / MALWARE
         Bytes ──►│  AttentionByte  (256-dim)  ─ cross-modal ─►                │                + Confidence %
          APIs ──►│  CLSTransformer (256-dim)                                  │                + Uncertainty
                   └────────────────────────────────────────────────────────────┘
                             Fused: 768 + 512 + 256 = 1536-dim
```

| Stream          | Input                  | Encoder                                    | Output  |
|-----------------|------------------------|--------------------------------------------|---------|
| CPG Graph       | Node/edge tensors      | OptimizedHGT (6 layers, 8 heads, JK)       | 768-dim |
| Grayscale Image | 224×224 RGB tensor     | ConvNeXt-Tiny (ImageNet pretrained)        | 512-dim |
| PE Bytes        | [1×1024] float         | 3-layer 1D CNN + attention pool            | 256-dim |
| API Imports     | [256] token IDs        | Pre-LN Transformer + CLS token + local CNN | 256-dim |
| **Fusion**      | concat → [B, 1536]     | Deep Residual MLP (MC dropout)             | 2-class |

---

## Supported File Types

- **Native Binaries**: PE (EXE, DLL, SYS), ELF, Mach-O
- **Scripts**: JavaScript, Python, PowerShell, VBScript, Batch, Shell
- **Documents**: Office (DOC, DOCX, XLS, XLSM), PDF, RTF
- **Launchers**: LNK shortcuts, URL files
- **Archives**: ZIP, RAR, 7z, ISO, MSI (recursive extraction)

---

## Installation

```bash
cd /path/to/ViGil
pip install -e .
```

For GPU support:
```bash
pip install -e ".[gpu]"
```

---

## Quick Prediction

Run prediction on any file using the pre-trained model:

```bash
python predict.py --file suspicious.exe
```

### Prediction Options

| Flag             | Default                           | Description                      |
|------------------|-----------------------------------|----------------------------------|
| `--file / -f`    | *(required)*                      | File to analyse                  |
| `--model / -m`   | `models/01/models/joint_model.pt` | Path to trained checkpoint       |
| `--samples / -s` | `20`                              | Monte Carlo dropout samples      |
| `--device`       | `auto`                            | `auto` / `cpu` / `cuda` / `mps`  |
| `--verbose / -v` | off                               | Verbose logging                  |
| `--json`         | off                               | Output raw JSON                  |

### Example Output

```
==================================================================
  ViGil — Quad-Modal Malware Detection
  Architecture: OptimizedHGT + ConvNeXt + AttentionByte + CLSTransformerAPI → DeepResMLP
==================================================================
  File:        suspicious.exe
  Verdict:     MALWARE
  Confidence:  94.38%
  Uncertainty: 0.000217  (epistemic variance, MC dropout)
==================================================================
```

---

## Training Workflow

Training is done **exclusively** through the Jupyter notebook:

```
traning_notebook/vigil.ipynb
```

**Steps:**
1. **Feature Extraction** — process raw samples into `.feat.pt` bundles using `uir batch`.
2. **Package for Kaggle** — zip the `.feat.pt` bundles for Kaggle dataset upload.
3. **Train on Kaggle GPU** — run `vigil.ipynb` on T4/P100 GPU.
4. **Deploy** — download `joint_model.pt` → place in `models/01/models/`.
5. **Predict** — `python predict.py --file suspicious.exe`

### Feature Extraction (CLI)

```bash
# Process samples into CPG + .feat.pt files
uir batch --input-dir ./dataset/malwares --output-dir ./features/malwares --device-profile m4
uir batch --input-dir ./dataset/benigns  --output-dir ./features/benigns  --device-profile m4

# NVIDIA GPU profile
uir batch --input-dir ./dataset --output-dir ./features --device-profile gtx_1650_ti
```

---

## Project Structure

```
ViGil/
├── predict.py                  ← Standalone prediction script
├── export_zip.py               ← Package model for deployment
├── models/
│   └── 01/
│       ├── models/
│       │   └── joint_model.pt  ← Trained weights (~158 MB)
│       ├── model_config.json   ← Architecture params
│       ├── confusion_matrix.png
│       └── README.md
├── traning_notebook/
│   └── vigil.ipynb             ← Training notebook (Kaggle GPU)
├── uir/
│   ├── extraction/             ← File-type detection, archive & PE extraction
│   ├── lifting/                ← Binary, script, document lifting → CPG
│   ├── cpg/                    ← Code Property Graph schema & builder
│   ├── tokenization/           ← Vocabulary, BPE, embeddings
│   ├── model/
│   │   ├── optimized_models.py ← Notebook-accurate model classes (use this)
│   │   ├── dataset.py          ← CPGDataset, PreExtractedDataset, .feat.pt loading
│   │   └── ...                 ← HGT, trainers, evaluator (library support)
│   └── pipeline/               ← End-to-end processor, batch processor, CLI
├── Docs/                       ← Architecture diagrams & documentation
├── requirements.txt
└── setup.py
```

---

## CLI Reference

```bash
# Single file CPG generation
uir process --input file.exe --output file.cpg.json --verbose

# Batch processing (generates .feat.pt files)
uir batch --input-dir ./dataset --output-dir ./features

# Predict via CLI
uir predict --model models/01/models/joint_model.pt --input suspicious.exe

# Export trained model as deployment ZIP
python export_zip.py --checkpoint models/01/models/joint_model.pt --output vigil_deploy.zip
```

---

## References

- **RansomFormer**: Byte + API cross-modal encoder inspiration.  
  *Electronics 14(7):1245, 2025.* [DOI:10.3390/electronics14071245](https://doi.org/10.3390/electronics14071245)
- **ConvNeXt-Tiny**: Image backbone for malware texture extraction.
- **HGT**: Heterogeneous Graph Transformer for CPG-based malware analysis.

---

## License

MIT License
