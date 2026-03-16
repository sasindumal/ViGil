# UIR - Unified Instruction Representation

A deep learning framework for heterogeneous malware analysis using Code Property Graphs and Heterogeneous Graph Transformers.

## Overview

UIR provides a unified approach to malware analysis across diverse file formats:
- **Native Binaries**: PE (EXE, DLL), ELF, Mach-O
- **Scripts**: JavaScript, Python, PowerShell, VBScript, Batch, Shell
- **Documents**: Office documents (DOC, DOCX, XLS, XLSM), PDF, RTF
- **Launchers**: LNK shortcuts, URL files
- **Archives**: ZIP, RAR, 7z, ISO, MSI (recursive extraction)

## Installation

```bash
cd c:\Users\sasin\Documents\ViGiL
pip install -e .
```

For GPU support:
```bash
pip install -e ".[gpu]"
```

## Quick Start

### Process a Single File

```bash
# Get file information
uir process --input file.exe --info

# Generate CPG
uir process --input file.exe --output file.cpg.json --verbose
```

### Batch Processing

```bash
# Get dataset statistics
uir batch --input-dir ./malware_dataset --stats

# Process entire directory
uir batch --input-dir ./malware_dataset --output-dir ./cpgs

uir batch --input-dir ./malware_dataset --output-dir ./cpgs_default --device-profile cpu_default
uir batch --input-dir ./malware_dataset --output-dir ./cpgs_m4 --device-profile m4
uir batch --input-dir ./malware_dataset --output-dir ./cpgs_gtx --device-profile gtx_1650_ti

# Install optimized deps
pip install -e ".[m4]"     # Apple M4
pip install -e ".[gpu]"    # NVIDIA GTX
pip install -e ".[fast]"   # Both
```

### Train Model

```bash
# Train on generated CPGs
python -m uir.pipeline.cli train --data-dir ./cpgs --epochs 50 --test
uir train --data-dir ./cpgs --epochs 50 --test
```

## Architecture

```
uir/
├── extraction/          # File type ID, archive extraction
├── lifting/             # Binary, script, document, launcher lifting
├── cpg/                 # Code Property Graph schema and builder
├── tokenization/        # Vocabulary, BPE, embeddings
├── model/               # HGT model, trainer, evaluator
└── pipeline/            # End-to-end processing, CLI
```

## Usage Example

```python
from uir.pipeline.processor import FileProcessor
from uir.config import UIRConfig

# Initialize
config = UIRConfig()
processor = FileProcessor(config)

# Process file
cpg = processor.process("sample.exe")

print(f"Nodes: {cpg.num_nodes}, Edges: {cpg.num_edges}")
print(f"Methods: {len(cpg.get_methods())}")

# Save CPG
cpg.save("sample.cpg.json")
```

## License

MIT License
