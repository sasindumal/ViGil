"""
PE Feature Extractor

Extracts two RansomFormer input modalities from raw PE/binary files:
  1. pe_bytes  — Sliding-window byte sequence (chunk=512, stride=256) normalized
                 to a fixed [1, 1024] float tensor.
  2. api_tokens — API import names hashed to token IDs, padded/truncated to
                  max_apis length, returned as a long tensor [max_apis].

These are the exact preprocessing steps described in:
  "RansomFormer: A Cross-Modal Transformer Architecture for Ransomware
   Detection via the Fusion of Byte and API Features"
  Electronics 14(7):1245, 2025.  DOI: 10.3390/electronics14071245
"""

from pathlib import Path
from typing import List, Optional
import numpy as np
import torch
import logging

logger = logging.getLogger(__name__)

# ── Constants (match RansomFormer paper) ─────────────────────────────────────
CHUNK_SIZE: int = 512      # bytes per sliding window
STRIDE: int = 256          # overlap stride
BYTE_SEQ_LEN: int = 1024   # fixed output length fed to 1D CNN
API_VOCAB_SIZE: int = 4096 # hashing vocabulary for API names
MAX_APIS: int = 256        # max number of API tokens per sample
PAD_TOKEN: int = 0         # padding token ID


# ── Byte feature extraction ───────────────────────────────────────────────────

def extract_byte_sequence(file_path: Path, seq_len: int = BYTE_SEQ_LEN,
                          chunk_size: int = CHUNK_SIZE,
                          stride: int = STRIDE) -> torch.Tensor:
    """
    Read the ENTIRE file, apply a sliding window (chunk_size, stride) to create
    overlapping byte chunks, then aggregate each chunk by its mean value.
    The resulting chunk-mean sequence is flattened, standardised to [seq_len]
    by zero-padding or truncation, and returned as a float tensor in [0, 1].

    Args:
        file_path: Path to the PE / binary file.
        seq_len:   Fixed output length (default 1024).
        chunk_size: Sliding window size in bytes (default 512).
        stride:    Sliding window stride in bytes (default 256).

    Returns:
        Tensor of shape [1, seq_len]  — single-channel, ready for 1D CNN.
    """
    try:
        file_path = Path(file_path)
        if not file_path.exists():
            logger.warning(f"File not found for byte extraction: {file_path}")
            return torch.zeros(1, seq_len)

        with open(file_path, "rb") as fh:
            raw = np.frombuffer(fh.read(), dtype=np.uint8).astype(np.float32)

        if len(raw) == 0:
            return torch.zeros(1, seq_len)

        # ── Sliding window aggregation ────────────────────────────────────────
        # Each chunk contributes one value = mean byte value of that window.
        # This collapses the file into a sequence whose length depends on the
        # file size but is independent of byte count per position.
        chunk_means: List[float] = []
        pos = 0
        while pos < len(raw):
            chunk = raw[pos: pos + chunk_size]
            chunk_means.append(float(chunk.mean()))
            pos += stride

        chunk_arr = np.array(chunk_means, dtype=np.float32)

        # ── Normalise to [0, 1] ───────────────────────────────────────────────
        chunk_arr = chunk_arr / 255.0

        # ── Pad / truncate to fixed seq_len ──────────────────────────────────
        if len(chunk_arr) >= seq_len:
            chunk_arr = chunk_arr[:seq_len]
        else:
            pad = np.zeros(seq_len - len(chunk_arr), dtype=np.float32)
            chunk_arr = np.concatenate([chunk_arr, pad])

        return torch.from_numpy(chunk_arr).unsqueeze(0)  # [1, seq_len]

    except Exception as exc:
        logger.error(f"Byte extraction failed for {file_path}: {exc}")
        return torch.zeros(1, seq_len)


# ── API token extraction ──────────────────────────────────────────────────────

def _hash_api_name(name: str, vocab_size: int = API_VOCAB_SIZE) -> int:
    """
    Deterministic polynomial hash of an API name to a token ID in [1, vocab_size).
    ID 0 is reserved for padding.
    """
    name = name.lower().split("!")[-1]  # strip DLL prefix e.g. 'kernel32!VirtualAlloc'
    h = 5381
    for ch in name:
        h = ((h << 5) + h) + ord(ch)
        h &= 0xFFFFFFFF
    return (h % (vocab_size - 1)) + 1   # [1, vocab_size-1]


def extract_api_tokens(api_names: List[str],
                       max_apis: int = MAX_APIS,
                       vocab_size: int = API_VOCAB_SIZE) -> torch.Tensor:
    """
    Hash a list of API import name strings into token IDs and return as a
    padded / truncated long tensor of shape [max_apis].

    Args:
        api_names: List of API import strings (e.g. from CPG metadata).
        max_apis:  Fixed output length (default 256).
        vocab_size: Hash vocabulary size (default 4096).

    Returns:
        Tensor of shape [max_apis] with dtype=torch.long.
    """
    tokens = [_hash_api_name(n, vocab_size) for n in api_names if n]
    if not tokens:
        return torch.zeros(max_apis, dtype=torch.long)

    if len(tokens) >= max_apis:
        tokens = tokens[:max_apis]
    else:
        tokens += [PAD_TOKEN] * (max_apis - len(tokens))

    return torch.tensor(tokens, dtype=torch.long)


# ── Convenience: extract both from a CPG metadata dict ───────────────────────

def extract_ransomformer_features(
        file_path: Path,
        api_names: Optional[List[str]] = None,
        seq_len: int = BYTE_SEQ_LEN,
        max_apis: int = MAX_APIS) -> tuple:
    """
    High-level helper that returns (pe_bytes, api_tokens) ready for the model.

    Args:
        file_path:  Path to the PE file.
        api_names:  List of API import name strings. If None, returns zero tokens.
        seq_len:    Byte sequence output length.
        max_apis:   API token output length.

    Returns:
        (pe_bytes   [1, seq_len]   float32,
         api_tokens [max_apis]    int64)
    """
    pe_bytes = extract_byte_sequence(file_path, seq_len=seq_len)
    api_tokens = extract_api_tokens(api_names or [], max_apis=max_apis)
    return pe_bytes, api_tokens
