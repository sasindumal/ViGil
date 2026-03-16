"""Pipeline module for end-to-end processing."""

from .processor import FileProcessor
from .batch_processor import BatchProcessor
from .accelerator import (
    HardwareProfile, detect_hardware,
    get_optimal_workers, get_optimal_batch_size,
    AcceleratedStringExtractor, AcceleratedPatternScanner
)

__all__ = [
    "FileProcessor",
    "BatchProcessor",
    "HardwareProfile",
    "detect_hardware",
    "get_optimal_workers",
    "get_optimal_batch_size",
    "AcceleratedStringExtractor",
    "AcceleratedPatternScanner",
]
