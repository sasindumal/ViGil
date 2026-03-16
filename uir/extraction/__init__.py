"""Extraction module for recursive file unpacking and type identification."""

from .file_identifier import FileIdentifier, identify_file
from .recursive_engine import RecursiveExtractor
from .archive_extractor import ArchiveExtractor
from .disk_image_extractor import DiskImageExtractor
from .msi_extractor import MSIExtractor

__all__ = [
    "FileIdentifier",
    "identify_file",
    "RecursiveExtractor",
    "ArchiveExtractor",
    "DiskImageExtractor",
    "MSIExtractor",
]
