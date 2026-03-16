"""
Recursive Extraction Engine

Orchestrates recursive unpacking of nested containers and archives.
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Set
from dataclasses import dataclass, field
from collections import deque
import hashlib
import logging

from ..config import FileType, FileCategory, FILE_TYPE_TO_CATEGORY, ExtractionConfig
from .file_identifier import FileIdentifier, FileIdentification
from .archive_extractor import ArchiveExtractor
from .disk_image_extractor import DiskImageExtractor
from .msi_extractor import MSIExtractor


logger = logging.getLogger(__name__)


@dataclass
class ExtractedFile:
    """Information about an extracted file."""
    path: Path
    original_source: Path
    file_type: FileType
    category: FileCategory
    depth: int
    hash: str = ""
    
    
@dataclass
class RecursiveExtractionResult:
    """Result of recursive extraction."""
    success: bool
    extracted_files: List[ExtractedFile]
    leaf_files: List[ExtractedFile]  # Non-container files
    errors: List[str] = field(default_factory=list)
    total_processed: int = 0


class RecursiveExtractor:
    """
    Recursively extracts nested containers.
    
    Handles:
    - Nested archives (ZIP inside RAR inside ISO)
    - Polyglot detection and forking
    - Deduplication via content hashing
    - Depth limiting to prevent zip bombs
    """
    
    def __init__(self, config: Optional[ExtractionConfig] = None):
        """
        Initialize the recursive extractor.
        
        Args:
            config: Extraction configuration
        """
        self.config = config or ExtractionConfig()
        
        # Initialize sub-extractors
        self.file_identifier = FileIdentifier()
        self.archive_extractor = ArchiveExtractor(max_files=self.config.max_extracted_files)
        self.disk_extractor = DiskImageExtractor(max_files=self.config.max_extracted_files)
        self.msi_extractor = MSIExtractor(max_files=self.config.max_extracted_files)
        
        # Track seen file hashes for deduplication
        self._seen_hashes: Set[str] = set()
    
    def extract(self, file_path: Path, output_dir: Optional[Path] = None) -> RecursiveExtractionResult:
        """
        Recursively extract a file.
        
        Args:
            file_path: Path to the file to extract
            output_dir: Directory for extracted files
            
        Returns:
            RecursiveExtractionResult with all extracted files
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            return RecursiveExtractionResult(
                success=False,
                extracted_files=[],
                leaf_files=[],
                errors=[f"File not found: {file_path}"]
            )
        
        # Create output directory
        if output_dir is None:
            output_dir = Path(self.config.temp_dir or tempfile.mkdtemp())
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Clear seen hashes for this extraction
        self._seen_hashes.clear()
        
        # Process queue: (path, original_source, depth)
        queue = deque([(file_path, file_path, 0)])
        
        all_extracted: List[ExtractedFile] = []
        leaf_files: List[ExtractedFile] = []
        errors: List[str] = []
        total_processed = 0
        
        while queue and total_processed < self.config.max_extracted_files:
            current_path, original_source, depth = queue.popleft()
            total_processed += 1
            
            # Check depth limit
            if depth > self.config.max_recursion_depth:
                logger.warning(f"Max depth reached for {current_path}")
                continue
            
            try:
                # Identify file
                identification = self.file_identifier.identify(current_path)
                
                # Compute hash for deduplication
                file_hash = self._compute_hash(current_path)
                if file_hash in self._seen_hashes:
                    logger.debug(f"Skipping duplicate: {current_path}")
                    continue
                self._seen_hashes.add(file_hash)
                
                # Create extracted file info
                extracted_file = ExtractedFile(
                    path=current_path,
                    original_source=original_source,
                    file_type=identification.file_type,
                    category=identification.category,
                    depth=depth,
                    hash=file_hash
                )
                all_extracted.append(extracted_file)
                
                # Handle polyglots
                if identification.is_polyglot and self.config.enable_polyglot_detection:
                    for secondary_type in identification.secondary_types:
                        logger.info(f"Polyglot detected: {current_path} ({identification.file_type} + {secondary_type})")
                
                # Check if it's a container
                if self._is_container(identification.file_type):
                    # Create subdirectory for extracted contents
                    extract_subdir = output_dir / f"{current_path.stem}_extracted_{depth}"
                    extract_subdir.mkdir(parents=True, exist_ok=True)
                    
                    # Extract contents
                    children = self._extract_container(
                        current_path,
                        identification.file_type,
                        extract_subdir
                    )
                    
                    # Add children to queue
                    for child_path in children:
                        queue.append((child_path, original_source, depth + 1))
                else:
                    # It's a leaf file
                    leaf_files.append(extracted_file)
                    
            except Exception as e:
                errors.append(f"Error processing {current_path}: {str(e)}")
                logger.error(f"Error processing {current_path}: {e}")
        
        return RecursiveExtractionResult(
            success=len(errors) == 0 or len(leaf_files) > 0,
            extracted_files=all_extracted,
            leaf_files=leaf_files,
            errors=errors,
            total_processed=total_processed
        )
    
    def _is_container(self, file_type: FileType) -> bool:
        """Check if a file type is a container."""
        category = FILE_TYPE_TO_CATEGORY.get(file_type, FileCategory.UNKNOWN)
        return category in (FileCategory.ARCHIVE, FileCategory.INSTALLER)
    
    def _extract_container(self, file_path: Path, file_type: FileType, output_dir: Path) -> List[Path]:
        """Extract a container and return paths to extracted files."""
        extracted_paths = []
        
        try:
            # Select appropriate extractor
            if file_type in (FileType.ZIP, FileType.SEVENZIP, FileType.RAR, 
                           FileType.GZ, FileType.TAR, FileType.CAB):
                result = self.archive_extractor.extract(file_path, output_dir)
                if result.success:
                    extracted_paths.extend(result.extracted_files)
                    
            elif file_type in (FileType.ISO, FileType.IMG):
                result = self.disk_extractor.extract(file_path, output_dir)
                if result.success:
                    extracted_paths.extend(result.extracted_files)
                    
            elif file_type == FileType.MSI:
                result = self.msi_extractor.extract(file_path, output_dir)
                if result.success:
                    extracted_paths.extend(result.extracted_files)
                    # Also save extracted scripts
                    for script_name, script_content in result.scripts:
                        script_path = output_dir / f"{script_name}.extracted_script"
                        with open(script_path, 'w', encoding='utf-8') as f:
                            f.write(script_content)
                        extracted_paths.append(script_path)
                        
            # Handle ZIP-based formats (JAR, APK, DOCX, etc.)
            elif file_type in (FileType.JAR, FileType.APK, FileType.DOCX, 
                              FileType.XLSX, FileType.PPTX, FileType.DOCM,
                              FileType.XLSM):
                result = self.archive_extractor.extract(file_path, output_dir)
                if result.success:
                    extracted_paths.extend(result.extracted_files)
                    
        except Exception as e:
            logger.error(f"Extraction failed for {file_path}: {e}")
        
        return extracted_paths
    
    def _compute_hash(self, file_path: Path, chunk_size: int = 8192) -> str:
        """Compute SHA256 hash of a file."""
        hasher = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""
    
    def cleanup(self, output_dir: Path):
        """Clean up extracted files."""
        try:
            if output_dir.exists():
                shutil.rmtree(output_dir)
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")
