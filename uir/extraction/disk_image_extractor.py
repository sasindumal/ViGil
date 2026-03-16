"""
Disk Image Extractor Module

Handles extraction of disk images: ISO, IMG, VHD.
"""

import os
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass
import tempfile

from ..config import FileType


@dataclass 
class ExtractionResult:
    """Result of an extraction operation."""
    success: bool
    extracted_files: List[Path]
    error: Optional[str] = None


class DiskImageExtractor:
    """
    Extracts contents from disk image formats.
    
    Supports: ISO, IMG (limited), VHD (limited)
    """
    
    def __init__(self, output_dir: Optional[Path] = None, max_files: int = 1000):
        """
        Initialize the disk image extractor.
        
        Args:
            output_dir: Directory for extracted files
            max_files: Maximum number of files to extract
        """
        self.output_dir = output_dir
        self.max_files = max_files
    
    def can_extract(self, file_type: FileType) -> bool:
        """Check if this extractor can handle the file type."""
        return file_type in (FileType.ISO, FileType.IMG, FileType.VHD)
    
    def extract(self, file_path: Path, output_dir: Optional[Path] = None) -> ExtractionResult:
        """
        Extract a disk image.
        
        Args:
            file_path: Path to the disk image
            output_dir: Override output directory
            
        Returns:
            ExtractionResult with list of extracted files
        """
        file_path = Path(file_path)
        out_dir = output_dir or self.output_dir or Path(tempfile.mkdtemp())
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        
        ext = file_path.suffix.lower()
        
        try:
            if ext == '.iso':
                return self._extract_iso(file_path, out_dir)
            elif ext == '.img':
                return self._extract_img(file_path, out_dir)
            elif ext == '.vhd':
                return self._extract_vhd(file_path, out_dir)
            else:
                return ExtractionResult(
                    success=False,
                    extracted_files=[],
                    error=f"Unsupported disk image type: {ext}"
                )
        except Exception as e:
            return ExtractionResult(
                success=False,
                extracted_files=[],
                error=str(e)
            )
    
    def _extract_iso(self, file_path: Path, output_dir: Path) -> ExtractionResult:
        """Extract ISO image using pycdlib."""
        extracted = []
        
        try:
            import pycdlib
            
            iso = pycdlib.PyCdlib()
            iso.open(str(file_path))
            
            file_count = 0
            
            # Try to walk the Joliet tree first (better long filename support)
            try:
                for dirname, dirlist, filelist in iso.walk(joliet=True):
                    for filename in filelist:
                        if file_count >= self.max_files:
                            break
                        
                        iso_path = f"{dirname}/{filename}"
                        
                        # Create safe local path
                        local_path = self._safe_path(output_dir, dirname, filename)
                        if local_path is None:
                            continue
                        
                        local_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        try:
                            iso.get_file_from_iso(
                                str(local_path),
                                joliet_path=iso_path
                            )
                            extracted.append(local_path)
                            file_count += 1
                        except Exception:
                            continue
            except Exception:
                # Fall back to Rock Ridge or ISO9660
                for dirname, dirlist, filelist in iso.walk(rr_path='/'):
                    for filename in filelist:
                        if file_count >= self.max_files:
                            break
                        
                        iso_path = f"{dirname}/{filename}"
                        
                        local_path = self._safe_path(output_dir, dirname, filename)
                        if local_path is None:
                            continue
                        
                        local_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        try:
                            iso.get_file_from_iso(
                                str(local_path),
                                rr_path=iso_path
                            )
                            extracted.append(local_path)
                            file_count += 1
                        except Exception:
                            continue
            
            iso.close()
            return ExtractionResult(success=True, extracted_files=extracted)
            
        except ImportError:
            return ExtractionResult(
                success=False,
                extracted_files=[],
                error="pycdlib not installed"
            )
        except Exception as e:
            return ExtractionResult(
                success=False,
                extracted_files=[],
                error=f"ISO extraction failed: {str(e)}"
            )
    
    def _extract_img(self, file_path: Path, output_dir: Path) -> ExtractionResult:
        """
        Extract IMG disk image.
        
        IMG files can be various formats - try common ones.
        """
        # First, try treating it as an ISO
        result = self._extract_iso(file_path, output_dir)
        if result.success and result.extracted_files:
            return result
        
        # IMG extraction is platform-specific and complex
        # For now, return unsupported
        return ExtractionResult(
            success=False,
            extracted_files=[],
            error="IMG extraction requires platform-specific mounting"
        )
    
    def _extract_vhd(self, file_path: Path, output_dir: Path) -> ExtractionResult:
        """
        Extract VHD virtual hard disk.
        
        VHD extraction typically requires Windows APIs or specialized tools.
        """
        # VHD extraction is complex and platform-specific
        return ExtractionResult(
            success=False,
            extracted_files=[],
            error="VHD extraction requires platform-specific APIs"
        )
    
    def _safe_path(self, base_dir: Path, dirname: str, filename: str) -> Optional[Path]:
        """Create a safe extraction path, preventing path traversal."""
        # Normalize and clean the path
        clean_dir = dirname.lstrip('/\\').replace('\\', '/')
        clean_name = filename.replace('\\', '/').split('/')[-1]
        
        # Skip if any component tries to escape
        if '..' in clean_dir or '..' in clean_name:
            return None
        
        # Build target path
        if clean_dir and clean_dir != '.':
            target = base_dir / clean_dir / clean_name
        else:
            target = base_dir / clean_name
        
        # Verify it's within base_dir
        try:
            target.resolve().relative_to(base_dir.resolve())
        except ValueError:
            return None
        
        return target
