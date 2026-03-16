"""
Archive Extractor Module

Handles extraction of various archive formats: ZIP, RAR, 7z, TAR, GZ.
"""

import os
import zipfile
import tarfile
import gzip
import shutil
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
    
    
class ArchiveExtractor:
    """
    Extracts contents from various archive formats.
    
    Supports: ZIP, RAR, 7z, TAR, GZ, TAR.GZ
    """
    
    def __init__(self, output_dir: Optional[Path] = None, max_files: int = 1000):
        """
        Initialize the archive extractor.
        
        Args:
            output_dir: Directory for extracted files (uses temp dir if None)
            max_files: Maximum number of files to extract
        """
        self.output_dir = output_dir
        self.max_files = max_files
    
    def can_extract(self, file_type: FileType) -> bool:
        """Check if this extractor can handle the file type."""
        return file_type in (
            FileType.ZIP, FileType.SEVENZIP, FileType.RAR,
            FileType.GZ, FileType.TAR, FileType.CAB
        )
    
    def extract(self, file_path: Path, output_dir: Optional[Path] = None) -> ExtractionResult:
        """
        Extract an archive file.
        
        Args:
            file_path: Path to the archive
            output_dir: Override output directory
            
        Returns:
            ExtractionResult with list of extracted files
        """
        file_path = Path(file_path)
        out_dir = output_dir or self.output_dir or Path(tempfile.mkdtemp())
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        
        # Detect archive type by extension and magic
        ext = file_path.suffix.lower()
        
        try:
            if ext == '.zip' or self._is_zip(file_path):
                return self._extract_zip(file_path, out_dir)
            elif ext == '.7z':
                return self._extract_7z(file_path, out_dir)
            elif ext == '.rar':
                return self._extract_rar(file_path, out_dir)
            elif ext in ('.tar', '.tar.gz', '.tgz'):
                return self._extract_tar(file_path, out_dir)
            elif ext == '.gz' and not file_path.stem.endswith('.tar'):
                return self._extract_gzip(file_path, out_dir)
            elif ext == '.cab':
                return self._extract_cab(file_path, out_dir)
            else:
                return ExtractionResult(
                    success=False,
                    extracted_files=[],
                    error=f"Unsupported archive type: {ext}"
                )
        except Exception as e:
            return ExtractionResult(
                success=False,
                extracted_files=[],
                error=str(e)
            )
    
    def _is_zip(self, file_path: Path) -> bool:
        """Check if file is a ZIP by magic bytes."""
        try:
            with open(file_path, 'rb') as f:
                return f.read(4) == b'PK\x03\x04'
        except Exception:
            return False
    
    def _safe_extract_path(self, base_dir: Path, member_path: str) -> Optional[Path]:
        """
        Validate and create safe extraction path.
        
        Prevents path traversal attacks (e.g., ../../../etc/passwd).
        """
        # Normalize the path and remove leading slashes
        member_path = member_path.lstrip('/\\')
        member_path = os.path.normpath(member_path)
        
        # Reject if path tries to escape
        if member_path.startswith('..') or os.path.isabs(member_path):
            return None
        
        target = base_dir / member_path
        
        # Verify the target is within base_dir
        try:
            target.resolve().relative_to(base_dir.resolve())
        except ValueError:
            return None
        
        return target
    
    def _extract_zip(self, file_path: Path, output_dir: Path) -> ExtractionResult:
        """Extract ZIP archive."""
        extracted = []
        
        with zipfile.ZipFile(file_path, 'r') as zf:
            members = zf.namelist()[:self.max_files]
            
            for member in members:
                # Skip directories
                if member.endswith('/'):
                    continue
                
                target = self._safe_extract_path(output_dir, member)
                if target is None:
                    continue
                
                # Create parent directories
                target.parent.mkdir(parents=True, exist_ok=True)
                
                # Extract file
                try:
                    with zf.open(member) as src, open(target, 'wb') as dst:
                        shutil.copyfileobj(src, dst)
                    extracted.append(target)
                except Exception:
                    continue
        
        return ExtractionResult(success=True, extracted_files=extracted)
    
    def _extract_7z(self, file_path: Path, output_dir: Path) -> ExtractionResult:
        """Extract 7z archive."""
        extracted = []
        
        try:
            import py7zr
            
            with py7zr.SevenZipFile(file_path, mode='r') as archive:
                # Get all file names
                names = archive.getnames()[:self.max_files]
                
                # Extract to temp then move with path validation
                archive.extractall(path=output_dir)
                
                for name in names:
                    target = output_dir / name
                    if target.exists() and target.is_file():
                        extracted.append(target)
            
            return ExtractionResult(success=True, extracted_files=extracted)
        except ImportError:
            return ExtractionResult(
                success=False,
                extracted_files=[],
                error="py7zr not installed"
            )
    
    def _extract_rar(self, file_path: Path, output_dir: Path) -> ExtractionResult:
        """Extract RAR archive."""
        extracted = []
        
        try:
            import rarfile
            
            with rarfile.RarFile(file_path, 'r') as rf:
                members = rf.namelist()[:self.max_files]
                
                for member in members:
                    if rf.getinfo(member).is_dir():
                        continue
                    
                    target = self._safe_extract_path(output_dir, member)
                    if target is None:
                        continue
                    
                    target.parent.mkdir(parents=True, exist_ok=True)
                    
                    try:
                        rf.extract(member, output_dir)
                        extracted.append(output_dir / member)
                    except Exception:
                        continue
            
            return ExtractionResult(success=True, extracted_files=extracted)
        except ImportError:
            return ExtractionResult(
                success=False,
                extracted_files=[],
                error="rarfile not installed"
            )
    
    def _extract_tar(self, file_path: Path, output_dir: Path) -> ExtractionResult:
        """Extract TAR/TAR.GZ archive."""
        extracted = []
        
        # Determine mode
        mode = 'r:gz' if file_path.suffix in ('.gz', '.tgz') else 'r'
        if str(file_path).endswith('.tar.gz'):
            mode = 'r:gz'
        
        with tarfile.open(file_path, mode) as tf:
            members = tf.getmembers()[:self.max_files]
            
            for member in members:
                if not member.isfile():
                    continue
                
                target = self._safe_extract_path(output_dir, member.name)
                if target is None:
                    continue
                
                target.parent.mkdir(parents=True, exist_ok=True)
                
                try:
                    # Extract to buffer first for safety
                    f = tf.extractfile(member)
                    if f:
                        with open(target, 'wb') as dst:
                            shutil.copyfileobj(f, dst)
                        extracted.append(target)
                except Exception:
                    continue
        
        return ExtractionResult(success=True, extracted_files=extracted)
    
    def _extract_gzip(self, file_path: Path, output_dir: Path) -> ExtractionResult:
        """Extract single GZIP file."""
        # Output name is the input without .gz
        out_name = file_path.stem
        target = output_dir / out_name
        
        try:
            with gzip.open(file_path, 'rb') as src:
                with open(target, 'wb') as dst:
                    shutil.copyfileobj(src, dst)
            
            return ExtractionResult(success=True, extracted_files=[target])
        except Exception as e:
            return ExtractionResult(success=False, extracted_files=[], error=str(e))
    
    def _extract_cab(self, file_path: Path, output_dir: Path) -> ExtractionResult:
        """Extract CAB archive (Windows Cabinet)."""
        # CAB extraction typically requires platform-specific tools
        # Try using cabextract if available, otherwise fall back
        import subprocess
        
        extracted = []
        
        try:
            # Try expand.exe on Windows
            if os.name == 'nt':
                result = subprocess.run(
                    ['expand', str(file_path), '-F:*', str(output_dir)],
                    capture_output=True,
                    timeout=60
                )
                if result.returncode == 0:
                    # Collect extracted files
                    for item in output_dir.iterdir():
                        if item.is_file():
                            extracted.append(item)
                    return ExtractionResult(success=True, extracted_files=extracted)
        except Exception:
            pass
        
        return ExtractionResult(
            success=False,
            extracted_files=[],
            error="CAB extraction not available"
        )
