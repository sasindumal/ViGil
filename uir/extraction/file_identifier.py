"""
File Type Identification Module

Uses magic bytes and extension-based detection to identify file types.
"""

import os
from pathlib import Path
from typing import Optional, Tuple
from dataclasses import dataclass
import struct

from ..config import FileType, FileCategory, FILE_TYPE_TO_CATEGORY


@dataclass
class FileIdentification:
    """Result of file identification."""
    file_type: FileType
    category: FileCategory
    mime_type: Optional[str] = None
    confidence: float = 1.0
    is_polyglot: bool = False
    secondary_types: list = None
    
    def __post_init__(self):
        if self.secondary_types is None:
            self.secondary_types = []


# Magic byte signatures for common file types
MAGIC_SIGNATURES = {
    # PE Executable (Windows)
    b'MZ': FileType.EXE,
    
    # ELF (Linux/Unix)
    b'\x7fELF': FileType.ELF,
    
    # Mach-O (macOS)
    b'\xfe\xed\xfa\xce': FileType.MACHO,  # 32-bit
    b'\xfe\xed\xfa\xcf': FileType.MACHO,  # 64-bit
    b'\xce\xfa\xed\xfe': FileType.MACHO,  # 32-bit reversed
    b'\xcf\xfa\xed\xfe': FileType.MACHO,  # 64-bit reversed
    
    # Java
    b'\xca\xfe\xba\xbe': FileType.CLASS,
    b'PK\x03\x04': FileType.ZIP,  # ZIP/JAR/APK
    
    # Archives
    b'Rar!\x1a\x07': FileType.RAR,
    b'7z\xbc\xaf\x27\x1c': FileType.SEVENZIP,
    b'\x1f\x8b': FileType.GZ,
    
    # Documents
    b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': FileType.DOC,  # OLE Compound
    b'%PDF': FileType.PDF,
    b'{\\rtf': FileType.RTF,
    
    # ISO
    # CD001 at offset 32769 or 34817
    
    # MSI (also OLE)
    
    # LNK
    b'\x4c\x00\x00\x00\x01\x14\x02\x00': FileType.LNK,
}


# Extension to file type mapping
EXTENSION_MAP = {
    # Native Binaries
    '.exe': FileType.EXE,
    '.dll': FileType.DLL,
    '.sys': FileType.SYS,
    '.scr': FileType.SCR,
    '.cpl': FileType.CPL,
    '.so': FileType.SO,
    
    # Managed Code
    '.jar': FileType.JAR,
    '.class': FileType.CLASS,
    '.apk': FileType.APK,
    '.dex': FileType.DEX,
    
    # Scripts
    '.js': FileType.JS,
    '.vbs': FileType.VBS,
    '.ps1': FileType.PS1,
    '.bat': FileType.BAT,
    '.cmd': FileType.CMD,
    '.sh': FileType.SH,
    '.py': FileType.PY,
    '.pl': FileType.PL,
    '.lua': FileType.LUA,
    '.php': FileType.PHP,
    '.hta': FileType.HTA,
    '.wsf': FileType.WSF,
    '.au3': FileType.AU3,
    '.jse': FileType.JSE,
    '.vbe': FileType.VBE,
    
    # Office Documents
    '.doc': FileType.DOC,
    '.docx': FileType.DOCX,
    '.docm': FileType.DOCM,
    '.xls': FileType.XLS,
    '.xlsx': FileType.XLSX,
    '.xlsm': FileType.XLSM,
    '.xll': FileType.XLL,
    '.ppt': FileType.PPT,
    '.pptx': FileType.PPTX,
    '.ppam': FileType.PPAM,
    
    # Rich Documents
    '.pdf': FileType.PDF,
    '.rtf': FileType.RTF,
    
    # Archives
    '.zip': FileType.ZIP,
    '.7z': FileType.SEVENZIP,
    '.rar': FileType.RAR,
    '.gz': FileType.GZ,
    '.tar': FileType.TAR,
    '.iso': FileType.ISO,
    '.img': FileType.IMG,
    '.cab': FileType.CAB,
    
    # Installers
    '.msi': FileType.MSI,
    '.dmg': FileType.DMG,
    
    # Launchers
    '.lnk': FileType.LNK,
    '.url': FileType.URL,
    '.desktop': FileType.DESKTOP,
    
    # Data/Config
    '.html': FileType.HTML,
    '.htm': FileType.HTML,
    '.xml': FileType.XML,
    '.json': FileType.JSON,
    '.ini': FileType.INI,
    '.vhd': FileType.VHD,
}


class FileIdentifier:
    """
    Identifies file types using magic bytes and extensions.
    
    Prioritizes content-based detection over extension-based to handle
    extension spoofing common in malware.
    """
    
    def __init__(self, use_python_magic: bool = True):
        """
        Initialize the file identifier.
        
        Args:
            use_python_magic: Whether to use python-magic library if available
        """
        self.use_python_magic = use_python_magic
        self._magic = None
        
        if use_python_magic:
            try:
                import magic
                self._magic = magic.Magic(mime=True)
            except ImportError:
                pass
    
    def identify(self, file_path: Path) -> FileIdentification:
        """
        Identify a file's type.
        
        Args:
            file_path: Path to the file
            
        Returns:
            FileIdentification object with type information
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not file_path.is_file():
            raise ValueError(f"Not a file: {file_path}")
        
        # Read file header
        header = self._read_header(file_path, 32)
        
        # Try magic-based detection first
        magic_type = self._identify_by_magic(header, file_path)
        
        # Get extension-based type
        ext_type = self._identify_by_extension(file_path)
        
        # Try python-magic if available
        mime_type = None
        if self._magic:
            try:
                mime_type = self._magic.from_file(str(file_path))
            except Exception:
                pass
        
        # Determine final type
        if magic_type and magic_type != FileType.UNKNOWN:
            file_type = magic_type
            # Check for polyglot if extension suggests different type
            is_polyglot = ext_type and ext_type != magic_type and ext_type != FileType.UNKNOWN
            secondary = [ext_type] if is_polyglot else []
        elif ext_type and ext_type != FileType.UNKNOWN:
            file_type = ext_type
            is_polyglot = False
            secondary = []
        else:
            file_type = FileType.UNKNOWN
            is_polyglot = False
            secondary = []
        
        # Refine PE types (EXE vs DLL vs SYS)
        if file_type == FileType.EXE and header.startswith(b'MZ'):
            file_type = self._refine_pe_type(file_path, ext_type)
        
        # Refine ZIP-based types (ZIP vs JAR vs APK vs DOCX)
        if file_type == FileType.ZIP:
            file_type = self._refine_zip_type(file_path, ext_type)
        
        # Refine OLE types (DOC vs XLS vs MSI)
        if file_type == FileType.DOC and header.startswith(b'\xd0\xcf\x11\xe0'):
            file_type = self._refine_ole_type(file_path, ext_type)
        
        category = FILE_TYPE_TO_CATEGORY.get(file_type, FileCategory.UNKNOWN)
        
        return FileIdentification(
            file_type=file_type,
            category=category,
            mime_type=mime_type,
            confidence=0.9 if magic_type else 0.7,
            is_polyglot=is_polyglot,
            secondary_types=secondary
        )
    
    def _read_header(self, file_path: Path, size: int = 32) -> bytes:
        """Read the first N bytes of a file."""
        try:
            with open(file_path, 'rb') as f:
                return f.read(size)
        except Exception:
            return b''
    
    def _identify_by_magic(self, header: bytes, file_path: Path) -> Optional[FileType]:
        """Identify file type by magic bytes."""
        if not header:
            return None
        
        # Check against known signatures
        for signature, file_type in MAGIC_SIGNATURES.items():
            if header.startswith(signature):
                return file_type
        
        # Special case: ISO files have signature at offset 32769
        if file_path.stat().st_size > 32769 + 5:
            try:
                with open(file_path, 'rb') as f:
                    f.seek(32769)
                    iso_sig = f.read(5)
                    if iso_sig == b'CD001':
                        return FileType.ISO
            except Exception:
                pass
        
        return None
    
    def _identify_by_extension(self, file_path: Path) -> Optional[FileType]:
        """Identify file type by extension."""
        ext = file_path.suffix.lower()
        return EXTENSION_MAP.get(ext, FileType.UNKNOWN)
    
    def _refine_pe_type(self, file_path: Path, ext_hint: Optional[FileType]) -> FileType:
        """Refine PE type based on characteristics."""
        try:
            import pefile
            pe = pefile.PE(str(file_path), fast_load=True)
            
            # Check if it's a DLL
            if pe.FILE_HEADER.Characteristics & 0x2000:  # IMAGE_FILE_DLL
                return FileType.DLL
            
            # Check if it's a driver/sys file
            if hasattr(pe, 'OPTIONAL_HEADER'):
                subsystem = pe.OPTIONAL_HEADER.Subsystem
                if subsystem == 1:  # NATIVE
                    return FileType.SYS
            
            pe.close()
        except Exception:
            pass
        
        # Fall back to extension hint
        if ext_hint in (FileType.DLL, FileType.SYS, FileType.SCR, FileType.CPL):
            return ext_hint
        
        return FileType.EXE
    
    def _refine_zip_type(self, file_path: Path, ext_hint: Optional[FileType]) -> FileType:
        """Refine ZIP-based type by checking contents."""
        import zipfile
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                names = zf.namelist()
                
                # Check for APK
                if 'AndroidManifest.xml' in names and 'classes.dex' in names:
                    return FileType.APK
                
                # Check for JAR
                if any(n.endswith('.class') or n == 'META-INF/MANIFEST.MF' for n in names):
                    return FileType.JAR
                
                # Check for DOCX/XLSX/PPTX
                if '[Content_Types].xml' in names:
                    if any('word/' in n for n in names):
                        return FileType.DOCX if ext_hint != FileType.DOCM else FileType.DOCM
                    if any('xl/' in n for n in names):
                        return FileType.XLSX if ext_hint != FileType.XLSM else FileType.XLSM
                    if any('ppt/' in n for n in names):
                        return FileType.PPTX
        except Exception:
            pass
        
        # Fall back to extension hint or ZIP
        if ext_hint in (FileType.JAR, FileType.APK, FileType.DOCX, FileType.XLSX, FileType.PPTX,
                        FileType.DOCM, FileType.XLSM, FileType.PPAM):
            return ext_hint
        
        return FileType.ZIP
    
    def _refine_ole_type(self, file_path: Path, ext_hint: Optional[FileType]) -> FileType:
        """Refine OLE compound document type."""
        try:
            import olefile
            ole = olefile.OleFileIO(str(file_path))
            
            # Check for MSI
            if ole.exists('\\x05SummaryInformation') or ole.exists('_Tables'):
                ole.close()
                return FileType.MSI
            
            # Check for specific Office streams
            if ole.exists('WordDocument'):
                ole.close()
                return FileType.DOC
            if ole.exists('Workbook') or ole.exists('Book'):
                ole.close()
                return FileType.XLS
            if ole.exists('PowerPoint Document'):
                ole.close()
                return FileType.PPT
            
            ole.close()
        except Exception:
            pass
        
        # Fall back to extension hint
        if ext_hint in (FileType.DOC, FileType.XLS, FileType.PPT, FileType.MSI):
            return ext_hint
        
        return FileType.DOC
    
    def is_container(self, file_type: FileType) -> bool:
        """Check if a file type is a container that can be extracted."""
        category = FILE_TYPE_TO_CATEGORY.get(file_type, FileCategory.UNKNOWN)
        return category in (FileCategory.ARCHIVE, FileCategory.INSTALLER)
    
    def is_executable(self, file_type: FileType) -> bool:
        """Check if a file type contains executable code."""
        category = FILE_TYPE_TO_CATEGORY.get(file_type, FileCategory.UNKNOWN)
        return category in (
            FileCategory.NATIVE_BINARY,
            FileCategory.MANAGED_CODE,
            FileCategory.SCRIPT,
            FileCategory.LAUNCHER
        )


def identify_file(file_path: Path) -> FileIdentification:
    """
    Convenience function to identify a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        FileIdentification object
    """
    identifier = FileIdentifier()
    return identifier.identify(file_path)
