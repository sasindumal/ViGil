"""
MSI Extractor Module

Handles extraction of Windows Installer (MSI) and CAB files,
including embedded scripts from CustomAction tables.
"""

import os
import re
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple
from dataclasses import dataclass

from ..config import FileType


@dataclass
class MSIExtractionResult:
    """Result of MSI extraction."""
    success: bool
    extracted_files: List[Path]
    scripts: List[Tuple[str, str]]  # (script_name, script_content)
    error: Optional[str] = None


class MSIExtractor:
    """
    Extracts contents from MSI installers.
    
    Handles:
    - Binary stream extraction
    - CustomAction script extraction
    - Embedded CAB extraction
    """
    
    def __init__(self, output_dir: Optional[Path] = None, max_files: int = 1000):
        """
        Initialize the MSI extractor.
        
        Args:
            output_dir: Directory for extracted files
            max_files: Maximum number of files to extract
        """
        self.output_dir = output_dir
        self.max_files = max_files
    
    def can_extract(self, file_type: FileType) -> bool:
        """Check if this extractor can handle the file type."""
        return file_type == FileType.MSI
    
    def extract(self, file_path: Path, output_dir: Optional[Path] = None) -> MSIExtractionResult:
        """
        Extract an MSI file.
        
        Args:
            file_path: Path to the MSI file
            output_dir: Override output directory
            
        Returns:
            MSIExtractionResult with files and scripts
        """
        file_path = Path(file_path)
        out_dir = output_dir or self.output_dir or Path(tempfile.mkdtemp())
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        
        extracted_files = []
        scripts = []
        
        try:
            # Try using msilib on Windows
            if os.name == 'nt':
                result = self._extract_windows(file_path, out_dir)
                if result.success:
                    return result
            
            # Try using oletools/olefile
            result = self._extract_ole(file_path, out_dir)
            return result
            
        except Exception as e:
            return MSIExtractionResult(
                success=False,
                extracted_files=[],
                scripts=[],
                error=str(e)
            )
    
    def _extract_windows(self, file_path: Path, output_dir: Path) -> MSIExtractionResult:
        """Extract MSI using Windows msilib."""
        import subprocess
        
        extracted_files = []
        scripts = []
        
        # Use msiexec to extract files
        extract_dir = output_dir / "files"
        extract_dir.mkdir(exist_ok=True)
        
        try:
            result = subprocess.run(
                ['msiexec', '/a', str(file_path), '/qn', f'TARGETDIR={extract_dir}'],
                capture_output=True,
                timeout=120
            )
            
            if result.returncode == 0:
                for item in extract_dir.rglob('*'):
                    if item.is_file():
                        extracted_files.append(item)
        except Exception:
            pass
        
        # Try to extract scripts from database
        scripts = self._extract_scripts_wmi(file_path)
        
        return MSIExtractionResult(
            success=len(extracted_files) > 0 or len(scripts) > 0,
            extracted_files=extracted_files[:self.max_files],
            scripts=scripts
        )
    
    def _extract_scripts_wmi(self, file_path: Path) -> List[Tuple[str, str]]:
        """Extract CustomAction scripts using WMI (Windows only)."""
        scripts = []
        
        try:
            import subprocess
            
            # Query CustomAction table
            ps_script = f'''
            $db = (New-Object -ComObject WindowsInstaller.Installer).OpenDatabase("{file_path}", 0)
            $view = $db.OpenView("SELECT Action, Source FROM CustomAction WHERE Type IN (5, 6, 37, 38, 53, 54)")
            $view.Execute()
            
            while ($record = $view.Fetch()) {{
                $action = $record.StringData(1)
                $source = $record.StringData(2)
                Write-Output "$action|$source"
            }}
            '''
            
            result = subprocess.run(
                ['powershell', '-Command', ps_script],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if '|' in line:
                        parts = line.split('|', 1)
                        if len(parts) == 2:
                            scripts.append((parts[0], parts[1]))
        except Exception:
            pass
        
        return scripts
    
    def _extract_ole(self, file_path: Path, output_dir: Path) -> MSIExtractionResult:
        """Extract MSI using OLE parsing."""
        extracted_files = []
        scripts = []
        
        try:
            import olefile
            
            if not olefile.isOleFile(str(file_path)):
                return MSIExtractionResult(
                    success=False,
                    extracted_files=[],
                    scripts=[],
                    error="Not a valid OLE file"
                )
            
            ole = olefile.OleFileIO(str(file_path))
            
            # List all streams
            file_count = 0
            for entry in ole.listdir():
                if file_count >= self.max_files:
                    break
                
                stream_name = '/'.join(entry)
                
                # Skip metadata streams
                if stream_name.startswith('\x05') or stream_name.startswith('_'):
                    continue
                
                try:
                    data = ole.openstream(entry).read()
                    
                    # Create safe filename
                    safe_name = self._safe_filename(stream_name)
                    target = output_dir / safe_name
                    
                    # Check if it might be a script
                    if self._looks_like_script(data):
                        try:
                            script_text = data.decode('utf-8', errors='replace')
                            scripts.append((safe_name, script_text))
                        except Exception:
                            pass
                    
                    # Save binary content
                    with open(target, 'wb') as f:
                        f.write(data)
                    extracted_files.append(target)
                    file_count += 1
                    
                except Exception:
                    continue
            
            ole.close()
            
            return MSIExtractionResult(
                success=True,
                extracted_files=extracted_files,
                scripts=scripts
            )
            
        except ImportError:
            return MSIExtractionResult(
                success=False,
                extracted_files=[],
                scripts=[],
                error="olefile not installed"
            )
        except Exception as e:
            return MSIExtractionResult(
                success=False,
                extracted_files=[],
                scripts=[],
                error=str(e)
            )
    
    def _safe_filename(self, name: str) -> str:
        """Create a safe filename from a stream name."""
        # Remove or replace unsafe characters
        safe = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
        # Limit length
        if len(safe) > 200:
            safe = safe[:200]
        return safe or "unnamed"
    
    def _looks_like_script(self, data: bytes) -> bool:
        """Check if data might be a script."""
        # Check for common script indicators
        indicators = [
            b'function ',
            b'Function ',
            b'Sub ',
            b'Dim ',
            b'CreateObject',
            b'WScript.',
            b'powershell',
            b'cmd /c',
            b'<script',
            b'javascript:',
            b'vbscript:',
        ]
        
        try:
            # Check first 1KB
            header = data[:1024]
            return any(ind in header for ind in indicators)
        except Exception:
            return False
