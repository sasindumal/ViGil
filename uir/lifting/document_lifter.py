"""
Document Lifter Module

Lifts Office documents and PDFs by extracting macros and embedded code.
"""

import re
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

from ..config import FileType
from .base_lifter import (
    BaseLifter, LiftedRepresentation, Function, BasicBlock,
    Instruction, InstructionType, Operand
)

logger = logging.getLogger(__name__)


class DocumentLifter(BaseLifter):
    """Lifts Office documents and PDFs by extracting embedded code."""
    
    SUPPORTED_TYPES = {
        FileType.DOC, FileType.DOCX, FileType.DOCM,
        FileType.XLS, FileType.XLSX, FileType.XLSM, FileType.XLL,
        FileType.PPT, FileType.PPTX, FileType.PPAM,
        FileType.PDF, FileType.RTF
    }
    
    def can_lift(self, file_type: FileType) -> bool:
        return file_type in self.SUPPORTED_TYPES
    
    def lift(self, file_path: Path) -> LiftedRepresentation:
        file_path = Path(file_path)
        ext = file_path.suffix.lower()
        
        if ext in ('.doc', '.xls', '.ppt', '.docm', '.xlsm'):
            return self._lift_ole(file_path)
        elif ext in ('.docx', '.xlsx', '.pptx'):
            return self._lift_ooxml(file_path)
        elif ext == '.pdf':
            return self._lift_pdf(file_path)
        elif ext == '.rtf':
            return self._lift_rtf(file_path)
        else:
            return LiftedRepresentation(source_file=file_path, file_type=FileType.UNKNOWN)
    
    def _lift_ole(self, file_path: Path) -> LiftedRepresentation:
        """Extract VBA macros from OLE documents using oletools."""
        functions = []
        strings = []
        imports = []
        metadata = {'has_macros': False, 'suspicious_keywords': []}
        
        try:
            from oletools.olevba import VBA_Parser
            
            vba_parser = VBA_Parser(str(file_path))
            
            if vba_parser.detect_vba_macros():
                metadata['has_macros'] = True
                
                for _, _, vba_filename, vba_code in vba_parser.extract_macros():
                    # Parse VBA code
                    func_names = self._extract_vba_functions(vba_code)
                    for name in func_names:
                        functions.append(Function(
                            name=name, address=0, size=0, is_external=False,
                            metadata={'source': vba_filename}
                        ))
                    
                    # Extract suspicious patterns
                    suspicious = self._analyze_vba(vba_code)
                    metadata['suspicious_keywords'].extend(suspicious)
                    
                    # Extract strings
                    str_matches = re.findall(r'"([^"]{4,})"', vba_code)
                    strings.extend(str_matches)
                
                # Analyze for AutoOpen/Document_Open
                analysis = list(vba_parser.analyze_macros())
                for _, keyword, _ in analysis:
                    if 'Auto' in keyword or 'Document_Open' in keyword:
                        metadata['auto_exec'] = True
            
            vba_parser.close()
            
        except ImportError:
            logger.warning("oletools not installed")
            metadata['error'] = "oletools not installed"
        except Exception as e:
            metadata['error'] = str(e)
        
        # Create main function
        main = Function(name="Document_Main", address=0, size=0, is_external=False)
        main.called_functions = [f.name for f in functions]
        functions.insert(0, main)
        
        return LiftedRepresentation(
            source_file=file_path,
            file_type=self._get_ole_type(file_path),
            functions=functions,
            strings=strings[:500],
            imports=imports,
            metadata=metadata
        )
    
    def _extract_vba_functions(self, code: str) -> List[str]:
        """Extract function/sub names from VBA code."""
        names = []
        for match in re.finditer(r'(?:Sub|Function)\s+(\w+)', code, re.IGNORECASE):
            names.append(match.group(1))
        return names
    
    def _analyze_vba(self, code: str) -> List[str]:
        """Detect suspicious VBA patterns."""
        suspicious = []
        patterns = {
            'Shell': r'\bShell\b',
            'CreateObject': r'CreateObject',
            'WScript.Shell': r'WScript\.Shell',
            'PowerShell': r'powershell',
            'Environ': r'\bEnviron\b',
            'Download': r'URLDownloadToFile|XMLHTTP',
        }
        for name, pat in patterns.items():
            if re.search(pat, code, re.IGNORECASE):
                suspicious.append(name)
        return suspicious
    
    def _get_ole_type(self, file_path: Path) -> FileType:
        ext = file_path.suffix.lower()
        return {
            '.doc': FileType.DOC, '.docm': FileType.DOCM,
            '.xls': FileType.XLS, '.xlsm': FileType.XLSM,
            '.ppt': FileType.PPT,
        }.get(ext, FileType.DOC)
    
    def _lift_ooxml(self, file_path: Path) -> LiftedRepresentation:
        """Lift OOXML documents (docx, xlsx, pptx)."""
        import zipfile
        
        metadata = {'has_macros': False}
        functions = []
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                names = zf.namelist()
                
                # Check for vbaProject.bin (macros)
                if any('vbaProject.bin' in n for n in names):
                    metadata['has_macros'] = True
                    # Extract and analyze if oletools available
                    for n in names:
                        if 'vbaProject.bin' in n:
                            vba_data = zf.read(n)
                            temp_path = file_path.parent / 'temp_vba.bin'
                            temp_path.write_bytes(vba_data)
                            result = self._lift_ole(temp_path)
                            temp_path.unlink()
                            return result
                
                # Check for external relationships
                for n in names:
                    if 'rels' in n.lower():
                        content = zf.read(n).decode('utf-8', errors='replace')
                        if 'External' in content or 'Target="http' in content:
                            metadata['external_links'] = True
                            
        except Exception as e:
            metadata['error'] = str(e)
        
        main = Function(name="Document_Main", address=0, size=0, is_external=False)
        
        return LiftedRepresentation(
            source_file=file_path,
            file_type=self._get_ooxml_type(file_path),
            functions=[main],
            metadata=metadata
        )
    
    def _get_ooxml_type(self, file_path: Path) -> FileType:
        ext = file_path.suffix.lower()
        return {'.docx': FileType.DOCX, '.xlsx': FileType.XLSX, '.pptx': FileType.PPTX}.get(ext, FileType.DOCX)
    
    def _lift_pdf(self, file_path: Path) -> LiftedRepresentation:
        """Analyze PDF for JavaScript and suspicious elements."""
        metadata = {'has_javascript': False, 'suspicious': []}
        functions = []
        strings = []
        
        try:
            content = file_path.read_bytes()
            
            # Check for JavaScript
            if b'/JavaScript' in content or b'/JS' in content:
                metadata['has_javascript'] = True
                functions.append(Function(name="PDF_JavaScript", address=0, size=0, is_external=False))
            
            # Check for suspicious actions
            suspicious_patterns = [b'/OpenAction', b'/AA', b'/Launch', b'/EmbeddedFile']
            for pat in suspicious_patterns:
                if pat in content:
                    metadata['suspicious'].append(pat.decode())
            
            # Entropy analysis for potential shellcode
            entropy = self._calculate_entropy(content)
            metadata['entropy'] = entropy
            if entropy > 7.5:
                metadata['high_entropy'] = True
                
        except Exception as e:
            metadata['error'] = str(e)
        
        main = Function(name="PDF_Main", address=0, size=0, is_external=False)
        functions.insert(0, main)
        
        return LiftedRepresentation(
            source_file=file_path, file_type=FileType.PDF,
            functions=functions, strings=strings, metadata=metadata
        )
    
    def _lift_rtf(self, file_path: Path) -> LiftedRepresentation:
        """Analyze RTF for embedded objects and exploits."""
        metadata = {'has_ole': False, 'suspicious': []}
        
        try:
            content = file_path.read_bytes()
            
            # Check for OLE objects
            if b'\\object' in content or b'objdata' in content.lower():
                metadata['has_ole'] = True
            
            # Check for equation editor exploit patterns
            if b'Equation.' in content or b'0002CE02' in content:
                metadata['suspicious'].append('equation_editor')
                
        except Exception as e:
            metadata['error'] = str(e)
        
        main = Function(name="RTF_Main", address=0, size=0, is_external=False)
        
        return LiftedRepresentation(
            source_file=file_path, file_type=FileType.RTF,
            functions=[main], metadata=metadata
        )
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        import math
        if not data:
            return 0.0
        
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        
        return entropy
