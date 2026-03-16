"""
Script Lifter Module

Lifts script files to unified representation using AST parsing.
"""

import re
import ast as python_ast
from pathlib import Path
from typing import List, Optional, Dict, Any
import logging

from ..config import FileType
from .base_lifter import (
    BaseLifter, LiftedRepresentation, Function, BasicBlock,
    Instruction, InstructionType, Operand
)

logger = logging.getLogger(__name__)


class ScriptLifter(BaseLifter):
    """Lifts script files (Python, JavaScript, PowerShell, etc.)."""
    
    SUPPORTED_TYPES = {
        FileType.JS, FileType.VBS, FileType.PS1, FileType.BAT, FileType.CMD,
        FileType.SH, FileType.PY, FileType.PL, FileType.LUA, FileType.PHP,
        FileType.HTA, FileType.WSF, FileType.AU3, FileType.JSE, FileType.VBE
    }
    
    def can_lift(self, file_type: FileType) -> bool:
        return file_type in self.SUPPORTED_TYPES
    
    def lift(self, file_path: Path) -> LiftedRepresentation:
        file_path = Path(file_path)
        content = self._read_script(file_path)
        ext = file_path.suffix.lower()
        file_type = self._ext_to_type(ext)
        obfuscation = self._detect_obfuscation(content)
        
        lifters = {
            FileType.PY: self._lift_python,
            FileType.JS: self._lift_javascript,
            FileType.PS1: self._lift_powershell,
            FileType.VBS: self._lift_vbscript,
            FileType.BAT: self._lift_batch,
            FileType.CMD: self._lift_batch,
            FileType.SH: self._lift_shell,
        }
        
        lifter = lifters.get(file_type, self._lift_generic)
        return lifter(file_path, content, obfuscation)
    
    def _read_script(self, file_path: Path) -> str:
        for enc in ['utf-8', 'utf-16', 'latin-1', 'cp1252']:
            try:
                return file_path.read_text(encoding=enc)
            except (UnicodeDecodeError, UnicodeError):
                continue
        return file_path.read_bytes().decode('utf-8', errors='replace')
    
    def _ext_to_type(self, ext: str) -> FileType:
        return {
            '.py': FileType.PY, '.js': FileType.JS, '.ps1': FileType.PS1,
            '.vbs': FileType.VBS, '.bat': FileType.BAT, '.cmd': FileType.CMD,
            '.sh': FileType.SH, '.pl': FileType.PL, '.lua': FileType.LUA,
            '.php': FileType.PHP, '.hta': FileType.HTA, '.wsf': FileType.WSF,
        }.get(ext, FileType.UNKNOWN)
    
    def _detect_obfuscation(self, content: str) -> Dict[str, Any]:
        indicators = {'eval_usage': False, 'base64_detected': False, 'patterns': []}
        
        for pat in [r'\beval\s*\(', r'\bexec\s*\(', r'Invoke-Expression', r'FromBase64']:
            if re.search(pat, content, re.IGNORECASE):
                indicators['eval_usage'] = True
                indicators['patterns'].append(pat)
        
        if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', content):
            indicators['base64_detected'] = True
        
        return indicators
    
    def _lift_python(self, file_path: Path, content: str, obf: Dict) -> LiftedRepresentation:
        functions, imports, strings = [], [], []
        
        try:
            tree = python_ast.parse(content)
            for node in python_ast.walk(tree):
                if isinstance(node, python_ast.Import):
                    imports.extend(a.name for a in node.names)
                elif isinstance(node, python_ast.ImportFrom) and node.module:
                    imports.append(node.module)
                elif isinstance(node, python_ast.FunctionDef):
                    functions.append(Function(name=node.name, address=node.lineno, size=0, is_external=False))
                elif isinstance(node, python_ast.Constant) and isinstance(node.value, str) and len(node.value) > 3:
                    strings.append(node.value)
        except SyntaxError:
            pass
        
        main = Function(name="__main__", address=0, size=len(content), is_external=False)
        functions.insert(0, main)
        
        return LiftedRepresentation(source_file=file_path, file_type=FileType.PY,
                                    functions=functions, imports=imports, strings=strings[:500],
                                    metadata={'obfuscation': obf})
    
    def _lift_javascript(self, file_path: Path, content: str, obf: Dict) -> LiftedRepresentation:
        functions = []
        for m in re.finditer(r'function\s+(\w+)\s*\([^)]*\)', content):
            functions.append(Function(name=m.group(1), address=m.start(), size=0, is_external=False))
        
        main = Function(name="__main__", address=0, size=len(content), is_external=False)
        block = BasicBlock(block_id=0, start_address=0, end_address=len(content))
        for m in re.finditer(r'\b(\w+)\s*\(', content):
            block.instructions.append(Instruction(inst_type=InstructionType.CALL, address=m.start(), raw_text=m.group(1)))
        main.blocks.append(block)
        functions.insert(0, main)
        
        return LiftedRepresentation(source_file=file_path, file_type=FileType.JS,
                                    functions=functions, metadata={'obfuscation': obf})
    
    def _lift_powershell(self, file_path: Path, content: str, obf: Dict) -> LiftedRepresentation:
        functions = []
        for m in re.finditer(r'function\s+([\w-]+)\s*', content, re.IGNORECASE):
            functions.append(Function(name=m.group(1), address=m.start(), size=0, is_external=False))
        
        cmdlets = set(re.findall(r'\b((?:Get|Set|New|Remove|Invoke|Start|Write)-\w+)', content))
        main = Function(name="__main__", address=0, size=len(content), is_external=False,
                       called_functions=list(cmdlets))
        functions.insert(0, main)
        
        return LiftedRepresentation(source_file=file_path, file_type=FileType.PS1,
                                    functions=functions, metadata={'obfuscation': obf, 'cmdlets': list(cmdlets)})
    
    def _lift_vbscript(self, file_path: Path, content: str, obf: Dict) -> LiftedRepresentation:
        functions = []
        for m in re.finditer(r'(?:Sub|Function)\s+(\w+)', content, re.IGNORECASE):
            functions.append(Function(name=m.group(1), address=m.start(), size=0, is_external=False))
        
        main = Function(name="__main__", address=0, size=len(content), is_external=False)
        functions.insert(0, main)
        
        return LiftedRepresentation(source_file=file_path, file_type=FileType.VBS,
                                    functions=functions, metadata={'obfuscation': obf})
    
    def _lift_batch(self, file_path: Path, content: str, obf: Dict) -> LiftedRepresentation:
        main = Function(name="__main__", address=0, size=len(content), is_external=False)
        block = BasicBlock(block_id=0, start_address=0, end_address=len(content))
        
        for i, line in enumerate(content.split('\n')):
            if re.match(r'^(?:@?call|start|cmd|powershell)\s+', line.strip(), re.IGNORECASE):
                block.instructions.append(Instruction(inst_type=InstructionType.CALL, address=i, raw_text=line.strip()))
        
        main.blocks.append(block)
        return LiftedRepresentation(source_file=file_path, file_type=FileType.BAT,
                                    functions=[main], metadata={'obfuscation': obf})
    
    def _lift_shell(self, file_path: Path, content: str, obf: Dict) -> LiftedRepresentation:
        functions = []
        for m in re.finditer(r'(\w+)\s*\(\s*\)\s*\{', content):
            functions.append(Function(name=m.group(1), address=m.start(), size=0, is_external=False))
        
        main = Function(name="__main__", address=0, size=len(content), is_external=False)
        functions.insert(0, main)
        
        return LiftedRepresentation(source_file=file_path, file_type=FileType.SH,
                                    functions=functions, metadata={'obfuscation': obf})
    
    def _lift_generic(self, file_path: Path, content: str, obf: Dict) -> LiftedRepresentation:
        main = Function(name="__main__", address=0, size=len(content), is_external=False)
        return LiftedRepresentation(source_file=file_path, file_type=FileType.UNKNOWN,
                                    functions=[main], metadata={'obfuscation': obf})
