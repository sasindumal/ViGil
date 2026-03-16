"""
Binary Lifter Module

Lifts native binaries (PE, ELF, Mach-O) to the unified representation.
Uses pefile for PE analysis and optionally Ghidra for P-Code lifting.
"""

import os
import struct
import subprocess
import tempfile
import json
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
import logging

from ..config import FileType, LiftingConfig
from .base_lifter import (
    BaseLifter, LiftedRepresentation, Function, BasicBlock,
    Instruction, InstructionType, Operand
)

logger = logging.getLogger(__name__)


# P-Code to InstructionType mapping
PCODE_TO_INSTRUCTION = {
    'INT_ADD': InstructionType.ADD,
    'INT_SUB': InstructionType.SUB,
    'INT_MULT': InstructionType.MUL,
    'INT_DIV': InstructionType.DIV,
    'INT_REM': InstructionType.MOD,
    'INT_NEGATE': InstructionType.NEG,
    'INT_AND': InstructionType.AND,
    'INT_OR': InstructionType.OR,
    'INT_XOR': InstructionType.XOR,
    'INT_NOT': InstructionType.NOT,
    'INT_LEFT': InstructionType.SHL,
    'INT_RIGHT': InstructionType.SHR,
    'INT_EQUAL': InstructionType.EQ,
    'INT_NOTEQUAL': InstructionType.NE,
    'INT_LESS': InstructionType.LT,
    'INT_LESSEQUAL': InstructionType.LE,
    'INT_GREATER': InstructionType.GT,  
    'INT_GREATEREQUAL': InstructionType.GE,
    'LOAD': InstructionType.LOAD,
    'STORE': InstructionType.STORE,
    'BRANCH': InstructionType.BRANCH,
    'CBRANCH': InstructionType.CBRANCH,
    'CALL': InstructionType.CALL,
    'RETURN': InstructionType.RETURN,
    'COPY': InstructionType.COPY,
    'CAST': InstructionType.CAST,
}


class BinaryLifter(BaseLifter):
    """
    Lifts native binaries to unified representation.
    
    Supports:
    - PE files (EXE, DLL, SYS) via pefile
    - ELF files via basic parsing
    - Ghidra P-Code integration (optional)
    """
    
    SUPPORTED_TYPES = {
        FileType.EXE, FileType.DLL, FileType.SYS, FileType.SCR, FileType.CPL,
        FileType.ELF, FileType.SO, FileType.MACHO
    }
    
    def __init__(self, config: Optional[LiftingConfig] = None):
        """
        Initialize the binary lifter.
        
        Args:
            config: Lifting configuration
        """
        self.config = config or LiftingConfig()
        self._pe = None
        
        # Initialize accelerated extractors
        try:
            from ..pipeline.accelerator import (
                AcceleratedStringExtractor, AcceleratedPatternScanner,
                detect_hardware
            )
            profile = detect_hardware()
            self._accel_strings = AcceleratedStringExtractor(profile)
            self._accel_patterns = AcceleratedPatternScanner(profile)
            self._use_accelerated = True
            logger.debug(f"Accelerated extraction enabled (profile: {profile.value})")
        except ImportError:
            self._accel_strings = None
            self._accel_patterns = None
            self._use_accelerated = False
            logger.debug("Accelerated extraction not available, using standard")
    
    def can_lift(self, file_type: FileType) -> bool:
        """Check if this lifter supports the file type."""
        return file_type in self.SUPPORTED_TYPES
    
    def lift(self, file_path: Path) -> LiftedRepresentation:
        """
        Lift a binary file to unified representation.
        
        Args:
            file_path: Path to the binary
            
        Returns:
            LiftedRepresentation of the binary
        """
        file_path = Path(file_path)
        
        # Detect binary format
        format_type = self._detect_format(file_path)
        
        if format_type == 'PE':
            return self._lift_pe(file_path)
        elif format_type == 'ELF':
            return self._lift_elf(file_path)
        elif format_type == 'MACHO':
            return self._lift_macho(file_path)
        else:
            # Return minimal representation
            return LiftedRepresentation(
                source_file=file_path,
                file_type=FileType.UNKNOWN,
                metadata={'error': 'Unknown binary format'}
            )
    
    def _detect_format(self, file_path: Path) -> str:
        """Detect binary format from magic bytes."""
        with open(file_path, 'rb') as f:
            magic = f.read(4)
        
        if magic[:2] == b'MZ':
            return 'PE'
        elif magic == b'\x7fELF':
            return 'ELF'
        elif magic in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                       b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
            return 'MACHO'
        return 'UNKNOWN'
    
    def _lift_pe(self, file_path: Path) -> LiftedRepresentation:
        """Lift a PE (Windows) binary."""
        try:
            import pefile
        except ImportError:
            return LiftedRepresentation(
                source_file=file_path,
                file_type=FileType.EXE,
                metadata={'error': 'pefile not installed'}
            )
        
        try:
            pe = pefile.PE(str(file_path), fast_load=False)
        except Exception as e:
            return LiftedRepresentation(
                source_file=file_path,
                file_type=FileType.EXE,
                metadata={'error': f'Failed to parse PE: {e}'}
            )
        
        # Determine specific file type
        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        file_type = FileType.DLL if is_dll else FileType.EXE
        
        # Extract imports
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='replace')
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='replace')
                        imports.append(f"{dll_name}!{func_name}")
        
        # Extract exports
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode('utf-8', errors='replace'))
        
        # Extract strings
        strings = self._extract_strings(file_path)
        
        # Create functions from imports (external)
        functions = []
        for imp_name in imports:
            func = Function(
                name=imp_name,
                address=0,
                size=0,
                is_external=True,
                signature=imp_name
            )
            functions.append(func)
        
        # Try to get entry point function
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        main_func = Function(
            name="_start" if not is_dll else "DllMain",
            address=entry_point,
            size=0,
            is_external=False
        )
        
        # If Ghidra is available and enabled, do P-Code lifting
        if self.config.enable_pcode_lifting and self.config.ghidra_path:
            pcode_functions = self._lift_with_ghidra(file_path)
            if pcode_functions:
                functions.extend(pcode_functions)
        else:
            # Basic disassembly-based lifting
            code_functions = self._basic_lift_pe(pe, file_path)
            functions.extend(code_functions)
        
        pe.close()
        
        return LiftedRepresentation(
            source_file=file_path,
            file_type=file_type,
            functions=functions,
            imports=imports,
            exports=exports,
            strings=strings[:1000],  # Limit strings
            entry_points=[main_func.name],
            metadata={
                'architecture': self._get_pe_arch(pe) if pe else 'unknown',
                'subsystem': pe.OPTIONAL_HEADER.Subsystem if pe else 0,
                'timestamp': pe.FILE_HEADER.TimeDateStamp if pe else 0
            }
        )
    
    def _get_pe_arch(self, pe) -> str:
        """Get architecture from PE file."""
        machine = pe.FILE_HEADER.Machine
        arch_map = {
            0x14c: 'x86',
            0x8664: 'x64',
            0x1c0: 'ARM',
            0xaa64: 'ARM64',
        }
        return arch_map.get(machine, f'unknown_{machine:x}')
    
    def _basic_lift_pe(self, pe, file_path: Path) -> List[Function]:
        """
        Basic PE lifting without Ghidra.
        
        Creates synthetic functions from section analysis.
        """
        functions = []
        
        # Analyze code sections
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='replace').strip('\x00')
            
            # Check if it's a code section
            if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                # Create a synthetic function for the section
                func = Function(
                    name=f"section_{section_name}",
                    address=section.VirtualAddress,
                    size=section.SizeOfRawData,
                    is_external=False
                )
                
                # Create a single basic block
                block = BasicBlock(
                    block_id=0,
                    start_address=section.VirtualAddress,
                    end_address=section.VirtualAddress + section.SizeOfRawData
                )
                
                # Try to identify function-like patterns
                section_data = section.get_data()
                patterns = self._analyze_code_section(section_data, section.VirtualAddress)
                
                for pattern in patterns:
                    inst = Instruction(
                        inst_type=pattern['type'],
                        address=pattern['address'],
                        operands=pattern.get('operands', []),
                        raw_text=pattern.get('raw', '')
                    )
                    block.instructions.append(inst)
                
                func.blocks.append(block)
                func.entry_block_id = 0
                functions.append(func)
        
        return functions
    
    def _analyze_code_section(self, data: bytes, base_addr: int) -> List[Dict]:
        """
        Analyze a code section for common patterns.
        
        Uses accelerated numpy-vectorized scanning when available,
        falls back to sequential scanning otherwise.
        
        Returns a list of identified instruction patterns.
        """
        max_instructions = self.config.max_functions_per_binary * 100
        
        # Try accelerated pattern scanning first
        if self._use_accelerated and self._accel_patterns:
            try:
                raw_patterns = self._accel_patterns.scan_code_section(
                    data, base_addr, max_instructions
                )
                # Convert raw patterns to instruction patterns with proper types
                patterns = []
                type_map = {
                    'CALL': InstructionType.CALL,
                    'RETURN': InstructionType.RETURN,
                    'BRANCH': InstructionType.BRANCH,
                }
                for rp in raw_patterns:
                    inst_type = type_map.get(rp['type'], InstructionType.UNKNOWN)
                    pattern = {
                        'type': inst_type,
                        'address': rp['address'],
                        'raw': rp['raw']
                    }
                    if 'target' in rp:
                        pattern['operands'] = [
                            Operand('target', 'constant', value=rp['target'])
                        ]
                    patterns.append(pattern)
                return patterns
            except Exception as e:
                logger.debug(f"Accelerated scanning failed, falling back: {e}")
        
        # Fallback: sequential byte-by-byte scanning
        return self._analyze_code_section_sequential(data, base_addr, max_instructions)
    
    def _analyze_code_section_sequential(self, data: bytes, base_addr: int,
                                          max_instructions: int) -> List[Dict]:
        """Fallback sequential code section analysis."""
        patterns = []
        i = 0
        
        while i < len(data) - 1 and len(patterns) < max_instructions:
            # Call instruction: E8 xx xx xx xx (relative call)
            if data[i] == 0xE8 and i + 4 < len(data):
                offset = struct.unpack('<i', data[i+1:i+5])[0]
                target = base_addr + i + 5 + offset
                patterns.append({
                    'type': InstructionType.CALL,
                    'address': base_addr + i,
                    'operands': [Operand('target', 'constant', value=target)],
                    'raw': f'CALL 0x{target:x}'
                })
                i += 5
                continue
            
            # Return: C3, C2 xx xx
            if data[i] == 0xC3:
                patterns.append({
                    'type': InstructionType.RETURN,
                    'address': base_addr + i,
                    'raw': 'RET'
                })
                i += 1
                continue
            
            # Jump: E9, EB (unconditional), 0F 8x (conditional)
            if data[i] == 0xE9 and i + 4 < len(data):
                offset = struct.unpack('<i', data[i+1:i+5])[0]
                target = base_addr + i + 5 + offset
                patterns.append({
                    'type': InstructionType.BRANCH,
                    'address': base_addr + i,
                    'operands': [Operand('target', 'constant', value=target)],
                    'raw': f'JMP 0x{target:x}'
                })
                i += 5
                continue
            
            if data[i] == 0xEB and i + 1 < len(data):
                offset = struct.unpack('b', bytes([data[i+1]]))[0]
                target = base_addr + i + 2 + offset
                patterns.append({
                    'type': InstructionType.BRANCH,
                    'address': base_addr + i,
                    'operands': [Operand('target', 'constant', value=target)],
                    'raw': f'JMP SHORT 0x{target:x}'
                })
                i += 2
                continue
            
            i += 1
        
        return patterns
    
    def _lift_elf(self, file_path: Path) -> LiftedRepresentation:
        """Lift an ELF (Linux) binary."""
        # Basic ELF parsing
        with open(file_path, 'rb') as f:
            # Read ELF header
            magic = f.read(4)
            if magic != b'\x7fELF':
                return LiftedRepresentation(
                    source_file=file_path,
                    file_type=FileType.ELF,
                    metadata={'error': 'Invalid ELF magic'}
                )
            
            # Read class (32/64 bit)
            ei_class = struct.unpack('B', f.read(1))[0]
            is_64 = ei_class == 2
            
            # Skip to important fields
            f.seek(0x10 if is_64 else 0x10)
            
            # Read type
            e_type = struct.unpack('<H', f.read(2))[0]
        
        # Extract strings
        strings = self._extract_strings(file_path)
        
        return LiftedRepresentation(
            source_file=file_path,
            file_type=FileType.ELF,
            strings=strings[:1000],
            metadata={
                'architecture': 'x64' if is_64 else 'x86',
                'elf_type': e_type
            }
        )
    
    def _lift_macho(self, file_path: Path) -> LiftedRepresentation:
        """Lift a Mach-O (macOS) binary."""
        # Basic Mach-O parsing
        with open(file_path, 'rb') as f:
            magic = f.read(4)
        
        is_64 = magic in (b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe')
        
        strings = self._extract_strings(file_path)
        
        return LiftedRepresentation(
            source_file=file_path,
            file_type=FileType.MACHO,
            strings=strings[:1000],
            metadata={
                'architecture': 'x64' if is_64 else 'x86'
            }
        )
    
    def _lift_with_ghidra(self, file_path: Path) -> List[Function]:
        """
        Lift binary using Ghidra for P-Code extraction.
        
        Requires Ghidra to be installed and configured.
        """
        if not self.config.ghidra_path or not Path(self.config.ghidra_path).exists():
            logger.warning("Ghidra not configured or not found")
            return []
        
        ghidra_path = Path(self.config.ghidra_path)
        analyze_headless = ghidra_path / "support" / "analyzeHeadless"
        
        if os.name == 'nt':
            analyze_headless = analyze_headless.with_suffix('.bat')
        
        if not analyze_headless.exists():
            logger.warning(f"Ghidra analyzeHeadless not found at {analyze_headless}")
            return []
        
        # Create temp project directory
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            project_name = "uir_analysis"
            output_file = project_dir / "pcode_output.json"
            
            # Run Ghidra headless analysis
            # This would require a custom Ghidra script to export P-Code
            # For now, this is a placeholder
            logger.info(f"Would run Ghidra on {file_path}")
        
        return []
    
    def _extract_strings(self, file_path: Path, min_length: int = 4) -> List[str]:
        """
        Extract printable strings from a binary.
        
        Uses accelerated numpy-vectorized extraction when available,
        falls back to sequential extraction otherwise.
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Try accelerated extraction first
            if self._use_accelerated and self._accel_strings:
                try:
                    return self._accel_strings.extract_strings(data)
                except Exception as e:
                    logger.debug(f"Accelerated string extraction failed, falling back: {e}")
            
            # Fallback: sequential extraction
            return self._extract_strings_sequential(data, min_length)
                
        except Exception as e:
            logger.error(f"Error extracting strings: {e}")
        
        return []
    
    def _extract_strings_sequential(self, data: bytes, min_length: int = 4) -> List[str]:
        """Fallback sequential string extraction."""
        strings = []
        
        # Find ASCII strings
        current = []
        for byte in data:
            if 32 <= byte < 127:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        
        if len(current) >= min_length:
            strings.append(''.join(current))
        
        # Find Unicode strings (basic UTF-16 LE)
        i = 0
        current = []
        while i < len(data) - 1:
            if 32 <= data[i] < 127 and data[i+1] == 0:
                current.append(chr(data[i]))
                i += 2
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
                i += 1
        
        if len(current) >= min_length:
            strings.append(''.join(current))
        
        return list(set(strings))  # Deduplicate
