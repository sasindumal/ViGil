"""
Launcher Lifter Module

Lifts launcher files (.lnk, .url, .desktop) to unified representation
by parsing their targets and arguments.
"""

import re
import struct
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

from ..config import FileType
from .base_lifter import (
    BaseLifter, LiftedRepresentation, Function, BasicBlock,
    Instruction, InstructionType, Operand
)

logger = logging.getLogger(__name__)


class LauncherLifter(BaseLifter):
    """Lifts launcher/shortcut files to unified representation."""
    
    SUPPORTED_TYPES = {FileType.LNK, FileType.URL, FileType.DESKTOP}
    
    def can_lift(self, file_type: FileType) -> bool:
        return file_type in self.SUPPORTED_TYPES
    
    def lift(self, file_path: Path) -> LiftedRepresentation:
        file_path = Path(file_path)
        ext = file_path.suffix.lower()
        
        if ext == '.lnk':
            return self._lift_lnk(file_path)
        elif ext == '.url':
            return self._lift_url(file_path)
        elif ext == '.desktop':
            return self._lift_desktop(file_path)
        else:
            return LiftedRepresentation(source_file=file_path, file_type=FileType.UNKNOWN)
    
    def _lift_lnk(self, file_path: Path) -> LiftedRepresentation:
        """Parse Windows shortcut file (.lnk)."""
        metadata = {'target': None, 'arguments': None, 'working_dir': None, 'suspicious': []}
        functions = []
        
        try:
            # Try pylnk3 first
            import pylnk3
            lnk = pylnk3.parse(str(file_path))
            
            metadata['target'] = lnk.path or lnk.relative_path
            metadata['arguments'] = lnk.arguments
            metadata['working_dir'] = lnk.working_dir
            metadata['icon'] = lnk.icon
            
        except ImportError:
            # Fallback to manual parsing
            lnk_data = self._parse_lnk_manual(file_path)
            metadata.update(lnk_data)
        except Exception as e:
            metadata['error'] = str(e)
        
        # Build synthetic call graph
        target = metadata.get('target', '')
        args = metadata.get('arguments', '') or ''
        
        # Create main function representing the shortcut
        main = Function(name="LNK_Main", address=0, size=0, is_external=False)
        block = BasicBlock(block_id=0, start_address=0, end_address=0)
        
        if target:
            # First call: the target executable
            target_name = Path(target).name if target else 'unknown'
            block.instructions.append(Instruction(
                inst_type=InstructionType.CALL,
                address=0,
                operands=[Operand(target_name, 'constant', value=target)],
                raw_text=f"CALL {target_name}"
            ))
            main.called_functions.append(target_name)
        
        # Analyze arguments for chained commands
        if args:
            # Check for suspicious patterns
            suspicious_patterns = [
                (r'powershell', 'PowerShell execution'),
                (r'-enc\s+', 'Encoded command'),
                (r'cmd\s*/c', 'Command execution'),
                (r'mshta', 'MSHTA execution'),
                (r'regsvr32', 'DLL registration'),
                (r'rundll32', 'RunDLL execution'),
                (r'certutil', 'Certutil usage'),
                (r'bitsadmin', 'BITS transfer'),
            ]
            
            for pattern, desc in suspicious_patterns:
                if re.search(pattern, args, re.IGNORECASE):
                    metadata['suspicious'].append(desc)
                    
                    # Add as additional call
                    block.instructions.append(Instruction(
                        inst_type=InstructionType.CALL,
                        address=len(block.instructions),
                        operands=[Operand(pattern, 'constant')],
                        raw_text=desc
                    ))
        
        main.blocks.append(block)
        main.entry_block_id = 0
        functions.append(main)
        
        return LiftedRepresentation(
            source_file=file_path, file_type=FileType.LNK,
            functions=functions, metadata=metadata
        )
    
    def _parse_lnk_manual(self, file_path: Path) -> Dict[str, Any]:
        """Manually parse LNK file structure."""
        result = {'target': None, 'arguments': None}
        
        try:
            data = file_path.read_bytes()
            
            # Verify LNK signature
            if data[:4] != b'\x4c\x00\x00\x00':
                return result
            
            # Read flags at offset 0x14
            flags = struct.unpack('<I', data[0x14:0x18])[0]
            
            offset = 0x4C  # Start of shell link header
            
            # Skip ItemIDList if present
            if flags & 0x01:
                idlist_size = struct.unpack('<H', data[offset:offset+2])[0]
                offset += 2 + idlist_size
            
            # Read LinkInfo if present
            if flags & 0x02:
                linkinfo_size = struct.unpack('<I', data[offset:offset+4])[0]
                # Extract local base path
                linkinfo_offset = offset
                local_base_offset = struct.unpack('<I', data[offset+0x10:offset+0x14])[0]
                if local_base_offset > 0:
                    path_start = linkinfo_offset + local_base_offset
                    path_end = data.find(b'\x00', path_start)
                    result['target'] = data[path_start:path_end].decode('utf-8', errors='replace')
                offset += linkinfo_size
            
            # Read StringData
            def read_string(off: int) -> tuple:
                if off >= len(data) - 2:
                    return '', off
                length = struct.unpack('<H', data[off:off+2])[0]
                if length == 0:
                    return '', off + 2
                try:
                    s = data[off+2:off+2+length*2].decode('utf-16-le', errors='replace')
                except Exception:
                    s = ''
                return s, off + 2 + length * 2
            
            # Description
            if flags & 0x04:
                _, offset = read_string(offset)
            # RelativePath
            if flags & 0x08:
                rel_path, offset = read_string(offset)
                if not result['target']:
                    result['target'] = rel_path
            # WorkingDir
            if flags & 0x10:
                _, offset = read_string(offset)
            # CommandLineArguments
            if flags & 0x20:
                args, offset = read_string(offset)
                result['arguments'] = args
                
        except Exception as e:
            logger.debug(f"Error parsing LNK: {e}")
        
        return result
    
    def _lift_url(self, file_path: Path) -> LiftedRepresentation:
        """Parse URL shortcut file."""
        metadata = {'url': None}
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='replace')
            
            # Parse INI-style format
            for line in content.split('\n'):
                if line.lower().startswith('url='):
                    metadata['url'] = line.split('=', 1)[1].strip()
                    break
                    
        except Exception as e:
            metadata['error'] = str(e)
        
        main = Function(name="URL_Main", address=0, size=0, is_external=False)
        
        if metadata.get('url'):
            block = BasicBlock(block_id=0, start_address=0, end_address=0)
            block.instructions.append(Instruction(
                inst_type=InstructionType.CALL,
                address=0,
                operands=[Operand('OpenURL', 'constant', value=metadata['url'])],
                raw_text=f"OpenURL {metadata['url']}"
            ))
            main.blocks.append(block)
        
        return LiftedRepresentation(
            source_file=file_path, file_type=FileType.URL,
            functions=[main], metadata=metadata
        )
    
    def _lift_desktop(self, file_path: Path) -> LiftedRepresentation:
        """Parse Linux .desktop file."""
        metadata = {'exec': None, 'type': None}
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='replace')
            
            for line in content.split('\n'):
                if line.lower().startswith('exec='):
                    metadata['exec'] = line.split('=', 1)[1].strip()
                elif line.lower().startswith('type='):
                    metadata['type'] = line.split('=', 1)[1].strip()
                    
        except Exception as e:
            metadata['error'] = str(e)
        
        main = Function(name="Desktop_Main", address=0, size=0, is_external=False)
        
        if metadata.get('exec'):
            block = BasicBlock(block_id=0, start_address=0, end_address=0)
            block.instructions.append(Instruction(
                inst_type=InstructionType.CALL,
                address=0,
                operands=[Operand('exec', 'constant', value=metadata['exec'])],
                raw_text=f"exec {metadata['exec']}"
            ))
            main.blocks.append(block)
        
        return LiftedRepresentation(
            source_file=file_path, file_type=FileType.DESKTOP,
            functions=[main], metadata=metadata
        )
