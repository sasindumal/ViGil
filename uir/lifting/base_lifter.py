"""
Base Lifter Module

Abstract base class for all code lifters.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from enum import Enum

from ..config import FileType, FileCategory


class InstructionType(str, Enum):
    """Types of instructions in the lifted representation."""
    # Arithmetic
    ADD = "ADD"
    SUB = "SUB"
    MUL = "MUL"
    DIV = "DIV"
    MOD = "MOD"
    NEG = "NEG"
    
    # Bitwise
    AND = "AND"
    OR = "OR"
    XOR = "XOR"
    NOT = "NOT"
    SHL = "SHL"
    SHR = "SHR"
    
    # Comparison
    EQ = "EQ"
    NE = "NE"
    LT = "LT"
    LE = "LE"
    GT = "GT"
    GE = "GE"
    
    # Memory
    LOAD = "LOAD"
    STORE = "STORE"
    
    # Control Flow
    BRANCH = "BRANCH"
    CBRANCH = "CBRANCH"  # Conditional branch
    CALL = "CALL"
    RETURN = "RETURN"
    
    # Data Movement
    COPY = "COPY"
    CAST = "CAST"
    
    # Special
    NOP = "NOP"
    UNKNOWN = "UNKNOWN"


@dataclass
class Operand:
    """An operand in an instruction."""
    name: str  # Variable/register name
    op_type: str  # "register", "memory", "constant", "variable"
    value: Optional[Any] = None  # For constants
    size: int = 0  # Size in bytes
    is_input: bool = True
    is_output: bool = False


@dataclass
class Instruction:
    """A single instruction in the lifted representation."""
    inst_type: InstructionType
    address: int  # Original address/position
    operands: List[Operand] = field(default_factory=list)
    raw_text: str = ""  # Original instruction text
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BasicBlock:
    """A basic block - sequence of instructions with single entry/exit."""
    block_id: int
    start_address: int
    end_address: int
    instructions: List[Instruction] = field(default_factory=list)
    successor_ids: List[int] = field(default_factory=list)  # CFG edges
    predecessor_ids: List[int] = field(default_factory=list)


@dataclass
class Function:
    """A function/method in the lifted representation."""
    name: str
    address: int
    size: int
    blocks: List[BasicBlock] = field(default_factory=list)
    entry_block_id: Optional[int] = None
    is_external: bool = False  # API/library function
    signature: str = ""
    return_type: str = ""
    parameters: List[tuple] = field(default_factory=list)  # (name, type) pairs
    local_variables: List[tuple] = field(default_factory=list)
    called_functions: List[str] = field(default_factory=list)
    callers: List[str] = field(default_factory=list)


@dataclass
class LiftedRepresentation:
    """
    The unified lifted representation of analyzed code.
    
    This is the intermediate format before CPG construction.
    """
    source_file: Path
    file_type: FileType
    functions: List[Function] = field(default_factory=list)
    global_variables: List[tuple] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def total_instructions(self) -> int:
        """Count total instructions across all functions."""
        count = 0
        for func in self.functions:
            for block in func.blocks:
                count += len(block.instructions)
        return count
    
    @property
    def total_blocks(self) -> int:
        """Count total basic blocks."""
        return sum(len(f.blocks) for f in self.functions)


class BaseLifter(ABC):
    """
    Abstract base class for code lifters.
    
    Lifters convert various file formats into the unified
    LiftedRepresentation for CPG construction.
    """
    
    @abstractmethod
    def can_lift(self, file_type: FileType) -> bool:
        """
        Check if this lifter can handle the given file type.
        
        Args:
            file_type: The file type to check
            
        Returns:
            True if this lifter supports the file type
        """
        pass
    
    @abstractmethod
    def lift(self, file_path: Path) -> LiftedRepresentation:
        """
        Lift a file to the unified representation.
        
        Args:
            file_path: Path to the file to lift
            
        Returns:
            LiftedRepresentation of the file's code
        """
        pass
    
    def supported_types(self) -> List[FileType]:
        """Return list of supported file types."""
        return [ft for ft in FileType if self.can_lift(ft)]


class LifterRegistry:
    """Registry for lifters - selects appropriate lifter for file types."""
    
    def __init__(self):
        self._lifters: List[BaseLifter] = []
    
    def register(self, lifter: BaseLifter):
        """Register a lifter."""
        self._lifters.append(lifter)
    
    def get_lifter(self, file_type: FileType) -> Optional[BaseLifter]:
        """Get a lifter that can handle the given file type."""
        for lifter in self._lifters:
            if lifter.can_lift(file_type):
                return lifter
        return None
    
    def lift(self, file_path: Path, file_type: FileType) -> Optional[LiftedRepresentation]:
        """Lift a file using the appropriate lifter."""
        lifter = self.get_lifter(file_type)
        if lifter:
            return lifter.lift(file_path)
        return None
