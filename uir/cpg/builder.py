"""
CPG Builder Module

Constructs Code Property Graphs from lifted representations.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

from .schema import (
    CPGNode, CPGEdge, NodeType, EdgeType, OperatorType, ControlType,
    INSTRUCTION_TO_OPERATOR
)
from .graph import CodePropertyGraph
from ..lifting.base_lifter import (
    LiftedRepresentation, Function, BasicBlock, Instruction, InstructionType
)
from ..config import CPGConfig

logger = logging.getLogger(__name__)


class CPGBuilder:
    """Builds Code Property Graphs from lifted representations."""
    
    def __init__(self, config: Optional[CPGConfig] = None):
        self.config = config or CPGConfig()
    
    def build(self, lifted: LiftedRepresentation) -> CodePropertyGraph:
        """
        Build a CPG from a lifted representation.
        
        Args:
            lifted: The lifted representation to convert
            
        Returns:
            CodePropertyGraph representing the code
        """
        cpg = CodePropertyGraph()
        cpg.source_file = str(lifted.source_file)
        cpg.file_type = lifted.file_type.value
        cpg.metadata = lifted.metadata.copy()
        
        # Track node mappings
        func_nodes: Dict[str, int] = {}
        block_nodes: Dict[tuple, int] = {}  # (func_name, block_id) -> node_id
        
        # Create METHOD nodes for each function
        for func in lifted.functions:
            method_node = cpg.create_node(
                NodeType.METHOD,
                name=func.name,
                code=func.signature or func.name,
                line_number=func.address,
                signature=func.signature,
                is_external=func.is_external,
            )
            func_nodes[func.name] = method_node.id
            
            if not func.is_external and func.blocks:
                self._build_function_body(cpg, func, method_node.id, block_nodes)
        
        # Create call graph edges
        for func in lifted.functions:
            if func.name in func_nodes:
                caller_id = func_nodes[func.name]
                for called_name in func.called_functions:
                    if called_name in func_nodes:
                        cpg.create_edge(caller_id, func_nodes[called_name], EdgeType.CALLS)
        
        # Add metadata nodes for imports/exports
        if lifted.imports:
            cpg.metadata['imports'] = lifted.imports[:100]
        if lifted.exports:
            cpg.metadata['exports'] = lifted.exports[:100]
        if lifted.strings:
            cpg.metadata['strings'] = lifted.strings[:200]
        
        return cpg
    
    def _build_function_body(self, cpg: CodePropertyGraph, func: Function, 
                             method_id: int, block_nodes: Dict):
        """Build nodes and edges for function body."""
        
        prev_block_id = None
        
        for block in func.blocks:
            # Create BLOCK node
            block_node = cpg.create_node(
                NodeType.BLOCK,
                name=f"block_{block.block_id}",
                line_number=block.start_address,
                attributes={'start': block.start_address, 'end': block.end_address}
            )
            block_nodes[(func.name, block.block_id)] = block_node.id
            
            # AST edge: METHOD contains BLOCK
            cpg.create_edge(method_id, block_node.id, EdgeType.AST)
            
            # CFG edge from previous block
            if prev_block_id is not None and block.block_id == func.entry_block_id:
                pass  # Entry block, no incoming edge from previous
            elif prev_block_id is not None:
                cpg.create_edge(prev_block_id, block_node.id, EdgeType.CFG)
            
            # Process instructions in block
            prev_inst_id = None
            for inst in block.instructions:
                inst_node = self._instruction_to_node(cpg, inst)
                
                # AST edge: BLOCK contains instruction
                cpg.create_edge(block_node.id, inst_node.id, EdgeType.AST)
                
                # CFG edge between sequential instructions
                if prev_inst_id is not None:
                    cpg.create_edge(prev_inst_id, inst_node.id, EdgeType.CFG)
                
                # Create operand nodes and data flow edges
                self._build_operands(cpg, inst, inst_node.id)
                
                prev_inst_id = inst_node.id
            
            prev_block_id = block_node.id
        
        # Add CFG edges for block successors
        for block in func.blocks:
            if (func.name, block.block_id) in block_nodes:
                src_id = block_nodes[(func.name, block.block_id)]
                for succ_id in block.successor_ids:
                    if (func.name, succ_id) in block_nodes:
                        tgt_id = block_nodes[(func.name, succ_id)]
                        cpg.create_edge(src_id, tgt_id, EdgeType.CFG)
    
    def _instruction_to_node(self, cpg: CodePropertyGraph, inst: Instruction) -> CPGNode:
        """Convert an instruction to a CPG node."""
        
        if inst.inst_type == InstructionType.CALL:
            return cpg.create_node(
                NodeType.CALL,
                name=inst.raw_text or "call",
                code=inst.raw_text,
                line_number=inst.address,
            )
        
        elif inst.inst_type == InstructionType.RETURN:
            return cpg.create_node(
                NodeType.RETURN,
                name="return",
                code=inst.raw_text,
                line_number=inst.address,
            )
        
        elif inst.inst_type in (InstructionType.BRANCH, InstructionType.CBRANCH):
            control_type = ControlType.IF if inst.inst_type == InstructionType.CBRANCH else None
            return cpg.create_node(
                NodeType.CONTROL_STRUCTURE,
                name="branch",
                code=inst.raw_text,
                line_number=inst.address,
                control_type=control_type,
            )
        
        else:
            # Operator node
            op_type = INSTRUCTION_TO_OPERATOR.get(inst.inst_type.value)
            return cpg.create_node(
                NodeType.OPERATOR,
                name=inst.inst_type.value,
                code=inst.raw_text,
                line_number=inst.address,
                operator_type=op_type,
            )
    
    def _build_operands(self, cpg: CodePropertyGraph, inst: Instruction, inst_id: int):
        """Build operand nodes and edges."""
        for i, operand in enumerate(inst.operands):
            if operand.op_type == 'constant':
                # LITERAL node
                node = cpg.create_node(
                    NodeType.LITERAL,
                    name=operand.name,
                    value=operand.value,
                    value_type=operand.op_type,
                    order=i,
                )
            else:
                # IDENTIFIER node
                node = cpg.create_node(
                    NodeType.IDENTIFIER,
                    name=operand.name,
                    order=i,
                )
            
            # ARGUMENT edge from instruction to operand
            cpg.create_edge(inst_id, node.id, EdgeType.ARGUMENT)
            
            # DATA_FLOW edge for outputs
            if operand.is_output:
                cpg.create_edge(inst_id, node.id, EdgeType.DATA_FLOW)
    
    def build_from_file(self, file_path: Path, lifter) -> Optional[CodePropertyGraph]:
        """Build CPG from a file using the provided lifter."""
        try:
            lifted = lifter.lift(file_path)
            return self.build(lifted)
        except Exception as e:
            logger.error(f"Failed to build CPG for {file_path}: {e}")
            return None


class CPGStorage:
    """Manages CPG persistence."""
    
    def __init__(self, cache_dir: Path):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def get_cache_path(self, source_file: Path) -> Path:
        """Get cache path for a source file."""
        import hashlib
        file_hash = hashlib.md5(str(source_file).encode()).hexdigest()[:16]
        return self.cache_dir / f"{source_file.stem}_{file_hash}.cpg.json"
    
    def save(self, cpg: CodePropertyGraph, source_file: Path):
        """Save CPG to cache."""
        cache_path = self.get_cache_path(source_file)
        cpg.save(cache_path)
    
    def load(self, source_file: Path) -> Optional[CodePropertyGraph]:
        """Load CPG from cache if exists."""
        cache_path = self.get_cache_path(source_file)
        if cache_path.exists():
            try:
                return CodePropertyGraph.load(cache_path)
            except Exception:
                return None
        return None
    
    def has_cached(self, source_file: Path) -> bool:
        """Check if CPG is cached."""
        return self.get_cache_path(source_file).exists()
