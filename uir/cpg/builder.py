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
                self._build_function_body(cpg, func, method_node.id, block_nodes, func_nodes)
        
        # Create call graph edges between METHOD nodes
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
                             method_id: int, block_nodes: Dict, func_nodes: Dict):
        """Build basic-block level nodes and pruned edges for a function."""
        
        # 1. Create BLOCK nodes (no AST edges to METHOD or instruction nodes)
        for block in func.blocks:
            # Concatenate all instructions' raw texts as the block code
            block_code = "\n".join([inst.raw_text for inst in block.instructions if inst.raw_text])
            
            # Count instruction types in this block
            inst_counts = {}
            for inst in block.instructions:
                itype = inst.inst_type.value
                inst_counts[itype] = inst_counts.get(itype, 0) + 1
            
            block_node = cpg.create_node(
                NodeType.BLOCK,
                name=f"block_{block.block_id}",
                code=block_code,
                line_number=block.start_address,
                attributes={
                    'start': block.start_address,
                    'end': block.end_address,
                    'num_instructions': len(block.instructions),
                    'inst_counts': inst_counts
                }
            )
            block_nodes[(func.name, block.block_id)] = block_node.id
            
        # Connect METHOD to its entry BLOCK node via CFG edge
        if func.entry_block_id is not None and (func.name, func.entry_block_id) in block_nodes:
            entry_node_id = block_nodes[(func.name, func.entry_block_id)]
            cpg.create_edge(method_id, entry_node_id, EdgeType.CFG)
        elif func.blocks:
            # Fallback to first block
            entry_node_id = block_nodes[(func.name, func.blocks[0].block_id)]
            cpg.create_edge(method_id, entry_node_id, EdgeType.CFG)
        
        # 2. Add CFG edges for block successors
        for block in func.blocks:
            if (func.name, block.block_id) in block_nodes:
                src_id = block_nodes[(func.name, block.block_id)]
                for succ_id in block.successor_ids:
                    if (func.name, succ_id) in block_nodes:
                        tgt_id = block_nodes[(func.name, succ_id)]
                        cpg.create_edge(src_id, tgt_id, EdgeType.CFG)
                        
        # 3. Add CALL graph edges from BLOCK to target METHOD nodes
        for block in func.blocks:
            if (func.name, block.block_id) in block_nodes:
                block_node_id = block_nodes[(func.name, block.block_id)]
                for inst in block.instructions:
                    if inst.inst_type == InstructionType.CALL:
                        called_names = []
                        # Check operands first
                        for op in inst.operands:
                            if op.name and op.name in func_nodes:
                                called_names.append(op.name)
                            elif op.value and str(op.value) in func_nodes:
                                called_names.append(str(op.value))
                        # Check raw_text
                        if inst.raw_text:
                            clean_text = inst.raw_text.strip()
                            if clean_text in func_nodes:
                                called_names.append(clean_text)
                            for part in clean_text.split():
                                if part in func_nodes:
                                    called_names.append(part)
                                    
                        for name in set(called_names):
                            cpg.create_edge(block_node_id, func_nodes[name], EdgeType.CALLS)
                            
        # 4. Add DATAFLOW edges between blocks using basic-block level reaching definitions analysis
        # Build CFG predecessor mapping for the function
        predecessors = {b.block_id: list(b.predecessor_ids) for b in func.blocks}
        # Fallback: if predecessor_ids are all empty, reconstruct from successor_ids
        if all(not preds for preds in predecessors.values()):
            for b in func.blocks:
                for succ in b.successor_ids:
                    if succ in predecessors:
                        if b.block_id not in predecessors[succ]:
                            predecessors[succ].append(b.block_id)
                            
        # Map variable -> list of block_ids that define it
        def_blocks_map = {}
        # Map block_id -> set of exposed uses (variables read before being defined in this block)
        exposed_uses_map = {}
        
        for b in func.blocks:
            defined_in_block = set()
            exposed_uses = set()
            
            for inst in b.instructions:
                # Read/use operands
                for op in inst.operands:
                    if op.is_input and op.name and op.op_type != 'constant':
                        if op.name not in defined_in_block:
                            exposed_uses.add(op.name)
                            
                # Write/define operands
                for op in inst.operands:
                    if op.is_output and op.name and op.op_type != 'constant':
                        defined_in_block.add(op.name)
                        
            exposed_uses_map[b.block_id] = exposed_uses
            for var in defined_in_block:
                if var not in def_blocks_map:
                    def_blocks_map[var] = []
                def_blocks_map[var].append(b.block_id)
                
        # Backward search on CFG to find reaching definitions for variable 'var' at block 'u_id'
        def find_reaching_defs(u_id, var, def_blocks):
            visited = set()
            queue = list(predecessors.get(u_id, []))
            reaching = set()
            
            while queue:
                curr = queue.pop(0)
                if curr in visited:
                    continue
                visited.add(curr)
                
                if curr in def_blocks:
                    reaching.add(curr)
                else:
                    queue.extend(predecessors.get(curr, []))
            return reaching
            
        # Draw DATAFLOW edges
        for b in func.blocks:
            u_id = b.block_id
            if (func.name, u_id) not in block_nodes:
                continue
            u_node_id = block_nodes[(func.name, u_id)]
            
            for var in exposed_uses_map.get(u_id, set()):
                if var in def_blocks_map:
                    reaching = find_reaching_defs(u_id, var, def_blocks_map[var])
                    for d_id in reaching:
                        if (func.name, d_id) in block_nodes:
                            d_node_id = block_nodes[(func.name, d_id)]
                            cpg.create_edge(d_node_id, u_node_id, EdgeType.DATA_FLOW)
    
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
