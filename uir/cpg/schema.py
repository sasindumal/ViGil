"""
CPG Schema Module

Defines the node and edge types for the Code Property Graph.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


class NodeType(str, Enum):
    """Types of nodes in the Code Property Graph."""
    # Code structure
    METHOD = "METHOD"
    BLOCK = "BLOCK"
    
    # Instructions/Statements
    CALL = "CALL"
    OPERATOR = "OPERATOR"
    CONTROL_STRUCTURE = "CONTROL_STRUCTURE"
    RETURN = "RETURN"
    
    # Data
    IDENTIFIER = "IDENTIFIER"
    LITERAL = "LITERAL"
    PARAMETER = "PARAMETER"
    LOCAL = "LOCAL"
    
    # Special
    UNKNOWN = "UNKNOWN"


class EdgeType(str, Enum):
    """Types of edges in the Code Property Graph."""
    # AST Edges - syntactic containment
    AST = "IS_AST_PARENT"
    
    # CFG Edges - control flow
    CFG = "FLOWS_TO"
    
    # PDG Edges - data/control dependencies
    DATA_FLOW = "REACHES"          # Data dependency
    CONTROL_DEP = "CONTROLS"       # Control dependency
    
    # Call graph
    CALLS = "CALLS"
    CALLED_BY = "CALLED_BY"
    
    # Argument edges
    ARGUMENT = "ARGUMENT"
    RECEIVER = "RECEIVER"


class ControlType(str, Enum):
    """Control structure types."""
    IF = "IF"
    ELSE = "ELSE"
    WHILE = "WHILE"
    FOR = "FOR"
    DO = "DO"
    SWITCH = "SWITCH"
    TRY = "TRY"
    CATCH = "CATCH"
    FINALLY = "FINALLY"


class OperatorType(str, Enum):
    """Semantic operator types - normalized across languages."""
    # Arithmetic
    ADDITION = "<operator>.addition"
    SUBTRACTION = "<operator>.subtraction"
    MULTIPLICATION = "<operator>.multiplication"
    DIVISION = "<operator>.division"
    MODULO = "<operator>.modulo"
    NEGATION = "<operator>.negation"
    
    # Bitwise
    BIT_AND = "<operator>.bitAnd"
    BIT_OR = "<operator>.bitOr"
    BIT_XOR = "<operator>.bitXor"
    BIT_NOT = "<operator>.bitNot"
    LEFT_SHIFT = "<operator>.leftShift"
    RIGHT_SHIFT = "<operator>.rightShift"
    
    # Comparison
    EQUALS = "<operator>.equals"
    NOT_EQUALS = "<operator>.notEquals"
    LESS_THAN = "<operator>.lessThan"
    LESS_EQUAL = "<operator>.lessEqual"
    GREATER_THAN = "<operator>.greaterThan"
    GREATER_EQUAL = "<operator>.greaterEqual"
    
    # Logical
    LOGICAL_AND = "<operator>.logicalAnd"
    LOGICAL_OR = "<operator>.logicalOr"
    LOGICAL_NOT = "<operator>.logicalNot"
    
    # Assignment
    ASSIGNMENT = "<operator>.assignment"
    
    # Memory
    LOAD = "<operator>.load"
    STORE = "<operator>.store"
    ADDRESS_OF = "<operator>.addressOf"
    DEREFERENCE = "<operator>.dereference"
    
    # Other
    INDEX_ACCESS = "<operator>.indexAccess"
    MEMBER_ACCESS = "<operator>.memberAccess"
    CAST = "<operator>.cast"


@dataclass
class CPGNode:
    """A node in the Code Property Graph."""
    id: int
    node_type: NodeType
    name: str = ""
    code: str = ""  # Original code/text
    line_number: int = 0
    column_number: int = 0
    order: int = 0  # Order within parent
    
    # Type-specific attributes
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    # For METHOD nodes
    signature: str = ""
    is_external: bool = False
    
    # For LITERAL nodes
    value: Any = None
    value_type: str = ""
    
    # For CONTROL_STRUCTURE nodes
    control_type: Optional[ControlType] = None
    
    # For OPERATOR nodes
    operator_type: Optional[OperatorType] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary."""
        result = {
            'id': self.id,
            'type': self.node_type.value,
            'name': self.name,
            'code': self.code,
            'line': self.line_number,
            'order': self.order,
        }
        if self.signature:
            result['signature'] = self.signature
        if self.is_external:
            result['is_external'] = True
        if self.value is not None:
            result['value'] = str(self.value)
            result['value_type'] = self.value_type
        if self.control_type:
            result['control_type'] = self.control_type.value
        if self.operator_type:
            result['operator_type'] = self.operator_type.value
        if self.attributes:
            result['attributes'] = self.attributes
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CPGNode':
        """Create node from dictionary."""
        node = cls(
            id=data['id'],
            node_type=NodeType(data['type']),
            name=data.get('name', ''),
            code=data.get('code', ''),
            line_number=data.get('line', 0),
            order=data.get('order', 0),
        )
        if 'signature' in data:
            node.signature = data['signature']
        if 'is_external' in data:
            node.is_external = data['is_external']
        if 'value' in data:
            node.value = data['value']
            node.value_type = data.get('value_type', '')
        if 'control_type' in data:
            node.control_type = ControlType(data['control_type'])
        if 'operator_type' in data:
            node.operator_type = OperatorType(data['operator_type'])
        if 'attributes' in data:
            node.attributes = data['attributes']
        return node


@dataclass
class CPGEdge:
    """An edge in the Code Property Graph."""
    source_id: int
    target_id: int
    edge_type: EdgeType
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert edge to dictionary."""
        result = {
            'source': self.source_id,
            'target': self.target_id,
            'type': self.edge_type.value,
        }
        if self.attributes:
            result['attributes'] = self.attributes
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CPGEdge':
        """Create edge from dictionary."""
        return cls(
            source_id=data['source'],
            target_id=data['target'],
            edge_type=EdgeType(data['type']),
            attributes=data.get('attributes', {})
        )


# Instruction type to operator mapping
INSTRUCTION_TO_OPERATOR = {
    'ADD': OperatorType.ADDITION,
    'SUB': OperatorType.SUBTRACTION,
    'MUL': OperatorType.MULTIPLICATION,
    'DIV': OperatorType.DIVISION,
    'MOD': OperatorType.MODULO,
    'NEG': OperatorType.NEGATION,
    'AND': OperatorType.BIT_AND,
    'OR': OperatorType.BIT_OR,
    'XOR': OperatorType.BIT_XOR,
    'NOT': OperatorType.BIT_NOT,
    'SHL': OperatorType.LEFT_SHIFT,
    'SHR': OperatorType.RIGHT_SHIFT,
    'EQ': OperatorType.EQUALS,
    'NE': OperatorType.NOT_EQUALS,
    'LT': OperatorType.LESS_THAN,
    'LE': OperatorType.LESS_EQUAL,
    'GT': OperatorType.GREATER_THAN,
    'GE': OperatorType.GREATER_EQUAL,
    'LOAD': OperatorType.LOAD,
    'STORE': OperatorType.STORE,
    'COPY': OperatorType.ASSIGNMENT,
}
