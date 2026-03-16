"""
Semantic Vocabulary Module

Defines the fixed vocabulary for CPG tokenization.
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field


@dataclass
class SemanticVocabulary:
    """
    Fixed semantic vocabulary for CPG node features.
    
    Includes operators, keywords, node types, and special tokens.
    """
    
    # Special tokens
    PAD_TOKEN = "<PAD>"
    UNK_TOKEN = "<UNK>"
    LARGE_INT_TOKEN = "<LARGE_INT>"
    MEM_ADDR_TOKEN = "<MEM_ADDR>"
    STRING_TOKEN = "<STRING>"
    
    # Token to ID mapping
    token_to_id: Dict[str, int] = field(default_factory=dict)
    id_to_token: Dict[int, str] = field(default_factory=dict)
    
    def __post_init__(self):
        self._build_vocab()
    
    def _build_vocab(self):
        """Build the vocabulary."""
        tokens = []
        
        # Special tokens (0-4)
        tokens.extend([
            self.PAD_TOKEN,
            self.UNK_TOKEN,
            self.LARGE_INT_TOKEN,
            self.MEM_ADDR_TOKEN,
            self.STRING_TOKEN,
        ])
        
        # Operators
        operators = [
            "ADD", "SUB", "MUL", "DIV", "MOD", "NEG",
            "AND", "OR", "XOR", "NOT", "SHL", "SHR",
            "EQ", "NE", "LT", "LE", "GT", "GE",
            "LOAD", "STORE", "COPY", "CAST",
            "CALL", "RETURN", "BRANCH", "CBRANCH",
            "NOP", "UNKNOWN",
        ]
        tokens.extend([f"<op>.{op}" for op in operators])
        
        # Node types
        node_types = [
            "METHOD", "BLOCK", "CALL", "OPERATOR",
            "CONTROL_STRUCTURE", "RETURN",
            "IDENTIFIER", "LITERAL", "PARAMETER", "LOCAL",
        ]
        tokens.extend([f"<node>.{nt}" for nt in node_types])
        
        # Control structures
        control_types = ["IF", "ELSE", "WHILE", "FOR", "DO", "SWITCH", "TRY", "CATCH", "FINALLY"]
        tokens.extend([f"<ctrl>.{ct}" for ct in control_types])
        
        # Generic registers
        registers = [
            "REG_GEN", "REG_SP", "REG_BP", "REG_PC", "REG_FLAGS",
            "REG_R0", "REG_R1", "REG_R2", "REG_R3", "REG_R4", "REG_R5", "REG_R6", "REG_R7",
            "REG_EAX", "REG_EBX", "REG_ECX", "REG_EDX", "REG_ESI", "REG_EDI",
        ]
        tokens.extend([f"<reg>.{r}" for r in registers])
        
        # Common API categories
        api_categories = [
            "FILE", "NETWORK", "PROCESS", "REGISTRY", "CRYPTO",
            "MEMORY", "STRING", "SHELL", "COM", "WMI", "HTTP",
        ]
        tokens.extend([f"<api>.{cat}" for cat in api_categories])
        
        # Value types
        value_types = ["INT", "FLOAT", "BOOL", "CHAR", "STRING", "PTR", "VOID"]
        tokens.extend([f"<type>.{vt}" for vt in value_types])
        
        # Small integers (-100 to 100)
        for i in range(-100, 101):
            tokens.append(f"<int>.{i}")
        
        # Common magic values
        magic_values = [
            "0x00", "0x01", "0xFF", "0x90", "0xCC",
            "0x4D5A", "0x5A4D",  # MZ header
            "0x50450000",  # PE signature
            "0x7F454C46",  # ELF magic
        ]
        tokens.extend([f"<magic>.{mv}" for mv in magic_values])
        
        # Build mappings
        for i, token in enumerate(tokens):
            self.token_to_id[token] = i
            self.id_to_token[i] = token
    
    @property
    def size(self) -> int:
        """Vocabulary size."""
        return len(self.token_to_id)
    
    @property
    def pad_id(self) -> int:
        return self.token_to_id[self.PAD_TOKEN]
    
    @property
    def unk_id(self) -> int:
        return self.token_to_id[self.UNK_TOKEN]
    
    def encode(self, token: str) -> int:
        """Encode a token to ID."""
        return self.token_to_id.get(token, self.unk_id)
    
    def decode(self, token_id: int) -> str:
        """Decode an ID to token."""
        return self.id_to_token.get(token_id, self.UNK_TOKEN)
    
    def encode_operator(self, op_name: str) -> int:
        """Encode an operator name."""
        return self.encode(f"<op>.{op_name}")
    
    def encode_node_type(self, node_type: str) -> int:
        """Encode a node type."""
        return self.encode(f"<node>.{node_type}")
    
    def encode_integer(self, value: int) -> int:
        """Encode an integer value."""
        if -100 <= value <= 100:
            return self.encode(f"<int>.{value}")
        return self.token_to_id[self.LARGE_INT_TOKEN]
    
    def contains(self, token: str) -> bool:
        """Check if token is in vocabulary."""
        return token in self.token_to_id
    
    def get_special_tokens(self) -> List[str]:
        """Get list of special tokens."""
        return [self.PAD_TOKEN, self.UNK_TOKEN, self.LARGE_INT_TOKEN, 
                self.MEM_ADDR_TOKEN, self.STRING_TOKEN]


# Global vocabulary instance
_vocab_instance = None

def get_vocabulary() -> SemanticVocabulary:
    """Get the global vocabulary instance."""
    global _vocab_instance
    if _vocab_instance is None:
        _vocab_instance = SemanticVocabulary()
    return _vocab_instance
