"""
Value Abstractor Module

Abstracts numeric values and addresses for consistent tokenization.
"""

from typing import Any, Optional, Tuple
import re


class ValueAbstractor:
    """
    Abstracts numeric values and memory addresses.
    
    - Small integers (-1000 to 1000): preserved as distinct tokens
    - Large integers: mapped to <LARGE_INT>
    - Memory addresses: mapped to <MEM_ADDR>
    - Known magic values: preserved
    """
    
    # Small integer range
    SMALL_INT_MIN = -1000
    SMALL_INT_MAX = 1000
    
    # Known magic values that should be preserved
    MAGIC_VALUES = {
        0x4D5A,      # MZ header
        0x5A4D,      # MZ reversed
        0x50450000,  # PE signature
        0x7F454C46,  # ELF magic
        0xCAFEBABE,  # Java class
        0xDEADBEEF,  # Common debug
        0xBAADF00D,  # LocalAlloc
        0x90,        # NOP
        0xCC,        # INT3 (breakpoint)
        0xC3,        # RET
        0xE8,        # CALL
        0xE9,        # JMP
        0xFF,        # Common byte
        0x00,        # NULL
        0x01,        # One
    }
    
    def __init__(self, small_range: Tuple[int, int] = (-1000, 1000)):
        self.small_min, self.small_max = small_range
    
    def abstract(self, value: Any) -> str:
        """
        Abstract a value to a token.
        
        Args:
            value: The value to abstract
            
        Returns:
            Token string
        """
        if value is None:
            return "<NULL>"
        
        # Handle strings
        if isinstance(value, str):
            return self._abstract_string(value)
        
        # Handle integers
        if isinstance(value, (int, float)):
            return self._abstract_number(int(value))
        
        # Handle bytes
        if isinstance(value, bytes):
            return "<BYTES>"
        
        # Handle lists/tuples
        if isinstance(value, (list, tuple)):
            return f"<LIST_{len(value)}>"
        
        return "<UNKNOWN>"
    
    def _abstract_number(self, value: int) -> str:
        """Abstract a numeric value."""
        # Check for magic values first
        if value in self.MAGIC_VALUES:
            return f"<MAGIC_{hex(value)}>"
        
        # Check for small integers
        if self.small_min <= value <= self.small_max:
            return f"<INT_{value}>"
        
        # Check if it looks like an address
        if self._looks_like_address(value):
            return "<MEM_ADDR>"
        
        # Large integer
        return "<LARGE_INT>"
    
    def _looks_like_address(self, value: int) -> bool:
        """Check if value looks like a memory address."""
        # 32-bit address range (common for PE)
        if 0x00400000 <= value <= 0x7FFFFFFF:
            return True
        
        # 64-bit address range
        if 0x0000000100000000 <= value <= 0x00007FFFFFFFFFFF:
            return True
        
        # Kernel addresses
        if value >= 0xFFFF800000000000 or (0x80000000 <= value <= 0xFFFFFFFF):
            return True
        
        return False
    
    def _abstract_string(self, value: str) -> str:
        """Abstract a string value."""
        # Check for URL patterns
        if re.match(r'https?://', value, re.IGNORECASE):
            return "<URL>"
        
        # Check for path patterns
        if re.match(r'[A-Za-z]:\\|/[a-z]+/', value):
            return "<PATH>"
        
        # Check for IP addresses
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', value):
            return "<IP_ADDR>"
        
        # Check for hex strings
        if re.match(r'^[0-9A-Fa-f]+$', value) and len(value) > 8:
            return "<HEX_STRING>"
        
        # Check for base64
        if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', value):
            return "<BASE64>"
        
        # Short strings: preserve
        if len(value) <= 16:
            return f"<STR_{self._sanitize_string(value)}>"
        
        # Long strings
        return "<LONG_STRING>"
    
    def _sanitize_string(self, s: str) -> str:
        """Sanitize a string for use in a token."""
        # Keep only alphanumeric and underscore
        sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', s)
        return sanitized[:16]
    
    def is_preserved_value(self, value: int) -> bool:
        """Check if a value should be preserved as-is."""
        return value in self.MAGIC_VALUES or self.small_min <= value <= self.small_max
