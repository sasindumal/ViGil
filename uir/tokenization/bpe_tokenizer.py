"""
BPE Tokenizer Module

Byte-Pair Encoding tokenizer for identifiers and strings.
"""

from typing import Dict, List, Tuple, Optional
from collections import Counter
import re


class BPETokenizer:
    """
    Byte-Pair Encoding tokenizer for variable names and strings.
    
    Handles out-of-vocabulary identifiers by breaking them into subwords.
    """
    
    def __init__(self, vocab_size: int = 8000):
        self.vocab_size = vocab_size
        self.token_to_id: Dict[str, int] = {}
        self.id_to_token: Dict[int, str] = {}
        self.merges: Dict[Tuple[str, str], str] = {}
        self._trained = False
        
        # Initialize with character-level vocab
        self._init_base_vocab()
    
    def _init_base_vocab(self):
        """Initialize with basic character vocabulary."""
        # Start with special tokens
        special = ["<pad>", "<unk>", "<bos>", "<eos>"]
        
        # Add common characters
        chars = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.")
        
        for i, token in enumerate(special + chars):
            self.token_to_id[token] = i
            self.id_to_token[i] = token
    
    def train(self, texts: List[str], num_merges: Optional[int] = None):
        """
        Train BPE on a corpus of texts.
        
        Args:
            texts: List of strings (identifiers, function names)
            num_merges: Number of merge operations (default: vocab_size - base_vocab)
        """
        if num_merges is None:
            num_merges = self.vocab_size - len(self.token_to_id)
        
        # Tokenize to characters with word boundaries
        word_freqs = Counter()
        for text in texts:
            words = self._split_identifier(text)
            for word in words:
                # Add space-separated characters
                chars = " ".join(list(word)) + " </w>"
                word_freqs[chars] += 1
        
        # Perform BPE merges
        for _ in range(num_merges):
            pairs = self._get_pair_freqs(word_freqs)
            if not pairs:
                break
            
            best_pair = max(pairs, key=pairs.get)
            new_token = best_pair[0] + best_pair[1].replace(" ", "")
            
            # Record the merge
            self.merges[best_pair] = new_token
            
            # Add to vocab if new
            if new_token not in self.token_to_id:
                idx = len(self.token_to_id)
                self.token_to_id[new_token] = idx
                self.id_to_token[idx] = new_token
            
            # Apply merge to word frequencies
            word_freqs = self._merge_pair(best_pair, word_freqs)
        
        self._trained = True
    
    def _split_identifier(self, text: str) -> List[str]:
        """Split identifier into meaningful parts (camelCase, snake_case)."""
        # Split on underscores and camelCase
        parts = re.split(r'_+', text)
        result = []
        for part in parts:
            # Split camelCase
            subparts = re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|[0-9]+', part)
            result.extend(subparts if subparts else [part])
        return [p.lower() for p in result if p]
    
    def _get_pair_freqs(self, word_freqs: Dict[str, int]) -> Dict[Tuple[str, str], int]:
        """Get frequency of all adjacent pairs."""
        pairs = Counter()
        for word, freq in word_freqs.items():
            symbols = word.split()
            for i in range(len(symbols) - 1):
                pairs[(symbols[i], symbols[i + 1])] += freq
        return pairs
    
    def _merge_pair(self, pair: Tuple[str, str], word_freqs: Dict[str, int]) -> Dict[str, int]:
        """Merge a pair in all words."""
        new_freqs = {}
        pattern = " ".join(pair)
        replacement = pair[0] + pair[1].replace(" ", "")
        
        for word, freq in word_freqs.items():
            new_word = word.replace(pattern, replacement)
            new_freqs[new_word] = freq
        
        return new_freqs
    
    def encode(self, text: str) -> List[int]:
        """Encode text to token IDs."""
        if not text:
            return []
        
        # Split into parts
        parts = self._split_identifier(text)
        tokens = []
        
        for part in parts:
            # Start with characters
            word = " ".join(list(part)) + " </w>"
            
            # Apply learned merges
            for pair, merged in self.merges.items():
                pattern = " ".join(pair)
                if pattern in word:
                    word = word.replace(pattern, merged)
            
            # Convert to IDs
            for token in word.split():
                if token in self.token_to_id:
                    tokens.append(self.token_to_id[token])
                else:
                    # Character fallback
                    for char in token:
                        if char in self.token_to_id:
                            tokens.append(self.token_to_id[char])
                        else:
                            tokens.append(self.token_to_id.get("<unk>", 1))
        
        return tokens
    
    def decode(self, token_ids: List[int]) -> str:
        """Decode token IDs back to text."""
        tokens = [self.id_to_token.get(tid, "<unk>") for tid in token_ids]
        text = "".join(tokens)
        text = text.replace("</w>", " ").replace(" ", "")
        return text
    
    @property
    def size(self) -> int:
        """Current vocabulary size."""
        return len(self.token_to_id)
    
    def save(self, path: str):
        """Save tokenizer to file."""
        import json
        data = {
            'vocab_size': self.vocab_size,
            'token_to_id': self.token_to_id,
            'merges': {f"{k[0]}|||{k[1]}": v for k, v in self.merges.items()},
        }
        with open(path, 'w') as f:
            json.dump(data, f)
    
    @classmethod
    def load(cls, path: str) -> 'BPETokenizer':
        """Load tokenizer from file."""
        import json
        with open(path) as f:
            data = json.load(f)
        
        tokenizer = cls(vocab_size=data['vocab_size'])
        tokenizer.token_to_id = data['token_to_id']
        tokenizer.id_to_token = {int(k): v for k, v in enumerate(data['token_to_id'])}
        tokenizer.merges = {
            tuple(k.split("|||")): v 
            for k, v in data['merges'].items()
        }
        tokenizer._trained = True
        return tokenizer
