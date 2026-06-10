"""
Image Generator Module

Converts raw binary files (PE, ELF, etc.) into 2D grayscale images
and resizes them for vision transformer compatibility.
"""

from pathlib import Path
import math
import numpy as np
from PIL import Image
import logging

logger = logging.getLogger(__name__)


def pe_to_grayscale_image(pe_path: Path, target_size: int = 224) -> Image.Image:
    """
    Converts a raw PE file to a grayscale image.
    
    Determines image width based on file size dynamically, resizes to target_size x target_size.
    
    Args:
        pe_path: Path to the binary file
        target_size: Output image height/width (default 224 for LeViT)
        
    Returns:
        PIL.Image.Image in grayscale ('L' mode) of size (target_size, target_size)
    """
    try:
        pe_path = Path(pe_path)
        if not pe_path.exists():
            raise FileNotFoundError(f"File not found: {pe_path}")
            
        with open(pe_path, 'rb') as f:
            data = f.read()
            
        if not data:
            logger.warning(f"File is empty: {pe_path}, generating black image.")
            return Image.new('L', (target_size, target_size), 0)
            
        # Convert bytes to numpy 1D array
        raw_bytes = np.frombuffer(data, dtype=np.uint8)
        num_bytes = len(raw_bytes)
        
        # Determine image width based on file size to preserve visual texture
        if num_bytes < 10240:       # < 10 KB
            width = 32
        elif num_bytes < 30720:     # 10 KB - 30 KB
            width = 64
        elif num_bytes < 61440:     # 30 KB - 60 KB
            width = 128
        elif num_bytes < 102400:    # 60 KB - 100 KB
            width = 256
        elif num_bytes < 204800:    # 100 KB - 200 KB
            width = 384
        elif num_bytes < 512000:    # 200 KB - 500 KB
            width = 512
        elif num_bytes < 1024000:   # 500 KB - 1000 KB
            width = 768
        else:                       # >= 1000 KB
            width = 1024
            
        # Calculate height needed
        height = math.ceil(num_bytes / width)
        
        # Pad array with zeros to match width * height
        padded_len = width * height
        if padded_len > num_bytes:
            padded_bytes = np.zeros(padded_len, dtype=np.uint8)
            padded_bytes[:num_bytes] = raw_bytes
        else:
            padded_bytes = raw_bytes
            
        # Reshape to 2D image matrix
        img_array = padded_bytes.reshape((height, width))
        
        # Create PIL Image
        img = Image.fromarray(img_array)
        
        # Resize to target dimension using bilinear filtering
        img_resized = img.resize((target_size, target_size), Image.Resampling.BILINEAR)
        return img_resized
        
    except Exception as e:
        logger.error(f"Error converting PE to grayscale image for {pe_path}: {e}")
        return Image.new('L', (target_size, target_size), 0)


def save_grayscale_image(pe_path: Path, output_path: Path, target_size: int = 224) -> bool:
    """
    Generates and saves the grayscale image to the specified path.
    
    Args:
        pe_path: Path to the binary file
        output_path: Output PNG image path
        target_size: Target image dimension
        
    Returns:
        True if successful, False otherwise
    """
    try:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        img = pe_to_grayscale_image(pe_path, target_size)
        img.save(output_path, "PNG")
        return True
    except Exception as e:
        logger.error(f"Failed to save image to {output_path}: {e}")
        return False
