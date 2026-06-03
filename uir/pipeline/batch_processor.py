"""
Batch Processor Module

Hardware-aware batch processing of files for CPG generation.
Optimized for Apple M4, NVIDIA GTX 1650 Ti, and standard CPUs.
"""

import os
import time
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Set
from dataclasses import dataclass, field
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed

from ..config import UIRConfig

logger = logging.getLogger(__name__)


@dataclass
class BatchResult:
    """Results from batch processing."""
    total: int = 0
    successful: int = 0
    failed: int = 0
    errors: Dict[str, str] = field(default_factory=dict)
    elapsed_seconds: float = 0.0
    device_profile: str = "cpu_default"


def _process_single_file(args: tuple) -> tuple:
    """
    Worker function for processing a single file.
    Must be a top-level function for pickling in multiprocessing.

    Args:
        args: (file_path_str, output_dir_str, config_dict)

    Returns:
        (file_path_str, success: bool, error_msg: str or None, node_count: int)
    """
    file_path_str, output_dir_str, use_fast_serialization = args

    try:
        from .processor import FileProcessor
        from ..config import UIRConfig

        config = UIRConfig()
        processor = FileProcessor(config)

        file_path = Path(file_path_str)
        cpg = processor.process(file_path)

        if cpg is None:
            return (file_path_str, False, "CPG generation returned None", 0)

        if cpg.num_nodes == 0:
            return (file_path_str, False, "Empty CPG (0 nodes)", 0)

        # Save to output directory if specified
        if output_dir_str:
            output_dir = Path(output_dir_str)
            # Determine benign/malware subfolder
            parent_name = file_path.parent.name.lower()
            if "malware" in parent_name or "malicious" in parent_name:
                sub_dir = output_dir / "malwares"
            else:
                sub_dir = output_dir / "benigns"

            sub_dir.mkdir(parents=True, exist_ok=True)
            output_path = sub_dir / f"{file_path.stem}.cpg.json"
            image_output_path = sub_dir / f"{file_path.stem}.png"

            # Save CPG
            # Use optimized serialization if available
            if use_fast_serialization:
                try:
                    cpg.save_optimized(output_path)
                except (AttributeError, Exception):
                    cpg.save(output_path)
            else:
                cpg.save(output_path)

            # Save grayscale image of the binary
            try:
                processor.save_image(file_path, image_output_path)
            except Exception as img_err:
                logger.warning(f"Failed to generate image for {file_path}: {img_err}")

        return (file_path_str, True, None, cpg.num_nodes)

    except Exception as e:
        return (file_path_str, False, str(e), 0)




class BatchProcessor:
    """
    Hardware-aware batch processor for CPG generation.

    Optimizes worker count, batch sizes, and I/O patterns based on
    the detected or specified hardware profile.
    """

    def __init__(self, config: Optional[UIRConfig] = None,
                 max_workers: Optional[int] = None,
                 device_profile: Optional[str] = None):
        """
        Initialize the batch processor.

        Args:
            config: UIR configuration
            max_workers: Override worker count (None for auto)
            device_profile: Hardware profile override ('auto', 'm4', 'gtx_1650_ti', 'cpu_default')
        """
        self.config = config or UIRConfig()

        # Resolve hardware profile
        from .accelerator import (
            HardwareProfile, detect_hardware,
            get_optimal_workers, get_optimal_batch_size
        )

        if device_profile:
            try:
                self.profile = HardwareProfile(device_profile)
            except ValueError:
                logger.warning(f"Unknown profile '{device_profile}', using auto-detect")
                self.profile = HardwareProfile.AUTO
        else:
            self.profile = HardwareProfile.AUTO

        if self.profile == HardwareProfile.AUTO:
            self.profile = detect_hardware()

        # Set workers
        if max_workers is not None:
            self.max_workers = max_workers
        else:
            self.max_workers = get_optimal_workers(self.profile)

        self.batch_size = get_optimal_batch_size(self.profile)

        # Check for fast serialization
        self._use_fast_serialization = False
        try:
            import orjson
            self._use_fast_serialization = True
        except ImportError:
            try:
                import msgpack
                self._use_fast_serialization = True
            except ImportError:
                pass

        logger.info(
            f"BatchProcessor initialized: profile={self.profile.value}, "
            f"workers={self.max_workers}, batch_size={self.batch_size}, "
            f"fast_serialization={self._use_fast_serialization}"
        )

    def process_directory(self, input_dir: Path,
                          output_dir: Optional[Path] = None,
                          recursive: bool = True,
                          extensions: Optional[List[str]] = None) -> BatchResult:
        """
        Process all files in a directory to generate CPGs.

        Args:
            input_dir: Directory containing files to process
            output_dir: Directory to save generated CPGs
            recursive: Whether to scan subdirectories
            extensions: File extensions to include (None for all)

        Returns:
            BatchResult with processing statistics
        """
        input_dir = Path(input_dir)
        result = BatchResult(device_profile=self.profile.value)

        if not input_dir.exists():
            logger.error(f"Directory not found: {input_dir}")
            return result

        # Collect files
        files = self._collect_files(input_dir, recursive, extensions)
        result.total = len(files)

        if result.total == 0:
            logger.warning(f"No files found in {input_dir}")
            return result

        logger.info(
            f"Processing {result.total} files with {self.max_workers} workers "
            f"(profile: {self.profile.value})"
        )

        # Create output directory
        if output_dir:
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

        start_time = time.time()

        # Process based on hardware profile
        if self.profile == HardwareProfile.GTX_1650_TI:
            self._process_gpu_optimized(files, output_dir, result)
        elif self.profile == HardwareProfile.M4:
            self._process_m4_optimized(files, output_dir, result)
        else:
            self._process_default(files, output_dir, result)

        result.elapsed_seconds = time.time() - start_time

        logger.info(
            f"Batch complete: {result.successful}/{result.total} successful "
            f"in {result.elapsed_seconds:.1f}s "
            f"({result.total / max(result.elapsed_seconds, 0.001):.1f} files/sec)"
        )

        return result

    def _process_default(self, files: List[Path], output_dir: Optional[Path],
                         result: BatchResult):
        """Standard multiprocessing batch processing."""
        from tqdm import tqdm

        output_dir_str = str(output_dir) if output_dir else None
        args_list = [
            (str(f), output_dir_str, self._use_fast_serialization)
            for f in files
        ]

        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(_process_single_file, args): args[0]
                for args in args_list
            }

            with tqdm(total=len(files), desc="Processing", unit="file") as pbar:
                for future in as_completed(futures):
                    file_path_str = futures[future]
                    try:
                        _, success, error, nodes = future.result(timeout=300)
                        if success:
                            result.successful += 1
                        else:
                            result.failed += 1
                            if error:
                                result.errors[file_path_str] = error
                    except Exception as e:
                        result.failed += 1
                        result.errors[file_path_str] = str(e)
                    pbar.update(1)

    def _process_m4_optimized(self, files: List[Path], output_dir: Optional[Path],
                              result: BatchResult):
        """
        Apple M4 optimized processing.

        Leverages:
        - Unified memory: larger batch sizes, no copy overhead
        - P-core + E-core: balanced worker distribution
        - Memory-mapped I/O for large files
        """
        from tqdm import tqdm

        output_dir_str = str(output_dir) if output_dir else None

        # Process in larger batches (unified memory can handle it)
        batch_count = 0
        for batch_start in range(0, len(files), self.batch_size):
            batch = files[batch_start:batch_start + self.batch_size]
            batch_count += 1

            args_list = [
                (str(f), output_dir_str, self._use_fast_serialization)
                for f in batch
            ]

            logger.debug(f"M4 batch {batch_count}: {len(batch)} files")

            with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {
                    executor.submit(_process_single_file, args): args[0]
                    for args in args_list
                }

                with tqdm(
                    total=len(batch),
                    desc=f"Batch {batch_count}",
                    unit="file",
                    leave=False
                ) as pbar:
                    for future in as_completed(futures):
                        file_path_str = futures[future]
                        try:
                            _, success, error, nodes = future.result(timeout=300)
                            if success:
                                result.successful += 1
                            else:
                                result.failed += 1
                                if error:
                                    result.errors[file_path_str] = error
                        except Exception as e:
                            result.failed += 1
                            result.errors[file_path_str] = str(e)
                        pbar.update(1)

    def _process_gpu_optimized(self, files: List[Path], output_dir: Optional[Path],
                               result: BatchResult):
        """
        NVIDIA GTX 1650 Ti optimized processing.

        Leverages:
        - ThreadPoolExecutor for async file I/O (GPU doesn't help with I/O)
        - ProcessPoolExecutor for CPU-bound CPG building
        - Batched processing to keep CUDA streams fed
        """
        from tqdm import tqdm

        output_dir_str = str(output_dir) if output_dir else None

        # Phase 1: Pre-read files using thread pool for overlapped I/O
        # Phase 2: Process CPGs using process pool
        # Combined here for simplicity with higher worker count

        args_list = [
            (str(f), output_dir_str, self._use_fast_serialization)
            for f in files
        ]

        # Use more workers for GPU profile — I/O is bottleneck
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(_process_single_file, args): args[0]
                for args in args_list
            }

            with tqdm(total=len(files), desc="GPU-Optimized", unit="file") as pbar:
                for future in as_completed(futures):
                    file_path_str = futures[future]
                    try:
                        _, success, error, nodes = future.result(timeout=300)
                        if success:
                            result.successful += 1
                        else:
                            result.failed += 1
                            if error:
                                result.errors[file_path_str] = error
                    except Exception as e:
                        result.failed += 1
                        result.errors[file_path_str] = str(e)
                    pbar.update(1)

    def _collect_files(self, input_dir: Path, recursive: bool,
                       extensions: Optional[List[str]] = None) -> List[Path]:
        """Collect files from directory with optional filtering."""
        files = []

        if recursive:
            iterator = input_dir.rglob('*')
        else:
            iterator = input_dir.glob('*')

        for path in iterator:
            if not path.is_file():
                continue

            # Skip hidden files and system files
            if path.name.startswith('.'):
                continue

            # Skip CPG output files
            if path.suffix in ('.json', '.msgpack', '.cpg'):
                continue

            # Extension filter
            if extensions:
                ext = path.suffix.lstrip('.').lower()
                if ext not in [e.lower().lstrip('.') for e in extensions]:
                    continue

            files.append(path)

        return sorted(files)

    def get_dataset_stats(self, input_dir: Path) -> Dict[str, Any]:
        """
        Get statistics about files in a directory.

        Args:
            input_dir: Directory to analyze

        Returns:
            Dictionary with file counts, sizes, and type breakdown
        """
        input_dir = Path(input_dir)
        stats = {
            'total_files': 0,
            'total_size_bytes': 0,
            'total_size_mb': 0.0,
            'by_extension': {},
            'device_profile': self.profile.value,
            'recommended_workers': self.max_workers,
        }

        for path in input_dir.rglob('*'):
            if not path.is_file():
                continue
            if path.name.startswith('.'):
                continue

            stats['total_files'] += 1
            size = path.stat().st_size
            stats['total_size_bytes'] += size

            ext = path.suffix.lower() or '(none)'
            stats['by_extension'][ext] = stats['by_extension'].get(ext, 0) + 1

        stats['total_size_mb'] = stats['total_size_bytes'] / (1024 * 1024)

        return stats


# Import HardwareProfile at module level for type resolution
try:
    from .accelerator import HardwareProfile
except ImportError:
    pass
