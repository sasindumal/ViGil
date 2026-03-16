"""
File Processor Module

End-to-end processing of a single file through the pipeline.
"""

from pathlib import Path
from typing import Optional, Dict, Any
import logging

from ..config import UIRConfig, FileType, FileCategory, FILE_TYPE_TO_CATEGORY
from ..extraction.file_identifier import FileIdentifier, identify_file
from ..extraction.recursive_engine import RecursiveExtractor
from ..lifting.base_lifter import LiftedRepresentation, LifterRegistry
from ..lifting.binary_lifter import BinaryLifter
from ..lifting.script_lifter import ScriptLifter
from ..lifting.document_lifter import DocumentLifter
from ..lifting.launcher_lifter import LauncherLifter
from ..cpg.graph import CodePropertyGraph
from ..cpg.builder import CPGBuilder, CPGStorage

logger = logging.getLogger(__name__)


class FileProcessor:
    """End-to-end file processor."""
    
    def __init__(self, config: Optional[UIRConfig] = None):
        self.config = config or UIRConfig()
        
        # Initialize components
        self.identifier = FileIdentifier()
        self.extractor = RecursiveExtractor(self.config.extraction)
        
        # Register lifters
        self.lifter_registry = LifterRegistry()
        self.lifter_registry.register(BinaryLifter(self.config.lifting))
        self.lifter_registry.register(ScriptLifter())
        self.lifter_registry.register(DocumentLifter())
        self.lifter_registry.register(LauncherLifter())
        
        # CPG builder
        self.cpg_builder = CPGBuilder(self.config.cpg)
        
        # Optional storage
        self.storage = None
        if self.config.cpg_cache_dir:
            self.storage = CPGStorage(self.config.cpg_cache_dir)
    
    def process(self, file_path: Path, use_cache: bool = True) -> Optional[CodePropertyGraph]:
        """
        Process a file and generate its CPG.
        
        Args:
            file_path: Path to the file
            use_cache: Whether to use cached CPG if available
            
        Returns:
            CodePropertyGraph or None on failure
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return None
        
        # Check cache
        if use_cache and self.storage:
            cached = self.storage.load(file_path)
            if cached:
                logger.debug(f"Loaded CPG from cache: {file_path}")
                return cached
        
        try:
            # Identify file
            identification = self.identifier.identify(file_path)
            logger.info(f"Identified {file_path.name} as {identification.file_type.value}")
            
            # Handle containers
            if identification.category in (FileCategory.ARCHIVE, FileCategory.INSTALLER):
                return self._process_container(file_path, identification)
            
            # Lift the file
            return self._process_single_file(file_path, identification.file_type)
            
        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
            return None
    
    def _process_single_file(self, file_path: Path, file_type: FileType) -> Optional[CodePropertyGraph]:
        """Process a single (non-container) file."""
        # Get appropriate lifter
        lifter = self.lifter_registry.get_lifter(file_type)
        
        if not lifter:
            logger.warning(f"No lifter for {file_type.value}")
            # Create minimal CPG
            cpg = CodePropertyGraph()
            cpg.source_file = str(file_path)
            cpg.file_type = file_type.value
            cpg.metadata = {'error': 'No lifter available'}
            return cpg
        
        # Lift to intermediate representation
        lifted = lifter.lift(file_path)
        
        # Build CPG
        cpg = self.cpg_builder.build(lifted)
        
        # Cache if storage available
        if self.storage:
            self.storage.save(cpg, file_path)
        
        return cpg
    
    def _process_container(self, file_path: Path, identification) -> Optional[CodePropertyGraph]:
        """Process a container file (archive, installer)."""
        # Extract contents
        result = self.extractor.extract(file_path)
        
        if not result.success:
            logger.warning(f"Extraction failed for {file_path}")
            cpg = CodePropertyGraph()
            cpg.source_file = str(file_path)
            cpg.file_type = identification.file_type.value
            cpg.metadata = {'extraction_error': result.errors}
            return cpg
        
        # Process each leaf file and combine
        combined_cpg = CodePropertyGraph()
        combined_cpg.source_file = str(file_path)
        combined_cpg.file_type = identification.file_type.value
        combined_cpg.metadata = {
            'is_container': True,
            'contained_files': len(result.leaf_files)
        }
        
        for extracted in result.leaf_files[:50]:  # Limit to 50 files
            child_cpg = self._process_single_file(extracted.path, extracted.file_type)
            if child_cpg and child_cpg.num_nodes > 0:
                combined_cpg.merge(child_cpg)
        
        # Cleanup
        if self.config.extraction.temp_dir:
            self.extractor.cleanup(Path(self.config.extraction.temp_dir))
        
        return combined_cpg
    
    def get_file_info(self, file_path: Path) -> Dict[str, Any]:
        """Get information about a file without full processing."""
        file_path = Path(file_path)
        
        identification = self.identifier.identify(file_path)
        
        return {
            'path': str(file_path),
            'type': identification.file_type.value,
            'category': identification.category.value,
            'mime_type': identification.mime_type,
            'is_polyglot': identification.is_polyglot,
            'secondary_types': [t.value for t in identification.secondary_types],
            'is_container': identification.category in (FileCategory.ARCHIVE, FileCategory.INSTALLER),
            'has_lifter': self.lifter_registry.get_lifter(identification.file_type) is not None
        }
