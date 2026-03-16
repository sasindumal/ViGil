"""
UIR Configuration Module

Central configuration management using Pydantic for validation.
"""

from pathlib import Path
from typing import Optional, List
from pydantic import BaseModel, Field
from enum import Enum


class FileCategory(str, Enum):
    """Categories of files based on execution semantics."""
    NATIVE_BINARY = "native_binary"
    MANAGED_CODE = "managed_code"
    SCRIPT = "script"
    OFFICE_OLE = "office_ole"
    RICH_DOC = "rich_doc"
    ARCHIVE = "archive"
    INSTALLER = "installer"
    LAUNCHER = "launcher"
    DATA_CONFIG = "data_config"
    UNKNOWN = "unknown"


class FileType(str, Enum):
    """Supported file types for analysis."""
    # Native Binaries
    EXE = "exe"
    DLL = "dll"
    SYS = "sys"
    ELF = "elf"
    MACHO = "macho"
    SO = "so"
    SCR = "scr"
    CPL = "cpl"
    
    # Managed Code
    JAR = "jar"
    CLASS = "class"
    APK = "apk"
    DEX = "dex"
    
    # Scripts
    JS = "js"
    VBS = "vbs"
    PS1 = "ps1"
    BAT = "bat"
    CMD = "cmd"
    SH = "sh"
    PY = "py"
    PL = "pl"
    LUA = "lua"
    PHP = "php"
    HTA = "hta"
    WSF = "wsf"
    AU3 = "au3"
    JSE = "jse"
    VBE = "vbe"
    
    # Office/OLE Documents
    DOC = "doc"
    DOCX = "docx"
    DOCM = "docm"
    XLS = "xls"
    XLSX = "xlsx"
    XLSM = "xlsm"
    XLL = "xll"
    PPT = "ppt"
    PPTX = "pptx"
    PPAM = "ppam"
    
    # Rich Documents
    PDF = "pdf"
    RTF = "rtf"
    
    # Archives
    ZIP = "zip"
    SEVENZIP = "7z"
    RAR = "rar"
    GZ = "gz"
    TAR = "tar"
    ISO = "iso"
    IMG = "img"
    CAB = "cab"
    
    # Installers
    MSI = "msi"
    DMG = "dmg"
    
    # Launchers
    LNK = "lnk"
    URL = "url"
    DESKTOP = "desktop"
    
    # Data/Config
    HTML = "html"
    XML = "xml"
    JSON = "json"
    INI = "ini"
    VHD = "vhd"
    
    # Unknown
    UNKNOWN = "unknown"


# Mapping from FileType to FileCategory
FILE_TYPE_TO_CATEGORY = {
    # Native Binaries
    FileType.EXE: FileCategory.NATIVE_BINARY,
    FileType.DLL: FileCategory.NATIVE_BINARY,
    FileType.SYS: FileCategory.NATIVE_BINARY,
    FileType.ELF: FileCategory.NATIVE_BINARY,
    FileType.MACHO: FileCategory.NATIVE_BINARY,
    FileType.SO: FileCategory.NATIVE_BINARY,
    FileType.SCR: FileCategory.NATIVE_BINARY,
    FileType.CPL: FileCategory.NATIVE_BINARY,
    
    # Managed Code
    FileType.JAR: FileCategory.MANAGED_CODE,
    FileType.CLASS: FileCategory.MANAGED_CODE,
    FileType.APK: FileCategory.MANAGED_CODE,
    FileType.DEX: FileCategory.MANAGED_CODE,
    
    # Scripts
    FileType.JS: FileCategory.SCRIPT,
    FileType.VBS: FileCategory.SCRIPT,
    FileType.PS1: FileCategory.SCRIPT,
    FileType.BAT: FileCategory.SCRIPT,
    FileType.CMD: FileCategory.SCRIPT,
    FileType.SH: FileCategory.SCRIPT,
    FileType.PY: FileCategory.SCRIPT,
    FileType.PL: FileCategory.SCRIPT,
    FileType.LUA: FileCategory.SCRIPT,
    FileType.PHP: FileCategory.SCRIPT,
    FileType.HTA: FileCategory.SCRIPT,
    FileType.WSF: FileCategory.SCRIPT,
    FileType.AU3: FileCategory.SCRIPT,
    FileType.JSE: FileCategory.SCRIPT,
    FileType.VBE: FileCategory.SCRIPT,
    
    # Office/OLE
    FileType.DOC: FileCategory.OFFICE_OLE,
    FileType.DOCX: FileCategory.OFFICE_OLE,
    FileType.DOCM: FileCategory.OFFICE_OLE,
    FileType.XLS: FileCategory.OFFICE_OLE,
    FileType.XLSX: FileCategory.OFFICE_OLE,
    FileType.XLSM: FileCategory.OFFICE_OLE,
    FileType.XLL: FileCategory.OFFICE_OLE,
    FileType.PPT: FileCategory.OFFICE_OLE,
    FileType.PPTX: FileCategory.OFFICE_OLE,
    FileType.PPAM: FileCategory.OFFICE_OLE,
    
    # Rich Docs
    FileType.PDF: FileCategory.RICH_DOC,
    FileType.RTF: FileCategory.RICH_DOC,
    
    # Archives
    FileType.ZIP: FileCategory.ARCHIVE,
    FileType.SEVENZIP: FileCategory.ARCHIVE,
    FileType.RAR: FileCategory.ARCHIVE,
    FileType.GZ: FileCategory.ARCHIVE,
    FileType.TAR: FileCategory.ARCHIVE,
    FileType.ISO: FileCategory.ARCHIVE,
    FileType.IMG: FileCategory.ARCHIVE,
    FileType.CAB: FileCategory.ARCHIVE,
    
    # Installers
    FileType.MSI: FileCategory.INSTALLER,
    FileType.DMG: FileCategory.INSTALLER,
    
    # Launchers
    FileType.LNK: FileCategory.LAUNCHER,
    FileType.URL: FileCategory.LAUNCHER,
    FileType.DESKTOP: FileCategory.LAUNCHER,
    
    # Data/Config
    FileType.HTML: FileCategory.DATA_CONFIG,
    FileType.XML: FileCategory.DATA_CONFIG,
    FileType.JSON: FileCategory.DATA_CONFIG,
    FileType.INI: FileCategory.DATA_CONFIG,
    FileType.VHD: FileCategory.DATA_CONFIG,
    
    FileType.UNKNOWN: FileCategory.UNKNOWN,
}


class HardwareProfile(str, Enum):
    """Supported hardware optimization profiles for CPG build."""
    AUTO = "auto"
    M4 = "m4"
    GTX_1650_TI = "gtx_1650_ti"
    CPU_DEFAULT = "cpu_default"


class CPGBuildConfig(BaseModel):
    """Hardware-optimized CPG build settings."""
    device_profile: HardwareProfile = HardwareProfile.AUTO
    max_workers: Optional[int] = None  # Auto-tuned per profile when None
    batch_size: int = Field(default=50, ge=1)
    use_fast_serialization: bool = True  # orjson/msgpack when available
    use_accelerated_extraction: bool = True  # numpy-based string/pattern extraction
    gpu_memory_limit_mb: int = Field(default=3072, ge=512)  # GTX 1650 Ti has 4GB
    enable_memory_mapping: bool = True  # M4 unified memory optimization


class ExtractionConfig(BaseModel):
    """Configuration for file extraction."""
    max_recursion_depth: int = Field(default=5, ge=1, le=20)
    max_extracted_files: int = Field(default=1000, ge=1)
    temp_dir: Optional[Path] = None
    enable_polyglot_detection: bool = True
    timeout_seconds: int = Field(default=300, ge=10)


class LiftingConfig(BaseModel):
    """Configuration for code lifting."""
    ghidra_path: Optional[Path] = None
    enable_pcode_lifting: bool = True
    enable_ast_generation: bool = True
    max_functions_per_binary: int = Field(default=10000, ge=100)
    enable_library_dedup: bool = True


class CPGConfig(BaseModel):
    """Configuration for Code Property Graph generation."""
    include_ast_edges: bool = True
    include_cfg_edges: bool = True
    include_data_flow_edges: bool = True
    include_control_dep_edges: bool = True
    max_nodes_per_graph: int = Field(default=50000, ge=1000)


class TokenizationConfig(BaseModel):
    """Configuration for tokenization."""
    vocab_size: int = Field(default=32000, ge=1000)
    bpe_vocab_size: int = Field(default=8000, ge=500)
    small_int_range: tuple = (-1000, 1000)
    embedding_dim: int = Field(default=256, ge=64)


class ModelConfig(BaseModel):
    """Configuration for the HGT model."""
    hidden_dim: int = Field(default=256, ge=64)
    num_heads: int = Field(default=8, ge=1)
    num_layers: int = Field(default=4, ge=1)
    dropout: float = Field(default=0.1, ge=0.0, le=0.5)
    num_classes: int = Field(default=2, ge=2)  # malware vs benign


class TrainingConfig(BaseModel):
    """Configuration for model training."""
    batch_size: int = Field(default=32, ge=1)
    learning_rate: float = Field(default=1e-4, gt=0)
    num_epochs: int = Field(default=100, ge=1)
    early_stopping_patience: int = Field(default=10, ge=1)
    use_contrastive_loss: bool = True
    contrastive_temperature: float = Field(default=0.07, gt=0)
    checkpoint_dir: Path = Path("./checkpoints")


class UIRConfig(BaseModel):
    """Main configuration for the UIR system."""
    # Paths
    project_root: Path = Path(".")
    data_dir: Path = Path("./data")
    output_dir: Path = Path("./output")
    cpg_cache_dir: Path = Path("./cpg_cache")
    
    # Sub-configurations
    extraction: ExtractionConfig = Field(default_factory=ExtractionConfig)
    lifting: LiftingConfig = Field(default_factory=LiftingConfig)
    cpg: CPGConfig = Field(default_factory=CPGConfig)
    build: CPGBuildConfig = Field(default_factory=CPGBuildConfig)
    tokenization: TokenizationConfig = Field(default_factory=TokenizationConfig)
    model: ModelConfig = Field(default_factory=ModelConfig)
    training: TrainingConfig = Field(default_factory=TrainingConfig)
    
    # Logging
    log_level: str = "INFO"
    verbose: bool = False
    
    def ensure_dirs(self):
        """Create necessary directories."""
        for path in [self.output_dir, self.cpg_cache_dir, self.training.checkpoint_dir]:
            path.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def from_yaml(cls, path: Path) -> "UIRConfig":
        """Load configuration from YAML file."""
        import yaml
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)
    
    def to_yaml(self, path: Path):
        """Save configuration to YAML file."""
        import yaml
        with open(path, 'w') as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False)


# Default configuration instance
default_config = UIRConfig()
