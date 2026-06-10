"""
ViGil — File Router
====================

Identifies the file type and routes the file to the appropriate analysis
pipeline (Portable Executable deep analyzer, CrewAI script analysis,
container extraction, or unsupported).
"""

from __future__ import annotations

import sys
import logging
from pathlib import Path
from typing import Any

# Ensure parent ViGil directory is in sys.path
PARENT_DIR = str(Path(__file__).resolve().parent.parent.parent.parent)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from uir.extraction.file_identifier import FileIdentifier
from uir.config import FileType, FileCategory

logger = logging.getLogger("vigil.file_router")


class FileRouter:
    """Routes identified files to specialized analysis pipelines."""

    def __init__(self):
        self.identifier = FileIdentifier(use_python_magic=True)

    def identify_and_route(self, file_path: Path) -> dict[str, Any]:
        """Determine file type, category, and matching processing route.

        Parameters
        ----------
        file_path:
            The path of the file to examine.

        Returns
        -------
        dict
            Contains file_type, category, route ('pe', 'script', 'container', 'unsupported'),
            and confidence score.
        """
        try:
            id_res = self.identifier.identify(file_path)
            file_type = id_res.file_type
            category = id_res.category
            confidence = id_res.confidence

            # Route mapping
            if self.is_pe_file(file_type):
                route = "pe"
            elif self.is_script_file(file_type):
                route = "script"
            elif self.is_container(file_type):
                route = "container"
            else:
                route = "unsupported"

            logger.info(
                "File router: %s identified as %s (%s) → routed to '%s' (conf: %.2f)",
                file_path.name, file_type.value, category.value, route, confidence
            )

            return {
                "file_type": file_type.value,
                "category": category.value,
                "route": route,
                "confidence": confidence,
                "mime_type": id_res.mime_type,
            }

        except Exception as exc:
            logger.exception("Error routing file %s", file_path)
            return {
                "file_type": "unknown",
                "category": "unknown",
                "route": "unsupported",
                "confidence": 0.0,
                "error": str(exc),
            }

    def is_pe_file(self, file_type: FileType) -> bool:
        """Return True if the file is a Portable Executable type."""
        return file_type in (
            FileType.EXE,
            FileType.DLL,
            FileType.SYS,
            FileType.SCR,
            FileType.CPL,
        )

    def is_script_file(self, file_type: FileType) -> bool:
        """Return True if the file is a script or text-based payload."""
        return file_type in (
            FileType.JS,
            FileType.VBS,
            FileType.PS1,
            FileType.BAT,
            FileType.CMD,
            FileType.SH,
            FileType.PY,
            FileType.PL,
            FileType.LUA,
            FileType.PHP,
            FileType.HTA,
            FileType.WSF,
            FileType.AU3,
            FileType.JSE,
            FileType.VBE,
        )

    def is_container(self, file_type: FileType) -> bool:
        """Return True if the file is a container/archive type."""
        return file_type in (
            FileType.ZIP,
            FileType.SEVENZIP,
            FileType.RAR,
            FileType.GZ,
            FileType.TAR,
            FileType.ISO,
            FileType.IMG,
            FileType.CAB,
            FileType.MSI,
        )
