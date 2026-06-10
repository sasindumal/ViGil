"""
ViGil — PE Strings Extractor
=============================

Extracts ASCII and Unicode strings (minimum length 4) from a binary,
and categorizes them into security-relevant groups (URLs, IPs, file paths,
registry keys, shell commands, Base64 blobs, persistence indicators,
and ransomware indicators).
"""

from __future__ import annotations

import re
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Regular expressions for string categorization
URL_REGEX = re.compile(r'(?:https?|ftp)://[^\s/$.?#].[^\s]*', re.IGNORECASE)
IP_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
PATH_REGEX = re.compile(r'\b[A-Za-z]:\\[\w\\\s.-]+\b|\b%(?:SystemRoot|System32|TEMP|APPDATA|USERPROFILE|LOCALAPPDATA)%\\[\w\\\s.-]+\b', re.IGNORECASE)
REGISTRY_REGEX = re.compile(r'\b(?:HKLM|HKCU|HKU|HKCR|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_USERS|HKEY_CLASSES_ROOT)\\[\w\\\s.-]+\b', re.IGNORECASE)
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
BASE64_REGEX = re.compile(r'\b[A-Za-z0-9+/]{32,}={0,2}\b')

# Keywords for behavior indicators
PERSISTENCE_KEYWORDS = ["runonce", "run", "software\\microsoft\\windows\\currentversion\\run", "schtasks", "createagent", "startup", "currentversion\\run"]
RANSOMWARE_KEYWORDS = ["decrypt", "encrypt", "ransom", "bitcoin", "tor", ".onion", "private key", "recover your files", "payment", "crypto"]
COMMANDS_KEYWORDS = ["cmd.exe", "powershell", "powershell.exe", "wscript", "cscript", "mshta", "regsvr32", "rundll32", "-enc", "-encodedcommand", "/c", "/k"]


class StringExtractor:
    """Extracts and categorizes ASCII and Unicode strings from PE files."""

    def __init__(self, min_length: int = 4):
        self.min_length = min_length

    def analyze(self, pe_path: Path) -> dict[str, Any]:
        """Extract and categorize strings from the specified file.

        Returns
        -------
        dict
            Categorized lists of strings and overall counts.
        """
        result: dict[str, Any] = {
            "urls": [],
            "ip_addresses": [],
            "file_paths": [],
            "registry_keys": [],
            "emails": [],
            "commands": [],
            "base64_blobs": [],
            "persistence_indicators": [],
            "ransomware_indicators": [],
            "total_strings": 0,
        }

        try:
            with open(pe_path, "rb") as f:
                data = f.read()
        except Exception as exc:
            logger.error("Failed to read file for string extraction %s: %s", pe_path, exc)
            result["error"] = str(exc)
            return result

        try:
            # Extract ASCII strings
            ascii_strings = self._extract_ascii(data)
            # Extract Unicode strings (UTF-16 LE)
            unicode_strings = self._extract_unicode(data)

            all_strings = ascii_strings + unicode_strings
            result["total_strings"] = len(all_strings)

            # Deduplicate and categorize
            seen = set()
            for s in all_strings:
                s_clean = s.strip()
                if not s_clean or s_clean in seen:
                    continue
                seen.add(s_clean)

                # Matching regexes
                if URL_REGEX.search(s_clean):
                    result["urls"].append(s_clean)
                elif IP_REGEX.search(s_clean):
                    result["ip_addresses"].append(s_clean)
                
                if PATH_REGEX.search(s_clean):
                    result["file_paths"].append(s_clean)
                
                if REGISTRY_REGEX.search(s_clean):
                    result["registry_keys"].append(s_clean)
                
                if EMAIL_REGEX.search(s_clean):
                    result["emails"].append(s_clean)

                # Keywords
                s_lower = s_clean.lower()
                if any(kw in s_lower for kw in PERSISTENCE_KEYWORDS):
                    result["persistence_indicators"].append(s_clean)
                
                if any(kw in s_lower for kw in RANSOMWARE_KEYWORDS):
                    result["ransomware_indicators"].append(s_clean)

                if any(kw in s_lower for kw in COMMANDS_KEYWORDS):
                    result["commands"].append(s_clean)

                # Check Base64 blobs
                if BASE64_REGEX.match(s_clean) and len(s_clean) >= 40:
                    result["base64_blobs"].append(s_clean)

            # Cap each category at 100 for safety / size reasons
            for key in result:
                if isinstance(result[key], list):
                    result[key] = sorted(list(set(result[key])))[:100]

        except Exception as exc:
            logger.exception("Error during string extraction of %s", pe_path)
            result["error"] = str(exc)

        return result

    def _extract_ascii(self, data: bytes) -> list[str]:
        """Extract ASCII strings from bytes."""
        ascii_re = re.compile(b'[ -~]{' + str(self.min_length).encode() + b',}')
        return [match.group().decode('ascii', errors='ignore') for match in ascii_re.finditer(data)]

    def _extract_unicode(self, data: bytes) -> list[str]:
        """Extract UTF-16 LE Unicode strings from bytes."""
        unicode_re = re.compile(b'(?:[ -~]\\x00){' + str(self.min_length).encode() + b',}')
        return [match.group().decode('utf-16le', errors='ignore') for match in unicode_re.finditer(data)]
