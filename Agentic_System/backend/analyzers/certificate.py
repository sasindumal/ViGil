"""
ViGil — PE Certificate & Authenticode Analyzer
===============================================

Checks if a PE file is signed by inspecting the Security directory entry,
tries to parse certificate details using the Signify library (if available),
identifies signers, validity windows, and computes a trust score.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pefile

logger = logging.getLogger(__name__)

# Try to import Signify for digital signature parsing
try:
    from signify.authenticode.signed_pe import SignedPEFile
    SIGNIFY_AVAILABLE = True
except ImportError:
    SIGNIFY_AVAILABLE = False


class CertificateAnalyzer:
    """Analyzes digital signatures and trust characteristics of PE files."""

    def analyze(self, pe_path: Path) -> dict[str, Any]:
        """Verify the signature and extract certificate chain data.

        Returns
        -------
        dict
            is_signed flag, signer_info, validity status, and trust score.
        """
        result: dict[str, Any] = {
            "is_signed": False,
            "signer_info": {},
            "certificate_valid": False,
            "trust_score": 0,
            "signify_available": SIGNIFY_AVAILABLE,
        }

        try:
            pe = pefile.PE(str(pe_path), fast_load=True)
        except Exception as exc:
            logger.error("Failed to parse PE in certificate analyzer %s: %s", pe_path, exc)
            result["error"] = str(exc)
            return result

        try:
            # 1. Check if the Security Directory exists and is not zero
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
            ]
            
            is_signed = bool(security_dir.VirtualAddress and security_dir.Size)
            result["is_signed"] = is_signed

            if not is_signed:
                result["trust_score"] = 0
                result["certificate_valid"] = False
                return result

            # Default if signed but signify is missing
            result["trust_score"] = 50  # Baseline for having a signature
            result["certificate_valid"] = True  # Tentative

            # 2. Try to parse certificate using Signify
            if SIGNIFY_AVAILABLE:
                try:
                    with open(pe_path, "rb") as f:
                        signed_pe = SignedPEFile(f)
                        
                        # Verify the signature
                        # Note: verification checks the signature structure, not necessarily trust roots
                        try:
                            verify_result = signed_pe.verify()
                            result["certificate_valid"] = True
                            result["trust_score"] = 80
                        except Exception as v_err:
                            logger.info("Signature verification failed: %s", v_err)
                            result["certificate_valid"] = False
                            result["trust_score"] = 20

                        # Extract certificates
                        signer_info = {}
                        for cert in signed_pe.certs:
                            signer_info = {
                                "issuer": str(cert.issuer),
                                "subject": str(cert.subject),
                                "serial_number": str(cert.serial_number),
                                "valid_from": cert.valid_from.isoformat() if hasattr(cert, "valid_from") else None,
                                "valid_to": cert.valid_to.isoformat() if hasattr(cert, "valid_to") else None,
                            }
                            # Self-signed check
                            if cert.issuer == cert.subject:
                                signer_info["self_signed"] = True
                                result["trust_score"] = min(result["trust_score"], 30)
                            else:
                                signer_info["self_signed"] = False
                            break  # Just take the primary certificate
                        
                        result["signer_info"] = signer_info

                except Exception as s_err:
                    logger.warning("Signify failed to parse PE signature: %s", s_err)
                    result["signer_info"] = {"error": f"Parsing failed: {s_err}"}

        except Exception as exc:
            logger.exception("Error during certificate analysis of %s", pe_path)
            result["error"] = str(exc)
        finally:
            pe.close()

        return result
