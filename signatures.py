#!/usr/bin/env python3
"""File type signatures (header/footer pairs) for carving.

Add new file types by adding entries to the SIGNATURES dict below.
Format: "unique_name": FileSignature(header=bytes, footer=bytes, description="Human readable description")
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass
class FileSignature:
    """A file type signature with header, footer, and description."""

    header: bytes
    footer: bytes
    description: str
    extension: str


# PNG: 89 50 4E 47 0D 0A 1A 0A = PNG magic number
#      49 45 4E 44 AE 42 60 82 = IEND chunk (end of PNG)
PNG_SIGNATURE = FileSignature(
    header=bytes.fromhex("89504E470D0A1A0A"),
    footer=bytes.fromhex("49454E44AE426082"),
    description="Portable Network Graphics (PNG)",
    extension="png",
)

# JPEG: FF D8 FF = Start of Image
#       FF D9 = End of Image
JPEG_SIGNATURE = FileSignature(
    header=bytes.fromhex("FFD8FF"),
    footer=bytes.fromhex("FFD9"),
    description="JPEG Image (JPEG)",
    extension="jpg",
)

# Add additional file signatures to SIGNATURES to extend carving support.
SIGNATURES: Dict[str, FileSignature] = {
    "png": PNG_SIGNATURE,
    "jpeg": JPEG_SIGNATURE,
}


def get_signature(name: str) -> FileSignature:
    """Get signature by name."""
    if name not in SIGNATURES:
        raise ValueError(f"Unknown signature: {name}")
    return SIGNATURES[name]


def get_all_signatures() -> Dict[str, FileSignature]:
    """Get all registered file signatures."""
    return SIGNATURES.copy()


def add_signature(name: str, header: bytes, footer: bytes, description: str) -> None:
    """Register a new signature at runtime."""
    SIGNATURES[name] = FileSignature(header=header, footer=footer, description=description)

