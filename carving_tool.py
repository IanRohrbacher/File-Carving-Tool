#!/usr/bin/env python3
"""Carve files from a target binary using header/footer byte signatures."""

from __future__ import annotations

import argparse
import bisect
import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from signatures import FileSignature, get_all_signatures


@dataclass
class CarveResult:
    output_path: Path
    payload_output_path: Optional[Path]
    start_offset: int
    end_offset: int
    size: int
    sha256: str
    file_type: str
    description: str
    is_valid: bool
    validation_error: str


@dataclass
class CarveCandidate:
    start_offset: int
    end_offset: int
    chunk: bytes


def parse_hex_signature(value: str) -> bytes:
    """Parse a user-provided hex string into bytes."""
    cleaned = (
        value.replace("0x", "")
        .replace("\\x", "")
        .replace(" ", "")
        .replace(",", "")
        .replace("-", "")
        .strip()
    )
    if len(cleaned) == 0:
        raise ValueError("Signature cannot be empty.")
    if len(cleaned) % 2 != 0:
        raise ValueError(f"Signature has odd length: {value!r}")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"Invalid hex signature: {value!r}") from exc


def find_all_occurrences(data: bytes, pattern: bytes) -> List[int]:
    """Return all start offsets for pattern, including overlapping matches."""
    offsets: List[int] = []
    start = 0
    while True:
        index = data.find(pattern, start)
        if index == -1:
            break
        offsets.append(index)
        start = index + 1
    return offsets


def compute_carve_ranges_for_type(
    data: bytes,
    header: bytes,
    footer: bytes,
    pairing: str = "nearest",
) -> List[Tuple[int, int]]:
    """Compute every possible [start, end) carve range for one file type.

    A range is valid when a footer appears at or after header_start + len(header).
    """
    header_offsets = find_all_occurrences(data, header)
    footer_offsets = find_all_occurrences(data, footer)

    ranges: List[Tuple[int, int]] = []
    min_gap = len(header)

    if pairing == "all":
        for h_start in header_offsets:
            for f_start in footer_offsets:
                if f_start >= h_start + min_gap:
                    ranges.append((h_start, f_start + len(footer)))
        return ranges

    # Default: choose the nearest footer after each header to avoid spanning across
    # unrelated embedded data.
    for h_start in header_offsets:
        min_footer_start = h_start + min_gap
        idx = bisect.bisect_left(footer_offsets, min_footer_start)
        if idx < len(footer_offsets):
            f_start = footer_offsets[idx]
            ranges.append((h_start, f_start + len(footer)))

    return ranges


def _validate_png(chunk: bytes) -> Optional[str]:
    if len(chunk) < 8:
        return "too short for PNG signature"
    if not chunk.startswith(bytes.fromhex("89504E470D0A1A0A")):
        return "missing PNG signature"

    pos = 8
    saw_iend = False
    while pos + 12 <= len(chunk):
        length = int.from_bytes(chunk[pos : pos + 4], byteorder="big")
        ctype = chunk[pos + 4 : pos + 8]
        pos += 8

        if pos + length + 4 > len(chunk):
            return "chunk length exceeds file size"

        # Skip chunk data and CRC.
        pos += length + 4

        if ctype == b"IEND":
            saw_iend = True
            if pos != len(chunk):
                return "extra bytes after IEND"
            break

    if not saw_iend:
        return "missing IEND chunk"
    return None


def _validate_jpeg(chunk: bytes) -> Optional[str]:
    # Baseline sanity check: start/end markers.
    if len(chunk) < 4:
        return "too short for JPEG markers"
    if not chunk.startswith(b"\xFF\xD8"):
        return "missing SOI marker"
    if not chunk.endswith(b"\xFF\xD9"):
        return "missing EOI marker"

    i = 2
    while i < len(chunk):
        if chunk[i] != 0xFF:
            return f"expected marker prefix 0xFF at offset {i}, got 0x{chunk[i]:02X}"

        # Skip fill bytes.
        while i < len(chunk) and chunk[i] == 0xFF:
            i += 1
        if i >= len(chunk):
            return "truncated marker stream"

        marker = chunk[i]
        i += 1

        if marker == 0xD9:
            if i != len(chunk):
                return "extra bytes after EOI"
            return None

        # Standalone markers without length.
        if marker in (0x01, *range(0xD0, 0xD8)):
            continue

        if i + 2 > len(chunk):
            return "truncated segment length"
        seg_len = int.from_bytes(chunk[i : i + 2], byteorder="big")
        if seg_len < 2:
            return "invalid segment length"
        i += 2

        # SOS: compressed image data until 0xFFD9 (respecting escaped 0xFF00 bytes).
        if marker == 0xDA:
            i += seg_len - 2
            if i > len(chunk):
                return "truncated SOS header"
            while i + 1 < len(chunk):
                if chunk[i] == 0xFF:
                    nxt = chunk[i + 1]
                    if nxt == 0x00:
                        i += 2
                        continue
                    if nxt == 0xD9:
                        i += 2
                        if i != len(chunk):
                            return "extra bytes after EOI"
                        return None
                    i += 1
                    continue
                i += 1
            return "missing EOI after SOS"

        i += seg_len - 2
        if i > len(chunk):
            return "truncated segment payload"

    return "missing EOI marker"


def validate_chunk(file_type: str, chunk: bytes) -> Optional[str]:
    # Apply format-aware validation only for known structured formats.
    if file_type == "png":
        return _validate_png(chunk)
    if file_type == "jpeg":
        return _validate_jpeg(chunk)
    return None


def guess_extension_from_magic(data: bytes) -> str:
    if data.startswith(bytes.fromhex("89504E470D0A1A0A")):
        return "png"
    if data.startswith(b"\xFF\xD8\xFF"):
        return "jpg"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    return "bin"


def carve_candidates_by_signatures(
    data: bytes,
    signatures: Dict[str, FileSignature],
    pairing: str = "nearest",
) -> Dict[str, List[CarveCandidate]]:
    result: Dict[str, List[CarveCandidate]] = {}
    for file_type, sig in signatures.items():
        ranges = compute_carve_ranges_for_type(
            data,
            sig.header,
            sig.footer,
            pairing=pairing,
        )
        candidates = [
            CarveCandidate(start_offset=start, end_offset=end, chunk=data[start:end])
            for start, end in ranges
        ]
        if candidates:
            result[file_type] = candidates
    return result


def carve_data_by_signatures(
    data: bytes,
    signatures: Dict[str, FileSignature],
    pairing: str = "nearest",
) -> Dict[str, List[bytes]]:
    """Return carved byte chunks organized by file type.

    Returns a dict mapping file type names to lists of carved chunks.
    """
    candidates = carve_candidates_by_signatures(data, signatures, pairing=pairing)
    return {
        file_type: [candidate.chunk for candidate in file_candidates]
        for file_type, file_candidates in candidates.items()
    }


def carve_file(
    target_path: Path,
    signatures: Dict[str, FileSignature],
    output_dir: Path,
    prefix: str = "carved",
    pairing: str = "nearest",
    only_valid_converted: bool = False,
    write_payload: bool = False,
) -> List[CarveResult]:
    """Carve a target file for all file types and write to type-specific subdirectories."""
    data = target_path.read_bytes()
    carved_by_type = carve_candidates_by_signatures(data, signatures, pairing=pairing)

    output_dir.mkdir(parents=True, exist_ok=True)
    results: List[CarveResult] = []

    for file_type, candidates in carved_by_type.items():
        sig = signatures[file_type]
        type_dir = output_dir / file_type
        bin_dir = type_dir / "bin"
        converted_dir = type_dir / "converted"
        payload_dir = type_dir / "payload"
        bin_dir.mkdir(parents=True, exist_ok=True)
        converted_dir.mkdir(parents=True, exist_ok=True)
        if write_payload:
            payload_dir.mkdir(parents=True, exist_ok=True)

        for i, candidate in enumerate(candidates, start=1):
            chunk = candidate.chunk
            filename = f"{prefix}_{i:03d}.bin"
            destination = bin_dir / filename
            destination.write_bytes(chunk)
            digest = hashlib.sha256(chunk).hexdigest()

            validation_error = validate_chunk(file_type, chunk)
            is_valid = validation_error is None

            converted_filename = f"{prefix}_{i:03d}.{sig.extension}"
            converted_path = converted_dir / converted_filename
            if not only_valid_converted or is_valid:
                converted_path.write_bytes(chunk)

            payload_output_path: Optional[Path] = None
            if write_payload and len(chunk) >= (len(sig.header) + len(sig.footer)):
                # Extract payload bytes between signature boundaries.
                payload = chunk[len(sig.header) : len(chunk) - len(sig.footer)]
                payload_ext = "bin"
                # Reclassify payload when it appears to contain a known wrapped file.
                for known_sig in signatures.values():
                    if payload.startswith(known_sig.header) and payload.endswith(known_sig.footer):
                        payload_ext = known_sig.extension
                        break
                if payload_ext == "bin":
                    payload_ext = guess_extension_from_magic(payload)
                payload_filename = f"{prefix}_{i:03d}_payload.{payload_ext}"
                payload_output_path = payload_dir / payload_filename
                payload_output_path.write_bytes(payload)

            results.append(
                CarveResult(
                    output_path=destination,
                    payload_output_path=payload_output_path,
                    start_offset=candidate.start_offset,
                    end_offset=candidate.end_offset,
                    size=len(chunk),
                    sha256=digest,
                    file_type=file_type,
                    description=sig.description,
                    is_valid=is_valid,
                    validation_error=validation_error or "",
                )
            )

    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Carve all possible files from target file(s) using registered signatures. "
                    "Defaults to input_data/ folder if no target specified, outputs to output_data/{timestamp}/."
    )
    parser.add_argument(
        "target",
        nargs="?",
        type=Path,
        default=Path("input_data"),
        help="Path to target binary file or folder. Defaults to input_data/ folder.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=None,
        help="Directory where carved files are organized. Defaults to output_data/{timestamp}/.",
    )
    parser.add_argument(
        "--prefix",
        default="carved",
        help="Prefix for carved output files.",
    )
    parser.add_argument(
        "--pairing",
        choices=("nearest", "all"),
        default="nearest",
        help="How headers are paired with footers: nearest (default) or all combinations.",
    )
    parser.add_argument(
        "--only-valid-converted",
        action="store_true",
        help="Write converted output files only when basic format validation passes.",
    )
    parser.add_argument(
        "--write-payload",
        action="store_true",
        help="Also write the bytes between header/footer for each carve candidate.",
    )
    parser.add_argument(
        "--list-signatures",
        action="store_true",
        help="List all registered file signatures and exit.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.list_signatures:
        sigs = get_all_signatures()
        print("Registered file signatures:")
        for file_type, sig in sigs.items():
            print(f"  {file_type}: {sig.description}")
            print(f"    Header: {sig.header.hex().upper()}")
            print(f"    Footer: {sig.footer.hex().upper()}")
        return 0

    if not args.target.exists():
        parser.error(f"Target does not exist: {args.target}")

    if args.output_dir is None:
        timestamp = datetime.now().strftime("%m_%d_%Y_%H_%M_%S")
        output_data_root = Path("output_data")
        output_data_root.mkdir(parents=True, exist_ok=True)
        args.output_dir = output_data_root / timestamp

    signatures = get_all_signatures()
    all_results: List[CarveResult] = []

    if args.target.is_dir():
        files_to_carve = sorted([f for f in args.target.iterdir() if f.is_file()])
        if not files_to_carve:
            print(f"No files found in folder: {args.target}")
            return 0
        print(f"Carving {len(files_to_carve)} file(s) from {args.target}/")
        print()
        for target_file in files_to_carve:
            file_output_dir = args.output_dir / f"{target_file.stem}_output"
            results = carve_file(
                target_path=target_file,
                signatures=signatures,
                output_dir=file_output_dir,
                prefix=args.prefix,
                pairing=args.pairing,
                only_valid_converted=args.only_valid_converted,
                write_payload=args.write_payload,
            )
            all_results.extend(results)
            print(f"  {target_file.name}: {len(results)} file(s) carved")
    else:
        file_output_dir = args.output_dir / f"{args.target.stem}_output"
        all_results = carve_file(
            target_path=args.target,
            signatures=signatures,
            output_dir=file_output_dir,
            prefix=args.prefix,
            pairing=args.pairing,
            only_valid_converted=args.only_valid_converted,
            write_payload=args.write_payload,
        )
        print(f"Target: {args.target}")

    print()
    print(f"Registered signatures: {', '.join(signatures.keys())}")
    print(f"Total carved files: {len(all_results)}")
    print(f"Output: {args.output_dir}")
    valid_count = sum(1 for result in all_results if result.is_valid)
    invalid_count = len(all_results) - valid_count
    print(f"Validation: valid={valid_count}, invalid={invalid_count}")
    print()

    if not all_results:
        print("No files carved.")
        return 0

    for result in all_results:
        validity_text = "valid" if result.is_valid else f"invalid ({result.validation_error})"
        payload_text = f" payload={result.payload_output_path.name}" if result.payload_output_path else ""
        print(
            f"[{result.file_type.upper()}] {result.output_path.name} | "
            f"offsets={result.start_offset}:{result.end_offset} "
            f"size={result.size} sha256={result.sha256} {validity_text}{payload_text}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
