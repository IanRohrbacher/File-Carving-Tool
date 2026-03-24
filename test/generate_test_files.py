#!/usr/bin/env python3
"""Generate test binaries from user-provided source files.

Source file bytes are included as-is (never modified internally). Random gibberish
may be added before, between, and after files to simulate noisy containers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from carving_tool import carve_data_by_signatures
from signatures import get_all_signatures


# Keep generated fixtures deterministic across runs.
random.seed(42)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def random_padding(min_size: int = 32, max_size: int = 256, weight: float = 1.0) -> bytes:
    """Generate random binary padding."""
    weighted_min = max(0, int(round(min_size * weight)))
    weighted_max = max(weighted_min, int(round(max_size * weight)))
    size = random.randint(weighted_min, weighted_max)
    return os.urandom(size)


def build_test_cases(
    source_dir: Path,
    signatures: Dict[str, object],
    padding_weight: float = 1.0,
) -> List[Dict[str, object]]:
    """Build noisy container binaries from source files without mutating source bytes.

    Cases include containers with many, some, one, and no source files.
    """
    cases: List[Dict[str, object]] = []

    # Read source fixtures that will be embedded unchanged in generated containers.
    source_files: List[tuple[str, bytes]] = []
    if source_dir.exists() and source_dir.is_dir():
        for file_path in sorted(source_dir.iterdir()):
            if file_path.is_file():
                source_files.append((file_path.name, file_path.read_bytes()))

    if not source_files:
        print(f"Warning: No source files found in {source_dir}/")
        print(f"Creating {source_dir}/ and using synthetic data for demo.")
        source_dir.mkdir(parents=True, exist_ok=True)
        source_files = [("synthetic_data", b"SYNTHETIC_HIDDEN_DATA")]

    # Case 1: Many source files in one noisy container.
    case1_parts = [random_padding(weight=padding_weight)]
    for _src_name, src_data in source_files:
        case1_parts.append(src_data)
        case1_parts.append(random_padding(32, 96, weight=padding_weight))
    case1_parts.append(random_padding(weight=padding_weight))
    case1 = b"".join(case1_parts)
    cases.append(
        {
            "name": "multi_signature_single_source.bin",
            "description": f"Noisy container with all {len(source_files)} source files as raw bytes.",
            "bytes": case1,
        }
    )

    # Case 2: Some source files in one noisy container.
    if len(source_files) >= 2:
        subset_count = max(2, len(source_files) // 2)
        selected_sources = source_files[:subset_count]
        case2_parts = [random_padding(weight=padding_weight)]
        for _src_name, src_data in selected_sources:
            case2_parts.append(src_data)
            case2_parts.append(random_padding(16, 64, weight=padding_weight))
        case2_parts.append(random_padding(weight=padding_weight))
        case2 = b"".join(case2_parts)
        cases.append(
            {
                "name": "multi_source_multi_signature.bin",
                "description": f"Noisy container with a subset of {len(selected_sources)} raw source files.",
                "bytes": case2,
            }
        )

    # Case 3: Real files with synthetic false-positive/corrupted marker pairs.
    case3_parts = [random_padding(weight=padding_weight)]

    # Keep real source bytes intact; noise is only around full files.
    real_count = min(2, len(source_files))
    for _src_name, src_data in source_files[:real_count]:
        case3_parts.append(src_data)
        case3_parts.append(random_padding(24, 80, weight=padding_weight))

    # Inject malformed marker patterns to force false positives.
    for _sig_name, sig in signatures.items():
        marker = f"false positive:{_sig_name}".encode("ascii")

        # Full header+random payload+footer pair likely to carve as invalid output.
        case3_parts.append(sig.header)
        case3_parts.append(random_padding(8, 24, weight=padding_weight))
        case3_parts.append(marker)
        case3_parts.append(random_padding(8, 24, weight=padding_weight))
        case3_parts.append(sig.footer)
        case3_parts.append(random_padding(16, 64, weight=padding_weight))

        # Standalone markers to create additional ambiguous boundaries.
        case3_parts.append(sig.header)
        case3_parts.append(marker)
        case3_parts.append(random_padding(8, 16, weight=padding_weight))
        case3_parts.append(sig.footer)
        case3_parts.append(random_padding(8, 24, weight=padding_weight))

    case3_parts.append(random_padding(weight=padding_weight))
    case3 = b"".join(case3_parts)
    cases.append(
        {
            "name": "with_false_positives.bin",
            "description": "Noisy container with real files plus synthetic false-positive/corrupted marker pairs.",
            "bytes": case3,
        }
    )

    # Case 4: No source files at all (only gibberish).
    case4 = random_padding(512, 1024, weight=padding_weight)
    cases.append(
        {
            "name": "no_match.bin",
            "description": "Random data with no valid signatures.",
            "bytes": case4,
        }
    )

    return cases


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate noisy test binaries from source files. Source bytes are preserved "
            "exactly; random padding is placed around files."
        )
    )
    parser.add_argument(
        "--padding-weight",
        type=float,
        default=1.0,
        help=(
            "Multiplier applied to all random padding ranges. "
            "1.0 keeps current defaults, 0.5 reduces padding, 2.0 increases it."
        ),
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.padding_weight < 0:
        parser.error("--padding-weight must be >= 0")

    root = Path(__file__).resolve().parent
    source_dir = root / "test_data_source"
    test_data_dir = root / "test_data"
    test_data_dir.mkdir(parents=True, exist_ok=True)

    signatures = get_all_signatures()

    # Track expected carve results for each generated case.
    manifest: Dict[str, object] = {
        "signatures": {
            name: {
                "description": sig.description,
                "header_hex": sig.header.hex().upper(),
                "footer_hex": sig.footer.hex().upper(),
            }
            for name, sig in signatures.items()
        },
        "cases": [],
    }

    for case in build_test_cases(source_dir, signatures, padding_weight=args.padding_weight):
        case_name = str(case["name"])
        case_bytes = bytes(case["bytes"])
        case_path = test_data_dir / case_name
        case_path.write_bytes(case_bytes)

        chunks_by_type = carve_data_by_signatures(case_bytes, signatures)
        case_manifest = {
            "file": case_name,
            "description": case["description"],
            "size": len(case_bytes),
            "source_sha256": sha256_hex(case_bytes),
            "carved_by_type": {},
        }

        for sig_name, chunks in chunks_by_type.items():
            chunk_hashes = [sha256_hex(chunk) for chunk in chunks]
            case_manifest["carved_by_type"][sig_name] = {
                "count": len(chunks),
                "sha256": chunk_hashes,
            }

        manifest["cases"].append(case_manifest)

    manifest_path = test_data_dir / "expected_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"Generated test files in: {test_data_dir}")
    print(f"Manifest: {manifest_path}")
    print(f"Cases: {len(manifest['cases'])}")
    print(f"Padding weight: {args.padding_weight}")
    if not source_dir.exists():
        print(f"\nNote: Place your test data files in {source_dir}/ for custom scenarios.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
