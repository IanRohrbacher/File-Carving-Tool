#!/usr/bin/env python3
"""Verify generated test files against expected manifest values."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from carving_tool import carve_data_by_signatures
from signatures import get_all_signatures


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    root = Path(__file__).resolve().parent
    test_data_dir = root / "test_data"
    manifest_path = test_data_dir / "expected_manifest.json"

    if not manifest_path.exists():
        print("Manifest not found. Run generate_test_files.py first.")
        return 1

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    all_sigs = get_all_signatures()
    
    # Validate each generated case against manifest hashes and carve counts.
    all_passed = True
    cases: List[Dict[str, object]] = manifest["cases"]

    print(f"Verifying {len(cases)} case(s)...")

    for case in cases:
        file_name = str(case["file"])
        file_path = test_data_dir / file_name
        carved_by_type = case["carved_by_type"]

        if not file_path.exists():
            print(f"[FAIL] Missing file: {file_name}")
            all_passed = False
            continue

        source = file_path.read_bytes()
        source_hash = sha256_hex(source)
        if source_hash != case["source_sha256"]:
            print(f"[FAIL] Source hash mismatch: {file_name}")
            all_passed = False
            continue

        chunks_by_type = carve_data_by_signatures(source, all_sigs)
        
        # Compare expected carved outputs with current carve results by type.
        case_passed = True
        for file_type, expected_info in carved_by_type.items():
            expected_count = expected_info["count"]
            expected_hashes = expected_info["sha256"]
            actual_chunks = chunks_by_type.get(file_type, [])
            actual_hashes = [sha256_hex(chunk) for chunk in actual_chunks]

            if len(actual_chunks) != expected_count or actual_hashes != expected_hashes:
                print(
                    f"[FAIL] {file_name} ({file_type}): "
                    f"expected {expected_count} carving(s), got {len(actual_chunks)}"
                )
                case_passed = False
                all_passed = False

        if case_passed:
            print(f"[PASS] {file_name}")

    if all_passed:
        print("All generated test files are valid.")
        return 0

    print("Verification failed for one or more files.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
