# File Carving Tool

Extract embedded files from binary data using header/footer byte signatures.

This project includes a command-line carver, test-data generation, manifest verification, and an end-to-end test runner.

## What It Does

- Carves file candidates for all registered signatures in one pass.
- Supports two header/footer pairing modes: nearest and all.
- Writes raw carved chunks and extension-based converted files.
- Optionally writes payload bytes (between header/footer) for each carve.
- Performs basic validity checks for PNG and JPEG carved output.

## Supported Signatures (Current Default)

- PNG
- JPEG

Add more in signatures.py by extending the signature registry.

## Project Layout

- carving_tool.py: main CLI carver
- signatures.py: signature registry and helpers
- test/generate_test_files.py: creates noisy binary test cases + expected manifest
- test/verify_test_files.py: verifies generated test files against the manifest
- test/run_tests.py: runs carving tests and writes a markdown summary
- test/test_data_source/: source files used to build generated test inputs
- test/test_data/: generated test binaries + expected_manifest.json

## Requirements

- Python 3.10+

No external dependencies are currently required (requirements.txt is empty).

## Setup (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
# python -m pip install -r requirements.txt
```

## Using the Carving Tool

Show help:

```powershell
python .\carving_tool.py -h
```

List registered signatures:

```powershell
python .\carving_tool.py --list-signatures
```

Carve everything in input_data/ (default target):

```powershell
python .\carving_tool.py
```

Carve one file and write payload output:

```powershell
python .\carving_tool.py .\test\test_data\multi_signature_single_source.bin --write-payload
```

Write converted files only when PNG/JPEG validation passes:

```powershell
python .\carving_tool.py --only-valid-converted
```

Try exhaustive pairing (every matching header/footer combination):

```powershell
python .\carving_tool.py --pairing all
```

Use a custom output directory and file prefix:

```powershell
python .\carving_tool.py .\input_data -o .\output_data\manual_run --prefix sample
```

## Key CLI Options

- target: file or folder to carve (defaults to input_data)
- -o, --output-dir: output root (defaults to output_data/<timestamp>)
- --prefix: output file prefix (default carved)
- --pairing: nearest (default) or all
- --only-valid-converted: only write converted files when validation passes
- --write-payload: write bytes between header/footer into payload/ subfolder
- --list-signatures: print signatures and exit

## Output Structure

For each target file, output is grouped by file type:

```text
output_data/<timestamp>/
    <input_name>_output/
        png/
            bin/
            converted/
            payload/      # only if --write-payload is used
        jpeg/
            bin/
            converted/
            payload/      # only if --write-payload is used
```

Notes:

- bin/ always contains carved raw chunks as .bin.
- converted/ uses the signature extension (PNG -> .png, JPEG -> .jpg).
- payload/ is optional and is created only when --write-payload is enabled.

## Using the Test Tools

1. Place source files in test/test_data_source/.
2. Generate noisy test containers and expected manifest.
3. Verify generated files against the manifest.
4. Run end-to-end carving tests.

Generate test files:

```powershell
python .\test\generate_test_files.py
```

Generate with less or more random padding:

```powershell
python .\test\generate_test_files.py --padding-weight 0.5
python .\test\generate_test_files.py --padding-weight 2.0
```

Verify generated files:

```powershell
python .\test\verify_test_files.py
```

Run end-to-end tests and write report:

```powershell
python .\test\run_tests.py
```

Test report output:

- report test/test_output/<timestamp>/test_summary.md
- carved test output under test/test_output/<timestamp>/

## Expected Behavior for Unsupported Types

The carver only extracts signatures registered in signatures.py.

If a target contains unsupported embedded types (for example WEBP when only PNG/JPEG are registered), those files are not carved.

## License

MIT License
