# peanalyzer

A command-line tool to statically analyze Portable Executable (PE) files and emit human-friendly summaries in CSV and JSON formats.

This repository contains `peanalyzer.py`, a lightweight PE inspection utility built on top of the `pefile` library. It extracts common PE metadata like sections, imports, exports, TLS callbacks, delay-load imports, relocations, overlay, resources and a DOS stub.

## Prerequisites

- Python 3.8+ installed
- `pefile` Python package

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

If you don't use the provided `requirements.txt`, install `pefile` directly:

```bash
python3 -m pip install pefile
```

## Usage

Basic analysis:

```bash
python3 peanalyzer.py /path/to/binary.exe
```

Write CSV summary (one-line rows of category/field/value):

```bash
python3 peanalyzer.py /path/to/binary.exe --csv
```

This writes a file named `<basename>.csv` in the current working directory (for example `binary.csv`).

Write JSON report:

```bash
python3 peanalyzer.py /path/to/binary.exe --json
```

This writes `<basename>.json` in the current working directory (for example `binary.json`). The JSON contains a `report`-like structure with these top-level keys:

- `file` — filename analyzed
- `sections` — map of section names to metadata (hashes, entropy, characteristics, virtual_size, sizeofrawdata)
- `stub` — DOS stub bytes as a hex string (if present)
- `timestamp` — IMAGE_FILE header TimeDateStamp as ISO 8601 string (if present)
- `imports` — mapping DLL -> list of imported symbols
- `exports` — mapping exported name/ordinal -> (address, forwarder) tuples
- `resource_strings_count` — number of resource strings found (if any)
- `overlay_size` — size in bytes of the overlay, if present
- `tls_callbacks` — list of TLS callback objects; each object includes `address` and may include `hex` (first bytes of function) or `data_error` if reading failed
- `delay_imports` — mapping of delay-loaded DLLs to their imported symbols
- `relocations` — list of relocation entries (type, rva)

## Examples

Write both CSV and JSON for a file:

```bash
python3 peanalyzer.py /path/to/binary.exe --csv --json
# produces binary.csv and binary.json in the current folder
```

## Troubleshooting

- Permission errors: Run the command as a user with read access to the file.
- Not a PE file: `pefile` will raise a PEFormatError and the script will exit with an error message.
