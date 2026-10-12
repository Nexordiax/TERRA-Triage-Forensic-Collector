# TERRA partial process memory — Volatility 3 plugins

Independent, offline plugins for TERRA's **non-root process-memory capture ZIP**.
No TERRA application imports, kernel symbols, privileged reads, evidence uploads
or changes to TERRA are required. Tested with Volatility 3 **2.28.2**, including
the checkout at `/home/naharn/forensics/volatility3`.

## Quick start

Use the Python environment you normally use for Volatility 3. Replace the capture
path below with the ZIP created by non-admin RAM acquisition. It should contain
`manifest.json` and `processes/` at its root. These plugins accept both manifest
versions 1 and 2, or a directory containing the extracted capture.

```bash
cd /home/naharn/forensics/volatility3
python3 vol.py --offline -p /home/naharn/TERRA/plugins/volatility3 terramemory.Processes --capture "/path/to/non-root-RAM.zip"
python3 vol.py --offline -p /home/naharn/TERRA/plugins/volatility3 terramemory.Verify --capture "/path/to/non-root-RAM.zip"
python3 vol.py --offline -p /home/naharn/TERRA/plugins/volatility3 terramemory.Maps --capture "/path/to/non-root-RAM.zip"
python3 vol.py --offline -p /home/naharn/TERRA/plugins/volatility3 terramemory.Strings --capture "/path/to/non-root-RAM.zip" --minimum 6
python3 vol.py --offline -p /home/naharn/TERRA/plugins/volatility3 terramemory.Search --capture "/path/to/non-root-RAM.zip" --needle "example.com"
```

Use **`--capture`**, rather than Volatility's global `-f` option. `-p` tells
Volatility where to discover these plugins; it does not copy or install them.
The plugin path must contain `terramemory.py` and the `terra_support/` directory.
For a final TERRA triage export, extract its inner `terra/memory/<name>.zip` first
and pass that inner partial-memory ZIP. LiME images and outer triage ZIPs are not
accepted. ZIP members are read directly without extraction.

## Available plugins

| Plugin | Output |
| --- | --- |
| `terramemory.Processes` | Captured, unavailable and excluded PIDs; accessible executable identity, argv, start time, acquisition times, change checks and access errors. Full recorded context is included as JSON. |
| `terramemory.Maps` | Structured mappings, compact-file segments, virtual addresses, acquisition metadata, explicit unreadable/unattempted ranges, and non-readable mappings. |
| `terramemory.Strings` | Printable ASCII or ASCII-range UTF-16 strings, with source PID, virtual address and region member. |
| `terramemory.Search` | Literal UTF-8, UTF-16 or hexadecimal byte matches, with source PID and virtual address. |
| `terramemory.Verify` | Streaming SHA-256 comparison for each region; `MATCH`, `MISMATCH`, or a read/CRC error. |
| `terramemory.Dump` | Verified original compact `.bin` regions plus JSON address-map/context sidecars, using Volatility's output file handler. |

Every plugin accepts `--pid 1234 5678` to filter results. Put this list last,
or follow it with another named option. Without it, all recorded captured PIDs
are examined; Processes additionally shows inaccessible/excluded PIDs.

Additional examples:

```bash
# UTF-16 text, common in application memory. Exact-case search.
python3 vol.py --offline -p /home/naharn/TERRA/plugins/volatility3 terramemory.Search --capture "/path/to/non-root-RAM.zip" --needle "investigation" --encoding utf-16-le

# Hexadecimal byte search.
python3 vol.py --offline -p /home/naharn/TERRA/plugins/volatility3 terramemory.Search --capture "/path/to/non-root-RAM.zip" --needle "50 4b 03 04" --encoding hex

# ASCII case-insensitive search in one PID.
python3 vol.py --offline -p /home/naharn/TERRA/plugins/volatility3 terramemory.Search --capture "/path/to/non-root-RAM.zip" --needle "example.com" --ignore-case --pid 1234

# ASCII-range UTF-16 strings, with no row limit.
python3 vol.py --offline -p /home/naharn/TERRA/plugins/volatility3 terramemory.Strings --capture "/path/to/non-root-RAM.zip" --encoding utf-16-le --limit 0

# Machine-readable JSON results (global renderer option goes before plugin).
python3 vol.py --offline -r json -p /home/naharn/TERRA/plugins/volatility3 terramemory.Processes --capture "/path/to/non-root-RAM.zip" > process-context.json

# Export regions to an existing analysis destination. Input ZIP stays unchanged.
mkdir -p /path/to/analysis-output
python3 vol.py --offline -o /path/to/analysis-output -p /home/naharn/TERRA/plugins/volatility3 terramemory.Dump --capture "/path/to/non-root-RAM.zip"
```

Strings and Search default to **10,000 output rows**. They warn when additional
results are omitted; use `--limit 0` to remove this cap. Search terms are limited
to 65,536 encoded bytes. Strings supports minimum lengths 1–4096 and splits
longer runs into bounded 4096-character pieces; these pieces are not separate
logical application values. UTF-16 string extraction covers printable ASCII
characters encoded as UTF-16, not arbitrary multilingual Unicode. Exact UTF-16
Search supports Unicode terms. `--ignore-case` performs ASCII byte folding and
is supported for UTF-8/hex only.

## Interpretation and integrity

This evidence contains **accessible process virtual memory**, not physical RAM.
It cannot provide kernel tasks, sockets, kernel modules or page tables needed by
standard `linux.pslist`, `linux.sockstat`, and similar kernel-based plugins.
These separate plugins use the collector's manifest and captured bytes; they do
not reconstruct missing kernel data. Process context is an observation made by
TERRA, not independently recovered kernel structure data.

Run Verify first. SHA-256 matches show agreement with the recorded manifest,
not independent authenticity, completeness or a simultaneous snapshot. Normal
analysis validates format, member sizes and segment structure, but does not
automatically rehash every region. Dump verifies before export and checks again
during copying. If copying fails or evidence changes, Volatility may leave a
partial output; treat output without its verified JSON sidecar as unsuccessful.

File offsets refer to compact region bytes. Virtual addresses are reconstructed
using `segments`; absent ranges remain absent and are never zero-filled. Searches
do not bridge gaps or region boundaries. Shared memory may appear in several
processes, so findings and captured byte totals can repeat. Missing context in a
v1 capture cannot be reconstructed by these plugins. Failed change checks remain
unknown. Accessible mapping/context checks cannot establish that every memory
byte stayed unchanged during a live acquisition.

Readers reject duplicate ZIP names, invalid/overlapping segment mappings,
inconsistent region sizes and unsafe member paths. Directory reads reject links
escaping the capture directory. Input files are opened read-only; filesystem
access-time behavior still depends on the mount. Metadata is bounded to 32 MiB,
and memory scans use bounded streaming reads. Plugins do not execute evidence.

## Standalone tests

From TERRA's root, with Volatility 3 installed in the chosen Python environment:

```bash
TERRA_VOL3_CLI=/home/naharn/forensics/volatility3/vol.py python3 plugins/volatility3/tests/test_plugins.py
```

If running a Python environment without an installed package, add the checkout
to `PYTHONPATH`. The CLI test uses temporary fixtures and output directories,
tests discovery and all six plugins, and compares exported bytes and sidecars.
No real evidence or TERRA modules are used by the tests. Without
`TERRA_VOL3_CLI`, the CLI integration test is skipped.

Framework references used for implementation:
[official plugin development documentation](https://volatility3.readthedocs.io/en/stable/development.html),
[PluginInterface](https://volatility3.readthedocs.io/en/stable/volatility3.framework.interfaces.plugins.html),
and the [official source repository](https://github.com/volatilityfoundation/volatility3).
