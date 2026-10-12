# Scan acceleration

## Parallel media analysis

Independent pictures, eligible PDFs/documents and explicitly enabled video screening
now overlap in isolated analysis processes. CPU affinity/quotas and measured available
RAM determine one to four analysis workers. Readable cgroup-v2 memory limits, including
parent limits, reduce the available allowance. Scheduling leaves 1 GiB for TERRA/the
desktop and allows 1.5 GiB per decoder; unknown host memory keeps analysis serial.
This is a startup limit, not a promise about available memory throughout a long scan.
An optional backend `analysis_workers` integer (1–4) can reduce the count; it cannot
bypass CPU/memory caps. There are no additional GUI controls.

Primary file reads retain their separate storage-aware concurrency limit. Thus a
rotational drive can read serially while cached pictures are analysed concurrently.
Uncached decoder inputs and enabled videos still require their existing verified
source reads. Archives/Office containers, credential-dependent retries and structured
parsers stay on the coordinator. Large imported container hash/keyword lists and
archive credentials are not copied into unrelated picture-worker requests.

The queue is bounded to twice the larger worker count, with at most 64 MiB of retained
input reserved within the evidence budget and 16 MiB of result per pending analysis.
The coordinator owns IDs, counters, diagnostics, callbacks, evidence storage and
recovery checkpoints. A slow independent media decoder no longer blocks ready
findings behind it: when the head job is media and at least 16 MiB of derived-result
headroom remains, completed jobs can publish first. File IDs and live arrival order
therefore may differ from a serial run; acquired bytes, hashes and per-file findings
are compared by source path in equivalence tests. Read-only batches retain their
ordering, and tight result-budget allocation stays ordered. Waiting progress displays
active media jobs instead of appearing stuck at the previous read. If a speculative
result exceeds the remaining scan analysis budget, it is analysed again at that
remaining budget before publication. Stop cancels pending work, waits for running
workers to terminate and releases all descriptors/reservations. Interrupted files
remain eligible for resume; unpublished speculative results are not checkpointed.

Synthetic media measurements, 2026-10-10: 12 generated 1024×768 PNGs, one primary
reader, median of three runs, eight usable CPUs, RAM-capped to two analysis workers.
Every run compared complete findings, acquired hashes/bytes, counters and coverage
with the serial result.

| Workload | 1 analysis worker | 2 analysis workers | Speedup |
| --- | ---: | ---: | ---: |
| Skin-colour screening | 0.9933 s | 0.5346 s | 1.86× |
| OCR and skin-colour screening | 2.1612 s | 1.1603 s | 1.86× |

Requesting four workers remained capped to two and produced similar timings. These
small synthetic measurements do not predict a complete disk scan, cold storage,
semantic segmentation or weapon-model inference. Reproduce with:

```bash
QT_QPA_PLATFORM=offscreen PYTHONDONTWRITEBYTECODE=1 OPENBLAS_NUM_THREADS=1 \
.venv/bin/python -m tests.benchmark_media_scan
```

Add `--ocr` or `--weapon` to exercise the installed offline capabilities. Regression
tests cover real serial/parallel results in both collection modes, actual analysis
overlap, small retention/result budgets, CPU/memory caps, cancellation cleanup,
completed checkpoint loading and stopped-checkpoint resume without duplicate findings.

Files changed for this extension: `controllers/scan_controller.py`,
`controllers/scan_scheduler.py`, `tests/test_parallel_media.py`,
`tests/benchmark_media_scan.py` and this document.

Independent large-file reads, imported hashes and raw content matching now overlap.
One coordinator owns finding IDs, callbacks, prompts, counters, parsers and storage.
SHA256 matching reuses the integrity digest instead of hashing the same bytes twice.
Existing modes, GUI, RAM acquisition and export remain available.

## Automatic scheduling

Usable CPU count respects affinity and readable cgroup-v2 quotas. Known nonrotational
storage uses at most four readers, unknown storage at most two, and identified
rotational media stays serial. Files below 1 MiB stay serial because local measurements
show thread overhead outweighs gains. Structured parsers and companions remain serial.
An optional backend scan_workers integer (1–8, CPU-capped) overrides scheduling for
integration tests/tuning; no GUI controls are added. Custom collectors stay serial
unless explicitly overridden.

The pending queue holds at most twice the reader count and reserves at most 64 MiB
of retained bytes within the existing RAM evidence budget. It never spills to disk.
Each queued read owns independent matchers and a duplicated directory descriptor.
Read-only results are consumed in submission order; mixed media batches can publish
ready results ahead of a slow media decoder as described above. Stop polls while waiting, shuts readers
down, and releases reservations/descriptors. Oversized files are still streamed.

## Synthetic measurements

Development measurements, 2026-10-10: eight allowed logical CPUs, warm-cache temporary
fixtures, median of three runs. Explicit worker counts bypass the small-file cutoff.
All runs produced identical hashes, matches, counters and retained bytes.

| Workload | 1 reader | 2 readers | 4 readers |
| --- | ---: | ---: | ---: |
| 256 × 32 KiB, SHA256 matches | 0.8770 s | 0.9405 s | 0.9497 s |
| 12 × 16 MiB, SHA256 matches | 0.2102 s | 0.1331 s | 0.1008 s |
| 12 × 16 MiB, hashes and keywords | 0.3914 s | 0.3483 s | 0.3237 s |
| 256 × 32 KiB, hashes/keywords, 8 MiB retained | 0.9618 s | 0.9653 s | 0.9767 s |

Large hash-bound reads improved about 2.1× with four readers in this fixture;
keyword-heavy reads improved less. Small-file results motivated the automatic
serial cutoff. These timings do not predict every device. Cold HDD/SSD, removable
and network media, OCR/weapon inference and RAM dumping need separate measurements.

Reproduce with synthetic files only:

```bash
QT_QPA_PLATFORM=offscreen PYTHONDONTWRITEBYTECODE=1 OPENBLAS_NUM_THREADS=1 \
.venv/bin/python -m tests.benchmark_scan
```

Regression tests cover full/matches-only equivalence, retention limits, worker errors
and timeouts, exact hash callback counts, Stop/descriptor cleanup, serial parsers and
automatic small-file scheduling.

Primary references:

- [Python hashing and GIL](https://docs.python.org/3/library/hashlib.html)
- [CPU count and affinity](https://docs.python.org/3/library/os.html#os.process_cpu_count)
- [Executor shutdown](https://docs.python.org/3/library/concurrent.futures.html)
- [Linux cgroup v2 CPU](https://docs.kernel.org/admin-guide/cgroup-v2.html#cpu)
