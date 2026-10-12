# RAM progress and live-media review fixes

> **Historical development note — October 2026**
>
> TERRA no longer includes weapon recognition. The weapon detection
> controls, inference implementation, and model weights have been removed.
> Any weapon-related descriptions, source paths, configuration options,
> or test results below refer to an earlier development version and
> do not describe the current application.
>
> Current supported media analysis includes OCR, reference-image
> similarity matching, and skin-area screening.


Unprivileged acquisition copies readable virtual mappings from accessible processes.
Its byte counter sums actual bytes copied, including repeated shared/aliased pages;
it does not count unique resident physical pages. Readable mappings need not already
be resident. Consequently the copied total can exceed installed RAM without proving
greater physical coverage. The display, saved manifest, evidence metadata and README
now make this distinction explicit. Acquisition bytes are not artificially capped or
discarded to match physical capacity. Root physical acquisition remains separate.

The live scan previously waited for the first queued media analysis even when later
jobs had finished. A bounded queue (up to eight jobs) could therefore appear stuck
behind one expensive decoder. Ready jobs can now publish ahead of a slow media job
while normal derived-result headroom remains; read-only queues and tight-budget
allocation retain their ordering. Findings retain their source paths and hashes;
their IDs/live arrival order can differ. Progress identifies active analysis work.
Stop, descriptor/RAM cleanup, checkpoint loading and stopped-session resume are tested.
This fixes a reproducible queue bottleneck, not a measurement of the user's drive;
large archives, OCR and enabled video processing can still take substantial time.

Weapon detection is disabled for PDF and Office document images, including images
in nested containers inside those documents. Other document text/OCR, skin review,
similarity, hashes, previews and export remain available. Images stored in ordinary
archives still receive weapon screening, as do standalone image files and enabled
video frames. The model/thresholds are unchanged, so ordinary image false positives
remain possible; removing document illustrations does not recalibrate the model.

Changed files:

- `artifacts/memory/process_collector.py` and `interface/pages/ram.py`: explicit
  virtual-byte accounting metadata and progress label.
- `controllers/scan_scheduler.py`: ready-result publication and active-analysis
  progress; `tests/test_parallel_media.py` and `tests/benchmark_media_scan.py` compare
  per-source evidence independently of live arrival IDs/order.
- `analyzers/content.py`, `analyzers/content_worker.py` and `analyzers/containers.py`:
  document weapon-screen restriction, including nested Office containers.
- `tests/test_container_search.py` and `tests/test_process_memory.py`: scope and
  progress/accounting regressions. `docs/scan-performance-plan.md` reflects the new
  queue behaviour.

Reference: [Linux kernel proc documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html),
which distinguishes virtual mapping size, resident pages, proportional shares and
shared/private memory.
