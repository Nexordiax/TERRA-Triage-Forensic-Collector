# Picture OCR defaults, diagnostics and prioritized image review

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


## Configuration controls

**Document and image analysis** appears first in the scrolling configuration form,
followed by **OCR match lists**. Picture OCR, semantic skin screening and experimental
weapon screening are selected by default. The colour heuristic remains selectable.
Video skin screening is opt-in and initially unchecked; see
[media screening enhancements](media-screening-enhancements.md). Document text extraction, PDF OCR and
OCR-every-PDF-page are off by default. Hash and ordinary keyword options retain their defaults.
Import an OCR `.txt` list to obtain the separate **OCR Matches** category.
Picture previews fit the available window space and rescale when the window is
resized or fullscreen is toggled. Aspect ratio and original evidence bytes are preserved;
each resize uses the original decoded image rather than a previously scaled copy.
OCR can also contribute to ordinary content-keyword matching when enabled, as before.

The picture default explicitly sends `ocr_pdf=false`. Legacy integrations that
omit this field keep their earlier combined picture/PDF OCR behavior. To OCR PDFs,
select **Also run OCR on PDF pages without readable text**; enable the additional
every-page option when readable text layers should also be rendered for OCR.

**OCR languages (combine with +)** accepts installed Tesseract codes such as
`eng+deu+fra`. **Show installed OCR languages…** queries the acquisition tool's
trusted OCR executable. This environment currently has `eng` and `osd`; `osd` is
orientation/script detection data, not a transcription language. Additional
`.traineddata` files must be prepared in the acquisition tool's tessdata directory
before collection; changing the field does not download language files.

**Minimum skin-like area for review** is editable from 1–100%, even before skin
screening is enabled. The default remains 30%. Increasing it requires a greater
fraction of sampled pixels classified as skin by the selected method and therefore usually reduces
review candidates. It does not increase detector sensitivity or prove nudity.

## Worker failures

`Analysis worker failed (1); original evidence retained` means the isolated derived
analysis process exited with an error. It does not mean source acquisition/hash
comparison failed, and the original evidence/source reference stays intact.

During this review, the active `.venv` had `include-system-site-packages=false`
and was missing Pillow, cryptography and pyasn1. Previously, the Pillow import
occurred outside worker error handling, which can produce exactly an exit-code-1
failure. Required dependencies were installed into `.venv`; the user's historical
error cannot be conclusively attributed from the generic message alone.

Missing Pillow now returns a structured dependency diagnostic mentioning
`requirements-forensics.txt`. Worker resource/setup failures are also structured.
Nonzero exits retain their exit code and bounded stderr detail; signal exits name
the signal, such as SIGKILL. A signal identifies termination, not its definitive
cause. Source bytes/hashes remain untouched by all these diagnostic paths.

## Review priority

The live findings tree pins categories in this order:

1. Hash Matches
2. File Content Matches
3. OCR Matches
4. Image Similarity Matches (when reference pictures are imported)
5. Skin-colour Review
6. Weapon Review

Within ordinary artifact categories, files with these findings are inserted ahead
of other files in the same order. Other category and file updates remain visible
throughout collection. Categories start collapsed; subsequent updates preserve a
user's expansion state. Encrypted-container subgroups keep their entropy ordering.

This changes presentation priority, not filesystem traversal or processing speed.
There is no second scan pass, deferred ordinary artifact queue or change to scope,
matching logic, hash notifications or source acquisition. Per-file analysis still
completes before that file's final finding is emitted.

## Experimental local weapon screening

**Screen pictures for possible guns, grenades and knives** enables CPU-only ONNX
inference inside the existing bounded/cancelable analysis worker. It analyzes the
same supported picture formats and first 20 frames used by other image analysis;
weapon inference does not analyze videos, audio, PDF illustrations or concealed weapons.
The separate video checkbox enables skin screening only.

Candidates appear under **Weapon Review** in full collection. Original hashes are
unchanged. In matches-only mode, a weapon/skin heuristic alone does not admit a file:
the existing hash, keyword or OCR-list match requirement remains in place. A matching
picture can have both ordinary matches and weapon review findings.

The **Minimum weapon model score** is adjustable from 1–100%, default 50%. Scores
are uncalibrated model outputs, not probabilities or proof that an object is a real
weapon. False positives, replicas/toys, illustrations and missed detections remain
possible. A negative result does not establish absence. Independent operational
validation against representative positive and negative images is still needed.

The pinned 12,268,102-byte reference model is under `assets/models/`, accompanied
by its [manifest](../assets/models/weapon-reference.json). SHA-256 is checked before
inference; unexpected sizes/checksums fail visibly. Only that application asset is
loaded: no arbitrary evidence model, Python pickle, custom operator library,
runtime model download or upload is used. Model bytes are supplied directly to
ONNX Runtime. Telemetry is disabled via `ORT_DISABLE_TELEMETRY=1` **before** import
and via the runtime API. CPU inference uses one inter/intra-op thread; no GPU or
profiling cache is requested.

The full image and up to nine overlapping crops use 640×640 RGB-letterboxed tensors.
Crop detections are mapped to the original analysis image and merged with
class-aware NMS (IoU 0.45). Each inference admits at
most 3,000 score-qualified candidates and 300 output detections per frame. Gun,
grenade and knife classes are admitted; the model's explosion class is excluded.
Rows preserve frame locator, class/score, xyxy boxes in EXIF-oriented analysis-image
pixels, image dimensions/transforms, threshold, preprocessing and model hash/revision.
Picture preview summarizes candidate labels/scores; complete rows are available
through **View OCR / colour / weapon analysis…** and explicit ZIP export.

The model publisher labels its card Apache-2.0, while the downloaded ONNX metadata
declares AGPL-3.0 and identifies an Ultralytics export. This discrepancy is recorded
in the manifest. Redistribution terms must be resolved before publishing a bundled
release; no claim of release-ready model licensing is made. Training provenance and
forensic accuracy have not been independently established.

## Validation and changes

Tests cover defaults, editable controls, language queries, PDF opt-in behavior,
structured missing-Pillow/setup failures, stderr/signal diagnostics, priority order
and expansion preservation, YOLO coordinate conversion, threshold/class filtering,
NMS, integrity checks, independent-analysis partial results, unchanged source bytes,
matches-only scope, native blank-image inference and a positive public-domain Glock
reference photo. The reference and attribution are in `tests/fixtures/`. Its positive
result verifies integration, not broad accuracy. Native weapon rows and original JPG
bytes are checked in the ZIP export.
The test harness flushes queued Qt widget deletions before interpreter shutdown;
otherwise the expanded GUI suite can abort while Qt destroys pending fixtures.

Changed files for this update:

- `interface/widgets/content_options.py`, `interface/pages/configuration.py`
- `interface/widgets/finding_priority.py`, `interface/pages/analysis.py`, `interface/widgets/media_preview.py`
- `controllers/configuration_controller.py`, `controllers/scan_controller.py`
- `analyzers/content.py`, `analyzers/content_worker.py`, `analyzers/ocr/analyzer.py`, `analyzers/weapons.py`
- `assets/models/weapon-reference.onnx`, `assets/models/weapon-reference.json`
- `requirements-forensics.txt`, `tests/test_content_analysis.py`, `tests/test_image_review.py`
- `tests/fixtures/weapon-reference-public-domain.jpg`, `tests/fixtures/weapon-reference-public-domain.md`
- `docs/document-image-analysis.md`, this document, `README.md`

## Primary references

- [Tesseract language data](https://tesseract-ocr.github.io/tessdoc/Data-Files.html)
- [ONNX Runtime Python API](https://onnxruntime.ai/docs/api/python/api_summary.html)
- [ONNX Runtime telemetry controls](https://github.com/microsoft/onnxruntime/blob/main/docs/Privacy.md)
- [Reference model publisher](https://huggingface.co/ECE-Software/connect-t1-weapon-fp32)
- [Public-domain reference photograph and dedication](https://commons.wikimedia.org/wiki/File:Glock_17.JPG)
