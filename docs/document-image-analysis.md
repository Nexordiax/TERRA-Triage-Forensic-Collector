# Local document text, OCR and skin-colour screening

Implemented for the Linux build, 2026-10-10. In **Triage Configuration**, picture OCR
and semantic skin and experimental weapon screening are selected by default.
The colour heuristic remains selectable. Video skin screening is opt-in; see
[media screening enhancements](media-screening-enhancements.md).
Document text extraction and PDF OCR are initially unchecked. Separate OCR lists produce **OCR Matches**.
**Also search images inside documents (PDF and Office; optional)** is unchecked by
default. Enable it for embedded-picture OCR, skin screening, image similarity and
PDF picture inventory. PDF page OCR additionally requires its PDF OCR checkbox.
With document-image searching disabled, TERRA skips automatic document-image
decoding; standalone and ordinarily archived pictures still use their selected
searches. Raw hash/keyword searches and selected stored-text extraction continue.
Weapon screening stays excluded from document images even when this option is on.

Files updated for document-image opt-in: `interface/widgets/content_options.py`,
`interface/pages/configuration.py`, `controllers/scan_controller.py`,
`analyzers/content.py`, `analyzers/content_worker.py` and `analyzers/containers.py`.
Regression coverage is in `tests/test_document_image_options.py` and the updated
archive, container, content-analysis, image-review and image-similarity tests. This document and
`docs/archive-preview-recovery.md` describe the revised defaults.
No evidence is uploaded. See [image review controls](image-review.md) for defaults,
language selection, thresholds, review ordering and experimental weapon screening.

## Supported analysis

| Source | Derived findings | Limits |
| --- | --- | --- |
| PDF | PDFium text layer per page; Tesseract OCR for pages without readable text | The optional **OCR every PDF page** also analyzes mixed/text-layer pages. PDF scripts, actions, attachments and forms are not executed. Password-protected PDFs need separate supported decryption. |
| DOCX | Stored document, header/footer, footnote/endnote and comment XML text | No Office application, macro execution, external relationships or layout reconstruction. Embedded picture OCR/screening requires document-image opt-in. |
| XLSX | Shared strings and stored worksheet XML text/value fields | Formula code is never evaluated; values may be cached or stale. Shared strings can include unused strings; cell-to-string/layout reconstruction is not claimed. |
| PPTX | Stored slide and speaker-note XML text | Embedded picture OCR/screening requires document-image opt-in. No slideshow execution or layout reconstruction. |
| ODT/ODS/ODP | `content.xml` text, inline text order and supported whitespace | Embedded picture analysis requires document-image opt-in; external references and arbitrary embedded executable objects are not opened. |
| RTF | Supported text/Unicode controls, CP1252 escapes, paragraphs and tabs | Ignorable destinations/objects are excluded; binary payload controls and unsupported legacy code pages fail explicitly. |
| DOC/XLS/PPT | Word CLX text pieces, Excel BIFF stored cell values and PowerPoint text atoms | Bounded offline legacy readers; no Office application, macro/formula execution or document-image decoding. See [extended formats](extended-media-office-formats.md). |
| Pictures | OCR text, word boxes, engine confidence scores and frame locators; optional skin-like colour percentages | JPEG/PNG/GIF/BMP/TIFF/WebP, AVIF, HEIF/HEIC and supported camera RAW variants. RAW uses a derived half-resolution rendering; originals are retained. OCR accuracy varies with language, orientation, image quality and layout. |

Audio content analysis remains outside this implementation; raw collection and matching continue.
Supported malformed/encrypted inputs, missing dependencies/languages and resource
limits retain raw evidence and record diagnostics. An empty OCR transcription does
not prove that an image contains no text.

## Matching, review and export

File hash matching still hashes the original complete file stream. Raw UTF-8
content matching is preserved. When content-keyword matching is enabled, extracted
document/OCR text is also compared using the existing matcher. Matching rows include
`matched_keywords`; file metadata includes `content_match_sources` with member,
page or frame provenance. Derived text preserves line breaks: phrases spanning
different lines/paragraphs are not automatically joined into one space-separated
phrase. Filename and folder matching are unchanged.

Separate **OCR match lists** import UTF-8 `.txt` entries and enable OCR independently
of content-keyword searching. Only OCR transcript rows are searched by these lists;
matches appear under **OCR Matches** and qualify for matches-only collection.
See [OCR lists and encrypted-container triage](triage-key-encryption-ocr.md) for
setup and category behavior.

Semantic skin segmentation is the GUI default and reports separate body/face
skin areas. See the enhancement document for its model, provenance and limits.
The selectable skin-colour method uses the original explicit YCbCr-range heuristic.
It converts a decoded frame to an RGBA thumbnail of at most 512 x 512, considers
pixels with alpha >=128, and counts sampled pixels with Y 20–245, Cb 77–127 and
Cr 133–173. The exported model ID is `ycbcr_chroma_v1`. ICC profiles are not
normalized. The ratio measures eligible thumbnail pixels, not exact full-resolution
skin area. Resampling, illumination, skin appearance and similarly coloured objects
can cause false positives/negatives. No accuracy claim across populations or
photographic conditions is made. This does not infer race, identity, age, nudity,
sexual activity or illegality.

The review threshold is adjustable from 1–100%, initially 30%. A frame at or above
the threshold adds the original file to **Skin-colour Review**. Each analyzed frame
retains its percentage, threshold, sample dimensions, pixel counts and model ranges.
Below-threshold measurements remain available in full collection. **Matches-only**
still requires a hash, keyword or OCR-list match; skin screening cannot admit an unrelated
file. This preserves that mode's existing scope.

Picture previews show the highest sampled percentage and **View OCR / colour
analysis…**, which opens the existing structured findings viewer. Pictures fit the preview window automatically. Document findings use the existing file-details viewer.
OCR word boxes refer to the analysis image's pixels. Rows retain analysis dimensions,
EXIF-orientation transformation or PDF render scale/page dimensions, and DPI hints.
ZIP exports include derived JSONL/CSV with the existing source input SHA256 and
unaltered original evidence. No OCR images, masks or text sidecars are silently
written beside examined files.

## RAM and cancellation

Analysis receives acquired bytes in a disposable local Python process, without an
examined pathname. Video workers instead receive a read-only descriptor and
results are accepted only after full source/hash reverification. Uncached picture
and document files are reread read-only and fully reverified before
analysis. XML archive members are read in RAM without extracting files. DTD/entity
declarations, duplicate selected members and excessive expansion are rejected.
Tesseract receives a re-encoded PNG through stdin and returns TSV through stdout;
the adapter does not create image/text temporary files or execute examined files.

Derived-analysis bounds are independent of raw acquisition/hashing:

- 64 MiB byte input per picture/PDF (video skin screening and large archive traversal use verified read-only descriptors instead); 32 MiB expanded selected Office XML; 10,000 archive members.
- 2,000,000 text characters; 200 PDF pages; 20 image frames; 20 million decoded
  pixels per image frame. PDF rendering targets 200 DPI, at most eight million
  pixels and a 6,000-pixel longest side.
- 50,000 OCR words per page; 8 MiB TSV; 16 MiB serialized worker result; a 64 MiB
  aggregate serialized derived-result budget per scan, plus small matching/provenance
  overhead. This is not a bound on all application metadata memory.
- On Linux, analysis processes inherit a maximum 1.5 GiB address-space limit,
  90-second CPU limit and disabled core dumps. Existing tighter limits are preserved.
  Parent wall timeout is 120 seconds per file; Tesseract has 40 seconds per page.

Cancellation is checked every 150 ms while waiting and kills the analysis process
group, including an active OCR child. No spill to disk is used to bypass a bound.
Timeouts/limits are visible in diagnostics and analysis status; partial successful
rows are retained when the worker can return them. A killed/crashed worker cannot
return its unfinished rows. Raw collection, complete hashes and reference matching
continue when derived analysis is unavailable or its budget is exhausted.

## Setup and validation

Run `.venv/bin/python main.py`. Python dependencies are in
`requirements-forensics.txt` (`Pillow>=12.2,<13`, `pypdfium2==5.14.0`). Prepare
Tesseract and language packs on the acquisition tool before using OCR. The language
field accepts installed codes such as `eng` or `eng+deu`; it never downloads data.

This development installation downloaded Kali packages into `/tmp/terra-ocr-setup`
and extracted them under `.venv/ocr`, without installing system packages:
Tesseract/libtesseract 5.5.0, Leptonica 1.86.0, English and orientation language
data 4.1.0. The adapter checks this project-local installation and known installed
tool locations, never an executable found through the examined filesystem/PATH.
These extracted Linux libraries are platform-specific, not a portable bundled
release. On another Linux installation, use its compatible Tesseract and language
packages and install the Python requirements in TERRA's environment.

`tests/test_content_analysis.py` includes independent synthetic Office/PDF/image
fixtures, native Tesseract/PDFium keyword matching, original MD5/SHA256 checks,
ZIP provenance, colour percentages/transparency/thresholds, disabled options,
matches-only behavior, uncached source changes, missing OCR, unsafe XML/archive
inputs, cancellation, timeout, result budgets and GUI navigation/viewing. Native
OCR tests explicitly skip when their tool/font/PDFium dependency is unavailable.
These checks do not establish recognition accuracy on real investigative material.

Changed files:

- `analyzers/content.py`, `content_worker.py`, `documents.py`,
  `ocr/analyzer.py`, `image_classification/analyzer.py`.
- `controllers/scan_controller.py`, `configuration_controller.py`.
- `interface/pages/configuration.py`, `interface/widgets/content_options.py`,
  `media_preview.py`.
- `requirements-forensics.txt`, `README.md`, this document and
  `tests/test_content_analysis.py`.

Primary references:

- [PDFium Python API](https://pypdfium2-team.github.io/pypdfium2/python_api.html)
- [Tesseract command-line/TSV documentation](https://tesseract-ocr.github.io/tessdoc/Command-Line-Usage.html)
- [Tesseract stdin memory decoding](https://tesseract-ocr.github.io/tessapi/5.x/a00056_source.html)
- [Pillow image API](https://pillow.readthedocs.io/en/stable/reference/Image.html)
- [Colour-model skin-screening research and limitations](https://arxiv.org/abs/1708.02694)

For current archive traversal, discovered passwords, contained-picture preview and recovery behavior, see [archive-preview-recovery.md](archive-preview-recovery.md).
