# Offline reference-picture matching

In Triage Configuration, use **Reference pictures → Import pictures…** to select
multiple image files. Remove selected entries as with the other reference lists.
Importing references activates matching automatically; no hash or OCR list is
needed for this feature. Hash/keyword searches retain their existing validation
and must be disabled if their lists are absent.

References are decoded and fingerprinted in RAM and re-read when Start is clicked.
Invalid, missing or unsupported images produce configuration errors. No network
service, model download, image execution or temporary evidence files are used.
Only compact descriptors are sent to the existing isolated analysis worker.

The independently implemented `terra-dct256-v1` fingerprint compares a normalized
64×64 grayscale image's low-frequency DCT coefficients. It uses 255 median-threshold
bits, excluding mean brightness. Candidate images are compared at 0°, 90°, 180°
and 270° after EXIF orientation correction. The default minimum score is **70%**. Adjust **Minimum image similarity score**
in the configuration window from 1–100%. The selected threshold travels with the
scan and is recorded in every match. Results at or above that score are kept:
`100 × (1 − Hamming distance / 255)`. This is a similarity score, not a probability
or proof that images are identical. Colour changes can match. It supports
near-duplicate screening; arbitrary crops, perspective changes, substantial edits
and semantic similarity (different photographs of the same subject) are not
reliably covered. Simple images can produce false positives; manual review is needed.
The design draws on [DCT perceptual hashing](https://www.phash.org/docs/design.html).

Live findings appear in the initially collapsed **Image Similarity Matches**
category, including reference paths and scores. Picture previews show the best
reference match; the analysis-details button exposes every match, reference
SHA-256, algorithm/version, distance, score, frame locator and tested rotation.
Matches also admit files in matches-only collection mode. Existing ZIP manifests,
derived-analysis exports and PDF reports retain match metadata through the normal
export path; source-file hashes are unchanged.

Limits: up to 256 reference pictures, 64 MiB and 20 megapixels per reference;
reference descriptors must fit the 60,000-byte worker configuration budget.
Only the first frame of each animated reference is used. Target images use the
existing isolated-analysis limits (64 MiB, 20 megapixels, first 20 frames, timeout
and scan-wide derived-result budget). These limits do not constrain acquisition
or ordinary cryptographic hash matching. Unsupported decoders and analysis failures
are logged; they do not silently count as similarity matches.

## Implementation files

- `analyzers/image_similarity.py`: reference validation, DCT fingerprints and comparisons.
- `analyzers/content.py`, `analyzers/content_worker.py`: isolated picture-analysis integration.
- `controllers/configuration_controller.py`, `controllers/scan_controller.py`: preparation, scan admission and matching results.
- `interface/pages/configuration.py`, `interface/pages/analysis.py`: picture import and live category.
- `interface/widgets/media_preview.py`, `interface/widgets/finding_priority.py`: match summaries and review ordering.
- `tests/test_image_similarity.py`: import, transformation, scan, limits and export coverage.
- `README.md`, `docs/image-review.md`, this document: feature documentation.
