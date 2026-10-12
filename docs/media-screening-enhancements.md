# Offline media screening improvements

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


## Configuration and scope

Picture skin screening and weapon screening retain their enabled defaults.
**Skin screening method** now defaults to semantic segmentation. The original
YCbCr colour heuristic remains selectable. The editable skin-area threshold
remains 30%; it applies to the selected method's estimate, not a probability.
The semantic detector records separate body-skin and face-skin percentages.
For API callers that omit `skin_method`, existing picture colour-screening behavior
is preserved. Selected semantic failures produce diagnostics; no silent fallback
or runtime model download occurs.

**Also screen video frames for skin areas (optional)** is unchecked by default.
It is independent of the picture checkbox. Selecting it enables the editable
sampling interval (default 5 seconds, range 1–60 seconds). It enables skin
screening when selected, independently of the picture settings. Separate unchecked
**Also search video frames for OCR matches** and **Also screen video frames for
possible weapons** options enable OCR and weapon inference. All three share the
frame sampling interval and 120-frame limit. OCR uses the selected languages and
existing OCR/content keyword matching; weapons use the existing detector and
threshold. Each derived row records its video timestamp and source provenance.
Image similarity is not enabled for videos.
Video candidates appear in **Video Skin Review**; picture candidates retain
**Skin-colour Review** for compatibility. Categories remain collapsed by default.
Both retain the existing matching requirements in matches-only collection.

## Weapon image tiling

The existing checksum-pinned weapon detector processes the complete picture and
up to nine overlapping crops for pictures larger than 640 pixels. Each crop spans
at least half the image on each axis (minimum 640 pixels, bounded by the image),
so coverage has no gaps and inference count is at most ten. This improves effective
resolution for small objects without unbounded inference on very large images.
Very small weapons can still be missed.

All crop boxes are mapped back to the original EXIF-oriented analysis image.
Class-aware cross-region nonmaximum suppression uses IoU 0.45 and retains at most
300 detections. Rows include each retained detection's inference region and the
complete crop list, model identifier, checksum, score and threshold. Whole-image
analysis is retained so large objects crossing crop boundaries can still be found.
Model scores remain uncalibrated review indicators.

## Semantic skin segmentation

The bundled ONNX conversion of Google's MediaPipe Selfie Multiclass 256 model
is 16,454,560 bytes, pinned by SHA-256 and source revision in
[`skin-segmentation.json`](../assets/models/skin-segmentation.json). Its Apache-2.0
license and notice accompany it. It uses the existing offline CPU ONNX Runtime
with telemetry disabled, one thread and no profiling or inference cache.
No TensorFlow or MediaPipe runtime is required.

Input is RGB stretched to 256×256 and normalized to [0,1]. Logits are converted
with softmax; body-skin and face-skin pixels count only when they are the winning
class with score at least 0.5. Transparent pixels with alpha below 128 are excluded.
Percentages describe eligible model-resolution pixels, not exact original-image
area. Results include the model provenance, preprocessing and separate areas.

The model was developed for people/selfie segmentation. Lighting, occlusion,
small people and unfamiliar image domains affect results. It does not establish
nudity, age, identity or illegality. Publisher conversion parity is documented
but has not been independently established here. A successful portrait/background
test demonstrates integration, not population-wide forensic accuracy.

## Video decoding, timestamps and evidence preservation

PyAV 16.1.0 decodes supported MP4/MOV/M4V, MKV/WebM, AVI, MPEG/TS, WMV/ASF,
3GP/3G2, OGV, FLV and MTS/M2TS/M2T containers in the disposable analysis worker. Decoder support and
file validity determine whether an individual file can be read. Playlists and
external resources are blocked through a demuxer whitelist, protocol restriction
and an external-open callback. FLV uses an explicitly forced FLV demuxer without
the options dictionary to avoid a native PyAV/FFmpeg probing crash observed in tests;
the external-open callback still denies secondary resources. There is no network access or temporary video
extraction.

For known durations, samples use seeks and decoded presentation timestamps.
At most 120 frames are sampled across the duration; the interval increases when
necessary and a diagnostic explains this. Transport streams use bounded sequential
sampling because their seek indexes are not relied on. Unknown-duration inputs also use sequential
decoding bounded to 3,600 decoded frames and 120 samples. Only the first video
stream is screened. Decode dimensions are limited to 20 million pixels and each
seek to 300 decoded frames. Existing worker CPU, wall-time, address-space and
derived-output bounds still apply. Short events between samples may be missed;
sampling is not full-frame coverage. Container rotation is not applied; rows
explicitly identify decoded-pixel orientation.

Rows preserve stream index, actual presentation timestamp, requested sample time,
frame PTS/time base, dimensions and skin results. Sampling summary rows identify
duration, effective interval and coverage. Results use the existing structured
details and JSONL/CSV export; original videos remain unchanged.

Linux video inputs use an inherited read-only regular-file descriptor, checked
against acquired size, timestamps, inode and device. They are not constrained by
the 64 MiB picture/document byte-input limit or copied wholesale into RAM. Before
accepting results, the parent streams the entire source through SHA-256, checks
metadata again and verifies the pathname still identifies the same evidence.
Changes discard the derived results. Cancellation terminates the worker through
the existing process-group cleanup and checkpoints retry interrupted files.

## Checks and references

Tests cover default opt-in behavior, crop coverage, duplicate merging and coordinate
offsets, a small public-domain gun found by tiling below the whole-image threshold,
semantic class/alpha/confidence logic, model integrity, a public-domain portrait,
plain brown backgrounds, video timestamps/categories, unchanged source bytes,
exported originals and derived rows, a video larger than 64 MiB, changed sources,
cancellation and rejected external playlists.

Changed files:

- Analysis: `analyzers/weapons.py`, `analyzers/image_classification/analyzer.py`,
  `analyzers/image_classification/semantic.py`, `analyzers/video.py`,
  `analyzers/content.py`, `analyzers/content_worker.py`.
- Configuration and scan integration: `controllers/configuration_controller.py`,
  `controllers/scan_controller.py`.
- GUI: `interface/widgets/content_options.py`, `interface/widgets/media_preview.py`,
  `interface/widgets/finding_priority.py`, `interface/pages/analysis.py`.
- Assets/dependencies: `assets/models/skin-segmentation.onnx`, its JSON manifest,
  license and notice; `requirements-forensics.txt`.
- Checks: `tests/test_media_enhancements.py`, public-domain skin reference fixture
  and attribution in `tests/fixtures/`.
- Documentation: this file, `docs/image-review.md`, `docs/document-image-analysis.md`.

- [Google segmentation models and preprocessing](https://developers.google.com/edge/mediapipe/solutions/vision/image_segmenter)
- [Original model card and Apache-2.0 licensing](https://storage.googleapis.com/mediapipe-assets/Model%20Card%20Multiclass%20Segmentation.pdf)
- [Pinned ONNX conversion and conversion notes](https://huggingface.co/senty-au/selfie_multiclass_256x256-ONNX/tree/6db8421a7150ac20558f2c24675078eb3a1a04d0)
- [PyAV decoding and seeking](https://pyav.org/docs/stable/api/container.html)
- [FFmpeg protocol restrictions](https://ffmpeg.org/ffmpeg-protocols.html)
