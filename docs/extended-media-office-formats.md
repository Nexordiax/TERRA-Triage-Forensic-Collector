# Extended picture, video and legacy Office formats

Implemented for Linux, 2026-10-10. Original acquired bytes and integrity hashes are
unchanged. These readers operate locally on acquired bytes or verified read-only
streams; they do not execute evidence, run Office, extract evidence into temporary
files or fetch external resources. Native media decoding stays in disposable workers
during collection and previews. Imported reference pictures use the same format
reader and bounded reference-input checks.

## Pictures

Picture discovery now includes AVIF/AVIFS, HEIC/HEIF/HIF and HEICS/HEIFS sequences,
plus DNG, CR2/CR3, NEF/NRW, ARW/SR2/SRF, ORF, RW2, RAF, PEF, SRW and RAW extensions.
AVIF uses Pillow's native decoder. HEIF uses pinned pillow-heif/libheif. Camera RAW
uses pinned rawpy/LibRaw; compatibility depends on the particular camera/RAW variant.
Extensions alone do not establish that a file is valid or decodable.

RAW rendering uses half-size, 8-bit RGB with camera white balance requested. Sensor
dimensions are bounded to 80 megapixels and rendered dimensions to 20 megapixels.
The derived image is used for selected OCR, skin, weapon and similarity searches and
for preview. RAW rows identify this rendering in their image-transform metadata.
Full-resolution original RAW files are acquired/exported unchanged. This is not a
claim that every sensor pixel or every possible rendering was searched.

HEIF/AVIF sequence searches keep the existing 20-frame limit. All pictures retain
the existing 64 MiB analysis input and 20 megapixel decoded-image bounds; contained
picture decoding retains the 32 MiB member bound. Decoding failures and exceeded
limits are diagnostic findings, not successful image analysis.

Reference-picture import filters include the new extensions. Extended picture
previews use the isolated decoder and existing fitted PictureView, with access to
analysis details. Unsupported/corrupt inputs show an error and retain the original.

Document images still require the unchecked-by-default document-image option.
Ordinary archive pictures continue to use selected image searches. Weapon screening
remains excluded from PDF/Office document images.

## Videos

Discovery and screening now share the same format list. In addition to existing
formats this includes WMV/ASF, FLV, TS/MTS/M2TS/M2T, 3GP/3G2 and OGV. Existing PyAV
supports the compatible codecs; extension support does not guarantee every codec.
Video skin screening remains unchecked by default. No video OCR, similarity or
weapon inference is added by this work.

FLV uses a forced FLV demuxer to avoid a native options/probing crash encountered
with the pinned PyAV build. Secondary I/O remains denied. Transport streams use
sequential sampling with an explicit coverage limitation: at most 3,600 decoded
frames and 120 samples, so a long stream may be screened only in its initial part.
Other formats retain their existing duration-aware sampling. Original videos,
timestamps, worker limits and export behaviour remain unchanged. In-app playback
continues through Qt Multimedia and depends on its installed/bundled codecs.

## Legacy Office text

Enable the existing **Extract document text** option; it now includes DOC/XLS/PPT.
Decoded text uses existing content-keyword matching, live findings and report/export
paths. These formats are also eligible for text extraction when inside archives.

- DOC: unencrypted Word 97–2007 binary FIB/CLX piece tables, reconstructing logical
  text across fragmented Unicode and CP1252 compressed pieces. Stored stories can
  include body, header/footer and other text. No layout/field evaluation is claimed.
  RTF stored under a `.doc` filename uses the existing RTF reader.
- XLS: xlrd reads BIFF stored values, including hidden sheets and cached formula
  results. Dates are derived through the workbook's date system. Formulas, macros
  and external links are not evaluated.
- PPT: bounded PowerPoint text-atom traversal with exact stream-offset locators.
  Stored historical edits, notes and master text may be included; this is not a
  reconstructed current slide deck. Encrypted headers/records are rejected.

Legacy input/stream bounds are 64 MiB; total extracted text is at most two million
characters. Word pieces/PPT records and nesting are bounded, as are Excel sheets
and at most 500,000 visited cell positions. Unsupported versions, encryption,
malformed structures and missing dependencies produce diagnostics. Originals remain
available under the selected collection mode. Embedded legacy Office pictures and
arbitrary embedded objects are not decoded by these new text readers.

## Files and validation

- Shared image reader: `analyzers/image_formats.py`; connected through
  `analyzers/content.py`, `analyzers/content_worker.py`, `analyzers/image_similarity.py`
  and `analyzers/embedded.py`.
- Legacy readers: `analyzers/legacy_office.py` and `analyzers/documents.py`.
- Video/discovery: `analyzers/video.py` and `artifacts/pictures/collector.py`.
- GUI: `interface/pages/configuration.py`, `interface/main_window.py`,
  `interface/widgets/content_options.py` and `interface/widgets/embedded_preview.py`.
- Dependencies: `requirements-forensics.txt` and test-only
  `requirements-forensics-test.txt` (xlwt generates independent Excel fixtures).
- Regression tests: `tests/test_media_legacy_formats.py` uses real HEIF/AVIF and
  synthetic DNG codecs, independently generated OLE DOC/PPT and native BIFF XLS,
  native FLV/ASF/MPEG-TS, GUI previews, text matches and byte-identical ZIP export.
  Existing format documentation was updated. The pre-existing
  `tests/test_extended_formats.py` was restored after a filename collision.

## Primary references

- [Pillow image formats](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [pillow-heif](https://github.com/bigcat88/pillow_heif)
- [rawpy/LibRaw API](https://letmaik.github.io/rawpy/api/)
- [Microsoft Word text retrieval](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/01d5d8c4-cf9c-4ef9-80fd-439e763cfe01)
- [PowerPoint TextCharsAtom](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/a3c5c8d5-e530-4167-a242-7743bc99aeac)
- [PowerPoint CurrentUserAtom](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/940d5700-e4d7-4fc0-ab48-fed5dbc48bc1)
- [xlrd BIFF reader](https://xlrd.readthedocs.io/en/stable/)
