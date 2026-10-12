import re
from pathlib import Path


class ConfigurationError(ValueError):
    pass


class ConfigurationController:
    """Read reference lists into RAM without writing to the examined device."""

    @staticmethod
    def parse_hash(value):
        # Bare digests, GNU *sum output, and BSD/OpenSSL labeled output.
        gnu = re.fullmatch(r'([0-9a-fA-F]+)(?:\s+.+)?', value)
        labeled = re.fullmatch(r'(MD5|SHA-?1|SHA-?256|SHA-?512)\s*(?:\(.+\)\s*=|:)\s*([0-9a-fA-F]+)', value, re.IGNORECASE)
        if labeled:
            algorithm = labeled.group(1).upper().replace('-', '')
            digest = labeled.group(2)
            if len(digest) != {'MD5': 32, 'SHA1': 40, 'SHA256': 64, 'SHA512': 128}[algorithm]:
                return None
        elif gnu:
            digest = gnu.group(1)
        else:
            return None
        return digest.lower() if len(digest) in (32, 40, 64, 128) else None

    @staticmethod
    def read_list(filename, hashes=False):
        path = Path(filename)
        if path.suffix.lower() != '.txt':
            raise ConfigurationError(f'Select a .txt list: {path}')
        try:
            lines = path.read_text(encoding='utf-8-sig').splitlines()
        except (OSError, UnicodeError) as error:
            raise ConfigurationError(f'Cannot read list {path}: {error}') from error
        values = []
        for number, line in enumerate(lines, 1):
            value = line.strip()
            if not value or value.startswith('#'):
                continue
            if hashes:
                parsed = ConfigurationController.parse_hash(value)
                if parsed is None:
                    raise ConfigurationError(f'Invalid hash in {path}, line {number}. Use a bare MD5/SHA-1/SHA-256/SHA-512 hash or standard hash-tool output.')
                value = parsed
            values.append(value)
        if not values:
            raise ConfigurationError(f'List contains no usable entries: {path}')
        return list(dict.fromkeys(values))

    def prepare(self, hash_files, keyword_files, options, collection_mode,
                decrypt_protected=True, decryption_secrets=None, analysis_options=None, ocr_files=None,
                image_files=None):
        analysis = dict(analysis_options or {})
        threshold = analysis.get('image_similarity_threshold', 70)
        if isinstance(threshold, bool) or not isinstance(threshold, int) or not 1 <= threshold <= 100:
            raise ConfigurationError('Image similarity threshold must be between 1 and 100 percent.')
        if analysis or image_files:
            analysis['image_similarity_threshold'] = threshold
        image_files = list(dict.fromkeys(image_files or []))
        if image_files:
            from analyzers.image_similarity import MAX_REFERENCES
            if len(image_files) > MAX_REFERENCES:
                raise ConfigurationError(f'Import at most {MAX_REFERENCES} reference pictures per scan.')
            analysis['image_references'] = [self.read_picture(path) for path in image_files]
            # The isolated worker receives compact descriptors, never reference files.
            import json
            if len(json.dumps(analysis).encode()) > 60000:
                raise ConfigurationError('Reference-picture descriptors exceed the worker configuration limit; import fewer pictures.')
        ocr_files = list(ocr_files or [])
        if ocr_files:
            analysis['ocr'] = True
        if analysis:
            if analysis.get('skin_method', 'colour') not in ('semantic', 'colour'):
                raise ConfigurationError('Select a supported skin screening method.')
            interval = analysis.get('video_skin_interval', 5)
            if isinstance(interval, bool) or not isinstance(interval, int) or not 1 <= interval <= 60:
                raise ConfigurationError('Video frame sampling interval must be between 1 and 60 seconds.')
            if not analysis.get('ocr') and not analysis.get('ocr_videos'):
                analysis['ocr_languages'] = 'eng'
            if not re.fullmatch(r'[A-Za-z0-9_]+(?:\+[A-Za-z0-9_]+)*', analysis.get('ocr_languages', 'eng')):
                raise ConfigurationError('OCR languages must be installed language codes, for example eng or eng+deu.')
            threshold = analysis.get('skin_threshold', 30)
            if isinstance(threshold, bool) or not isinstance(threshold, int) or not 1 <= threshold <= 100:
                raise ConfigurationError('Skin-colour threshold must be between 1 and 100 percent.')
        secrets = dict(decryption_secrets or {}) if decrypt_protected else {}
        for name, length in (('signal_key', 64), ('telegram_key', 512)):
            if secrets.get(name) and not re.fullmatch('[0-9a-fA-F]{' + str(length) + '}', secrets[name]):
                raise ConfigurationError(f'{name.replace("_", " ").capitalize()} must contain exactly {length} hexadecimal characters.')
        keyword_search = any(options[name] for name in ('folder_names', 'file_names', 'file_contents'))
        if options['hash_matches'] and not hash_files:
            raise ConfigurationError('Hash list missing. Import at least one hash .txt file or disable hash matching.')
        if keyword_search and not keyword_files:
            raise ConfigurationError('Keyword list missing. Import at least one keyword .txt file or disable the keyword searches.')
        if collection_mode == 'matches_only' and not any(options.values()) and not ocr_files and not image_files:
            raise ConfigurationError('Enable at least one matching option to gather only matches.')
        hashes = []
        keywords = []
        ocr_keywords = []
        # Re-read every imported file at Start so removed or changed lists are detected.
        for filename in hash_files:
            hashes.extend(self.read_list(filename, hashes=True))
        for filename in keyword_files:
            keywords.extend(self.read_list(filename))
        for filename in ocr_files:
            ocr_keywords.extend(self.read_list(filename))
        return {
            'hash_files': list(hash_files), 'keyword_files': list(keyword_files),
            'hashes': list(dict.fromkeys(hashes)),
            'keywords': list(dict.fromkeys(keywords)),
            'ocr_files': ocr_files, 'ocr_keywords': list(dict.fromkeys(ocr_keywords)),
            'image_files': image_files,
            'options': dict(options), 'collection_mode': collection_mode,
            'decrypt_protected': bool(decrypt_protected), '_decryption_secrets': secrets,
            'analysis_options': analysis,
        }

    @staticmethod
    def read_picture(filename):
        try:
            from analyzers.image_similarity import read_reference
            return read_reference(filename)
        except (OSError, ValueError, ImportError) as error:
            raise ConfigurationError(f'Cannot import reference picture {filename}: {error}') from error
