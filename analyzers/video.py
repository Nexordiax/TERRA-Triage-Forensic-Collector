"""Bounded opt-in video skin and OCR screening with verified source access."""
import errno
import hashlib
import math
import os
import stat

from artifacts.parser_support import check_cancelled, verify_unchanged

VIDEOS = {'.mp4', '.m4v', '.mov', '.mkv', '.webm', '.avi', '.mpg', '.mpeg', '.wmv', '.asf',
          '.3gp', '.3g2', '.ogv', '.ts', '.mts', '.m2ts', '.m2t', '.flv'}
MAX_FRAMES = 120
MAX_PIXELS = 20_000_000
SOURCE_KEYS = ('size', 'mtime_ns', 'ctime_ns', 'device', 'inode')


def video_enabled(options):
    return any(options.get(key) for key in ('skin_videos', 'ocr_videos'))


def open_source(path, metadata, directory_fd):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    name = os.path.basename(path) if directory_fd is not None else path
    try:
        fd = os.open(name, flags | getattr(os, 'O_NOATIME', 0), dir_fd=directory_fd)
    except OSError as error:
        if error.errno not in (errno.EPERM, errno.EACCES, errno.EINVAL):
            raise
        fd = os.open(name, flags, dir_fd=directory_fd)
    source = os.fdopen(fd, 'rb')
    try:
        _check_source(source, metadata)
    except Exception:
        source.close()
        raise
    return source


def _check_source(source, metadata):
    info = os.fstat(source.fileno())
    actual = (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_dev, info.st_ino)
    if not stat.S_ISREG(info.st_mode) or actual != tuple(metadata[key] for key in SOURCE_KEYS):
        raise ValueError('Video source changed; derived screening discarded')


def verify_source(source, path, metadata, directory_fd, cancelled):
    _check_source(source, metadata)
    source.seek(0)
    digest = hashlib.sha256()
    while chunk := source.read(1024 * 1024):
        check_cancelled(cancelled)
        digest.update(chunk)
    _check_source(source, metadata)
    verify_unchanged(path, metadata, directory_fd)
    if digest.hexdigest() != metadata['sha256']:
        raise ValueError('Video source differs from acquired hash; derived screening discarded')


def sample_times(duration, interval):
    if not math.isfinite(duration) or duration <= 0:
        raise ValueError('Invalid video duration')
    count = min(MAX_FRAMES, max(1, math.ceil(duration / interval)))
    effective = max(float(interval), duration / MAX_FRAMES)
    return [index * effective for index in range(count)], effective


def _deny_external(*args, **kwargs):
    raise ValueError('External video resources are disabled during forensic screening')


def analyze_video(source, options):
    result = dict(entries=[], limitations=[], status='parsed')
    if not video_enabled(options):
        return result
    try:
        import av
        from analyzers.image_classification.analyzer import screen_selected
        interval = options.get('video_skin_interval', 5)
        if isinstance(interval, bool) or not isinstance(interval, int) or not 1 <= interval <= 60:
            raise ValueError('Video sampling interval must be between 1 and 60 seconds')
        source.seek(0)
        flv = source.read(3) == b'FLV'
        source.seek(0)
        # PyAV 16/FFmpeg FLV probing with an options dictionary can abort in
        # native code. Force the FLV demuxer instead; secondary I/O is denied
        # by the same callback and the source remains our acquired byte stream.
        opening = dict(format='flv') if flv else dict(options={
                'protocol_whitelist': 'pipe',
                'format_whitelist': 'mov,matroska,webm,avi,mpeg,mpegts,asf,ogg,flv',
                'threads': '1'})
        with av.open(source, mode='r', io_open=_deny_external, **opening) as container:
            streams = list(container.streams.video)
            if not streams:
                raise ValueError('No decodable video stream')
            stream = streams[0]
            stream.codec_context.thread_count = 1
            if stream.codec_context.width * stream.codec_context.height > MAX_PIXELS:
                raise ValueError('Video dimensions exceed screening pixel bound')
            if len(streams) > 1:
                result['limitations'].append('Only the first video stream was screened')
            start = float((stream.start_time or 0) * stream.time_base)
            duration = float(stream.duration * stream.time_base) if stream.duration is not None else (
                container.duration / av.time_base if container.duration is not None else None)
            timestamps = []
            def screen_frame(frame, target, index):
                if frame.width * frame.height > MAX_PIXELS:
                    raise ValueError('Decoded video frame exceeds screening pixel bound')
                actual = float(frame.pts * frame.time_base) if frame.pts is not None else None
                timestamp = max(0, actual - start) if actual is not None else target
                with frame.to_image() as image:
                    provenance = dict(media_kind='video', locator=f'video:stream:{stream.index}:sample:{index + 1}:time:{timestamp:.6f}',
                               timestamp_seconds=round(timestamp, 6), timestamp_is_estimated=actual is None,
                               stream_index=stream.index, frame_pts=frame.pts,
                               frame_time_base=str(frame.time_base), requested_timestamp_seconds=round(target, 6),
                               analysis_image_width=image.width, analysis_image_height=image.height,
                               image_transform=dict(type='decoded_video_frame', orientation='decoded pixels; container rotation not applied'))
                    def add_screen(name, operation):
                        try:
                            row = dict(operation())
                            row.update(provenance)
                            result['entries'].append(row)
                        except Exception as error:
                            result['limitations'].append(f'Video {name} at {timestamp:.6f}s: {type(error).__name__}: {error}')
                    if options.get('skin_videos'):
                        add_screen('skin screening', lambda: screen_selected(image, options.get('skin_threshold', 30), options.get('skin_method', 'semantic')))
                    if options.get('ocr_videos'):
                        from analyzers.ocr.analyzer import recognize
                        add_screen('OCR', lambda: recognize(image, options.get('ocr_languages', 'eng')))
                    timestamps.append(timestamp)
            effective = interval
            transport_stream = 'mpegts' in container.format.name.split(',')
            if duration is not None and duration > 0 and math.isfinite(duration) and not transport_stream:
                times, effective = sample_times(duration, interval)
                seen_pts = set()
                for index, target in enumerate(times):
                    container.seek(int((target + start) / stream.time_base), stream=stream, backward=True)
                    for decoded, frame in enumerate(container.decode(stream)):
                        if decoded >= 300:
                            raise ValueError('Video seek decoding bound reached; previous samples retained')
                        actual = float(frame.pts * frame.time_base) - start if frame.pts is not None else None
                        if actual is not None and actual + 1e-6 < target:
                            continue
                        if frame.pts is None or frame.pts not in seen_pts:
                            screen_frame(frame, target, index)
                            seen_pts.add(frame.pts)
                        break
                if effective > interval:
                    result['limitations'].append('Video sample limit reached: interval increased to cover the declared duration with at most 120 samples')
            else:
                reason = 'Transport-stream seek indexes are not relied on' if transport_stream else 'Video duration unavailable'
                result['limitations'].append(reason + ': sequential screening limited to 3600 decoded frames and 120 samples')
                next_time = 0
                rate = float(stream.average_rate or 25)
                for decoded, frame in enumerate(container.decode(stream)):
                    if decoded >= 3600 or len(timestamps) >= MAX_FRAMES:
                        break
                    timestamp = float(frame.pts * frame.time_base) - start if frame.pts is not None else decoded / rate
                    if timestamp >= next_time:
                        screen_frame(frame, timestamp, len(timestamps))
                        next_time = timestamp + interval
            result['entries'].append(dict(type='video_skin_sampling', locator=f'video:stream:{stream.index}',
                sampled_frames=len(timestamps), requested_interval_seconds=interval,
                effective_interval_seconds=effective, declared_duration_seconds=duration,
                first_sample_seconds=timestamps[0] if timestamps else None,
                last_sample_seconds=timestamps[-1] if timestamps else None,
                max_samples=MAX_FRAMES, decoder='PyAV/FFmpeg', decoder_version=av.__version__,
                enabled_searches=[name for name, key in (('skin', 'skin_videos'), ('ocr', 'ocr_videos')) if options.get(key)],
                note='Selected searches run on sampled video frames; events between samples may be missed. Image similarity is not requested.'))
            if not timestamps:
                raise ValueError('No video frames could be sampled')
    except Exception as error:
        result['limitations'].append(f'Video frame analysis: {type(error).__name__}: {error}')
    if result['limitations']:
        result['status'] = 'partial' if result['entries'] else 'failed'
    return result
