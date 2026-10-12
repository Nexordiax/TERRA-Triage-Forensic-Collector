"""Inclusive physical-address coverage; absent bytes are never inferred as zero."""


def merge_ranges(ranges):
    merged = []
    for start, end in sorted(ranges):
        if start < 0 or end < start:
            raise ValueError('Invalid expected physical RAM range.')
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def estimated_image_size(ranges):
    # AVML 0.20.0 splits output at 16 MiB; include the additional LiME
    # headers in pre-acquisition capacity estimates.
    block_size = 16 * 1024 * 1024
    return sum(end - start + 1 + 32 * max(1, (end - start + block_size) // block_size)
               for start, end in merge_ranges(ranges))


def coverage(expected, captured):
    expected = merge_ranges(expected)
    captured = merge_ranges(captured)
    missing = []
    index = 0
    for start, end in expected:
        cursor = start
        while index < len(captured) and captured[index][1] < start:
            index += 1
        probe = index
        while probe < len(captured) and captured[probe][0] <= end:
            left, right = captured[probe]
            if left > cursor:
                missing.append((cursor, min(end, left - 1)))
            cursor = max(cursor, right + 1)
            probe += 1
        if cursor <= end:
            missing.append((cursor, end))
    return dict(expected_physical_bytes=sum(end - start + 1 for start, end in expected),
                missing_physical_bytes=sum(end - start + 1 for start, end in missing),
                missing_memory_ranges=[dict(start=start, end=end) for start, end in missing],
                expected_memory_ranges=[dict(start=start, end=end) for start, end in expected],
                complete_physical_ram=bool(expected) and not missing)
