# Unprivileged process-memory context

The existing partial-memory ZIP stores raw regions under
`processes/<pid>/regions/`. `manifest.json` format version 2 adds context;
region paths, bytes, SHA-256 hashes and virtual-address segment mappings remain
unchanged. This is process virtual memory, not a physical RAM or LiME image.

Each collected process records the kernel executable link and backing-file
identity (device, inode, size and timestamps), command-line arguments with the
original bounded bytes in `raw_hex`, and start-time ticks. Approximate start UTC
is derived where `/proc/stat` boot time and the clock-tick frequency are available.
Executable files are neither executed nor read for hashing.

Structured mappings include non-readable mappings, permissions, address ranges,
backing-file offsets, device, inode, pathname and capture status. Each attempted
region has UTC start/end times and monotonic duration. `segments` maps copied
bytes to virtual addresses; `gaps` records failed/empty reads with address,
length, reason and errno. Stopping records explicit `not_attempted_ranges` and
marks remaining mappings as not attempted after stop. Gaps are never zero-filled.

Before/after executable, argv, identity and mapping checks expose observed
changes. Changed mappings retain the later raw map and added/removed entries.
An unavailable change check is unknown, not evidence that nothing changed.
Processes are not paused: timestamps bracket observations, not an atomic
snapshot, and changes that occur between observations can escape detection.

`unavailable_processes` preserves accessible context, failure operation and
errno for denied/exited/inaccessible processes; these records do not count as
collected memory. Optional metadata failures do not discard accessible memory.
Diagnostics remain in `logs/diagnostics.jsonl` and `logs/acquisition.log`.
If no other process memory is accessible, the existing failure behavior applies:
no empty evidence ZIP is saved, and diagnostics are returned to the controller.

Linux ptrace, ownership, dumpability and other security restrictions still apply.
No privileges are elevated. This change does not add a Volatility layer or make
standard physical-memory plugins accept these raw process regions.

Kernel metadata reference: [Linux proc filesystem documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html).
