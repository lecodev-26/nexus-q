#!/usr/bin/env python3
"""Stream fuzz campaign output to stdout while keeping a bounded on-disk log.

Reads stdin line by line and passes every line through to stdout so the
Actions console shows live output. At the same time it maintains the file
at --output on disk, never letting that file exceed --cap-bytes: whenever
new data would push it over the cap, the oldest bytes are dropped so only
the most recent tail (up to the cap) is retained.

While streaming, the bounded log is visible at "<output>.part" and is
atomically renamed to "<output>" when stdin reaches EOF; anything polling
the file during the run should poll the ".part" sibling. The on-disk file
never exceeds the cap at any point, including mid-line. Rotation drops
the oldest bytes down to roughly half the cap, so rotation cost stays
amortized over the stream instead of running per line near the cap.

Usage:
    some-command 2>&1 | fuzz_bounded_log.py --cap-bytes 10485760 --output run.log
"""

import argparse
import os
import sys


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pass stdin to stdout while keeping its tail in a size-capped file."
    )
    parser.add_argument(
        "--cap-bytes",
        type=int,
        required=True,
        help="maximum size of the bounded log file",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="path of the bounded log; a .part sibling is used while streaming",
    )
    args = parser.parse_args()
    if args.cap_bytes <= 0:
        parser.error("--cap-bytes must be positive")

    cap = args.cap_bytes
    partial = args.output + ".part"
    written = 0
    out = open(partial, "wb", buffering=0)
    try:
        for raw in sys.stdin.buffer:
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()
            if len(raw) > cap:
                raw = raw[-cap:]
            if written + len(raw) > cap:
                # Rotate down to roughly half the cap so the next rotation
                # is ~cap//2 bytes away, keeping rotation amortized O(1)
                # instead of running per line near the cap.
                out.close()
                keep = cap - max(len(raw), cap // 2)
                size = os.path.getsize(partial)
                with open(partial, "rb") as fh:
                    fh.seek(max(0, size - keep))
                    tail = fh.read()
                out = open(partial, "wb", buffering=0)
                out.write(tail)
                written = len(tail)
            out.write(raw)
            written += len(raw)
    finally:
        out.close()
    os.replace(partial, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
