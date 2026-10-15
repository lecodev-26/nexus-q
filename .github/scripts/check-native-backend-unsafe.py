#!/usr/bin/env python3
"""Same rule as check-kernel-unsafe.py, applied to the experimental native backend:
every unsafe site needs a nearby `// SAFETY:` justification."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
UNSAFE_CODE = re.compile(r"\bunsafe\s*(?:\{|fn\b|impl\b|extern\b|trait\b|static\b|union\b)")
errors = []
for d in ("crates/nexusq-native-backend/src", "crates/nexusq-native-backend/tests", "arena/runners/nexusq-native/src"):
    for source in sorted((ROOT / d).rglob("*.rs")):
        lines = source.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if UNSAFE_CODE.search(line) and "// SAFETY:" not in "\n".join(lines[max(0, i - 5): i + 1]):
                errors.append(f"{source.relative_to(ROOT)}:{i + 1}: unsafe code lacks a nearby // SAFETY: justification")
if errors:
    print("Native-backend unsafe-code policy failed:", file=sys.stderr)
    print("\n".join(f"  - {e}" for e in errors), file=sys.stderr)
    sys.exit(1)
print("Native-backend unsafe-code policy passed.")
