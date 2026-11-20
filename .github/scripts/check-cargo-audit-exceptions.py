#!/usr/bin/env python3
"""Validate that cargo-audit ignores have reviewed, unexpired metadata."""

from __future__ import annotations

import datetime as dt
import pathlib
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]
AUDIT_CONFIG = ROOT / ".cargo" / "audit.toml"
EXCEPTIONS_CONFIG = ROOT / ".cargo" / "audit-exceptions.toml"


def fail(message: str) -> int:
    print(f"cargo-audit exception policy: ERROR: {message}", file=sys.stderr)
    return 1


def main() -> int:
    try:
        audit = tomllib.loads(AUDIT_CONFIG.read_text(encoding="utf-8"))
        exception_data = tomllib.loads(EXCEPTIONS_CONFIG.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return fail(str(error))

    ignored = audit.get("advisories", {}).get("ignore", [])
    exceptions = exception_data.get("exceptions", [])
    if not isinstance(ignored, list) or not all(isinstance(item, str) for item in ignored):
        return fail(".cargo/audit.toml [advisories].ignore must be a list of advisory IDs")
    if not isinstance(exceptions, list):
        return fail(".cargo/audit-exceptions.toml exceptions must be an array of tables")

    metadata: dict[str, dict[str, object]] = {}
    for entry in exceptions:
        if not isinstance(entry, dict):
            return fail("each exception must be a TOML table")
        advisory_id = entry.get("id")
        if not isinstance(advisory_id, str) or not advisory_id.strip():
            return fail("each exception needs a non-empty id")
        if advisory_id in metadata:
            return fail(f"duplicate exception metadata for {advisory_id}")
        for field in ("owner", "rationale", "expires"):
            if not isinstance(entry.get(field), str) or not entry[field].strip():
                return fail(f"{advisory_id} needs a non-empty {field}")
        try:
            expiry = dt.date.fromisoformat(entry["expires"])
        except ValueError:
            return fail(f"{advisory_id} has invalid expires date; use YYYY-MM-DD")
        if expiry <= dt.datetime.now(dt.timezone.utc).date():
            return fail(f"{advisory_id} exception expired on {expiry.isoformat()}")
        metadata[advisory_id] = entry

    if len(ignored) != len(set(ignored)):
        return fail("duplicate advisory IDs in .cargo/audit.toml [advisories].ignore")
    if set(ignored) != set(metadata):
        missing = sorted(set(ignored) - set(metadata))
        unused = sorted(set(metadata) - set(ignored))
        return fail(f"ignore/metadata mismatch; missing metadata={missing}, unused metadata={unused}")

    print(f"cargo-audit exception policy: valid ({len(ignored)} active exception(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
