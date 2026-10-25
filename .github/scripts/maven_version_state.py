#!/usr/bin/env python3
"""Validate a Maven Central search response and report present/absent."""

import json
import sys


def state(payload: str) -> str:
    try:
        data = json.loads(payload)
        response = data["response"]
        count = response["numFound"]
        docs = response["docs"]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("response.numFound must be a non-negative integer")
        if not isinstance(docs, list):
            raise ValueError("response.docs must be a list")
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid Maven Central search response: {exc}") from exc
    return "present" if count > 0 else "absent"


def main() -> int:
    try:
        print(state(sys.stdin.read()))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
