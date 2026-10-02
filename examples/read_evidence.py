#!/usr/bin/env python3
"""Read HeaderProof evidence JSONL without depending on the app version.

Consumers (dashboards, auditors, CI gates) should select a schema from each
record's ``schema_version`` field instead of importing headerproof itself:
published schemas are immutable, so old files stay readable forever.

Usage:
    python examples/read_evidence.py out/signals.jsonl
    python examples/read_evidence.py out/signals.jsonl --strict
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Minimal per-version field contract. Mirrors schemas/evidence-vX.Y.schema.json
# required-lists; unknown versions are reported, never silently accepted.
REQUIRED_FIELDS = {
    "1.2": ["schema_version", "record_type", "check", "type", "severity",
            "confidence", "title", "evidence"],
}


def read_records(path: Path, strict: bool = False) -> dict:
    summary: dict = {"files": str(path), "total": 0, "by_version": {},
                     "unknown_versions": [], "errors": []}
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            summary["total"] += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                summary["errors"].append("line %d: not JSON (%s)" % (lineno, exc))
                if strict:
                    raise SystemExit("line %d: not JSON" % lineno)
                continue
            version = str(record.get("schema_version", "missing"))
            summary["by_version"][version] = summary["by_version"].get(version, 0) + 1
            required = REQUIRED_FIELDS.get(version)
            if required is None:
                summary["unknown_versions"].append("line %d: %s" % (lineno, version))
                if strict:
                    raise SystemExit("line %d: unsupported schema_version %r" % (lineno, version))
                continue
            missing = [f for f in required if f not in record]
            if missing:
                summary["errors"].append("line %d: missing %s" % (lineno, ", ".join(missing)))
                if strict:
                    raise SystemExit("line %d: missing %s" % (lineno, ", ".join(missing)))
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("jsonl", type=Path, help="evidence JSONL file (e.g. out/signals.jsonl)")
    parser.add_argument("--strict", action="store_true",
                        help="exit non-zero on unknown versions or bad records")
    args = parser.parse_args(argv)
    summary = read_records(args.jsonl, strict=args.strict)
    print(json.dumps(summary, indent=2, sort_keys=True))
    if summary["errors"] or (args.strict and summary["unknown_versions"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
