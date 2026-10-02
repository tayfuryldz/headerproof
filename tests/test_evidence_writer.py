from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from headerproof.output import EvidenceWriter


def _records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_evidence_writer_routes_streams_and_advances_checkpoint(tmp_path: Path) -> None:
    metadata = {"schema_version": "1.2", "run_id": "run-evidence"}
    writer = EvidenceWriter(tmp_path, metadata)
    first = {
        "url": "https://a.test/one",
        "status": "scanned",
        "filtered_signals": 2,
        "duplicate_signals": 1,
        "signals": [
            {
                "type": "header_reflection_candidate",
                "severity": "medium",
                "title": "reflected",
                "assessment": {"state": "observed"},
            }
        ],
        "observations": [{"record_type": "observation", "type": "note"}],
        "probes": [{"probe_id": "baseline", "status": "completed"}],
        "coverage": [{"sequence": 1, "state": "completed"}],
        "errors": ["baseline parser warning"],
    }
    second = {
        "url": "https://b.test/two",
        "status": "partial_timeout",
        "filtered_signals": 1,
        "duplicate_signals": 3,
        "signals": [],
        "observations": [],
        "probes": [{"probe_id": "probe-2", "status": "skipped"}],
        "coverage": [],
        "errors": [{"error_type": "url_timeout", "message": "budget exhausted"}],
    }

    writer.append_result(first)
    first_checkpoint = json.loads((tmp_path / "checkpoint.json").read_text(encoding="utf-8"))
    writer.append_result(second)
    second_checkpoint = json.loads((tmp_path / "checkpoint.json").read_text(encoding="utf-8"))
    summary = writer.finalize()

    assert _records(tmp_path / "results.jsonl") == [first, second]
    assert _records(tmp_path / "signals.jsonl") == [{"url": first["url"], **first["signals"][0]}]
    assert _records(tmp_path / "observations.jsonl") == first["observations"]
    assert _records(tmp_path / "probes.jsonl") == [
        {"url": first["url"], **first["probes"][0]},
        {"url": second["url"], **second["probes"][0]},
    ]
    assert _records(tmp_path / "coverage.jsonl") == [
        {"record_type": "coverage", "url": first["url"], **first["coverage"][0]}
    ]
    assert _records(tmp_path / "errors.jsonl") == [
        {"record_type": "error", "url": first["url"], "message": "baseline parser warning"},
        {
            "record_type": "error",
            "url": second["url"],
            "error_type": "url_timeout",
            "message": "budget exhausted",
        },
    ]
    assert first_checkpoint["completed_urls"] == 1
    assert first_checkpoint["last_completed_url"] == "https://a.test/one"
    assert second_checkpoint["completed_urls"] == 2
    assert second_checkpoint["last_completed_url"] == "https://b.test/two"
    assert second_checkpoint["run_id"] == "run-evidence"
    assert isinstance(second_checkpoint["updated_at"], str)
    assert summary == {
        "urls": 2,
        "scanned": 1,
        "partial_error": 0,
        "partial_timeout": 1,
        "error": 0,
        "verified_technical_signals": 1,
        "filtered_signals": 3,
        "duplicate_signals": 4,
        "observations": 1,
        "probes": 2,
        "coverage_records": 1,
        "error_events": 2,
        "by_severity": {"medium": 1},
        "by_evidence_state": {"observed": 1},
        "by_type": {"header_reflection_candidate": 1},
        "out_dir": str(tmp_path),
    }

    stored = json.loads((tmp_path / "metadata.json").read_text(encoding="utf-8"))
    assert stored["url_count"] == 2
    assert stored["summary"] == summary
    assert isinstance(stored["completed_at"], str)
    assert (tmp_path / "summary.md").is_file()
