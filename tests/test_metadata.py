from __future__ import annotations

import argparse
import json
import subprocess

from headerproof.metadata import build_metadata, current_git_commit, safe_cli_args


def test_safe_cli_args_redacts_header_value() -> None:
    result = safe_cli_args(["scan", "--header", "Authorization=SECRET_TOKEN", "--verbose"])

    assert result == [
        "scan",
        "--header",
        "<redacted>",
        "--verbose",
    ]


def test_safe_cli_args_redacts_equals_header_value() -> None:
    result = safe_cli_args(["scan", "--header=Authorization=SECRET_TOKEN", "--verbose"])

    assert result == [
        "scan",
        "--header=<redacted>",
        "--verbose",
    ]


def test_safe_cli_args_redacts_multiple_headers() -> None:
    result = safe_cli_args(
        [
            "scan",
            "--header",
            "Authorization=SECRET_ONE",
            "--verbose",
            "--header=Cookie=SECRET_TWO",
            "--timeout",
            "5",
        ]
    )

    assert result == [
        "scan",
        "--header",
        "<redacted>",
        "--verbose",
        "--header=<redacted>",
        "--timeout",
        "5",
    ]


def test_build_metadata_does_not_leak_header_values() -> None:
    secret_one = "SYNTHETIC_SECRET_ONE"
    secret_two = "SYNTHETIC_SECRET_TWO"

    args = argparse.Namespace(
        argv=[
            "scan",
            "--header",
            f"Authorization={secret_one}",
            f"--header=Cookie={secret_two}",
        ],
        enabled_checks=set(),
        concurrency=1,
        per_url_concurrency=1,
        rate_limit=0,
        timeout=2.5,
        url_timeout=9.0,
        max_body=16384,
        header_probe_limit=5,
        origin=[],
        header=[
            f"Authorization={secret_one}",
            f"Cookie={secret_two}",
        ],
        request_headers={},
        config_path="",
        no_preflight=False,
        no_cache_confirm=False,
        follow_redirects=True,
        save_body_samples=False,
        fp_mode="strict",
        severity_filter=set(),
        no_live_alerts=False,
    )

    metadata = build_metadata(args, "urls.txt", 1)
    serialized = json.dumps(metadata)

    assert metadata["config"]["custom_probe_headers_count"] == 2
    assert secret_one not in serialized
    assert secret_two not in serialized


def test_current_git_commit_returns_empty_on_failure(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise OSError("git is unavailable")

    monkeypatch.setattr("headerproof.metadata.subprocess.run", fake_run)

    assert current_git_commit() == ""


def test_current_git_commit_returns_empty_on_timeout(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="git", timeout=2)

    monkeypatch.setattr("headerproof.metadata.subprocess.run", fake_run)

    assert current_git_commit() == ""
