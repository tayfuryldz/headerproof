from __future__ import annotations

import argparse
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from .constants import PRODUCT_NAME, SCHEMA_VERSION, VERSION

PROJECT_ROOT = Path(__file__).resolve().parents[2]

def safe_cli_args(argv: list[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    for item in argv:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        if item in {"--header"}:
            redacted.append(item)
            redact_next = True
            continue
        if item.startswith("--header="):
            redacted.append("--header=<redacted>")
            continue
        redacted.append(item)
    return redacted


def current_git_commit() -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(PROJECT_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            check=False,
            text=True,
            timeout=0.5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()


def scan_config(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "checks": sorted(args.enabled_checks),
        "concurrency": args.concurrency,
        "per_url_concurrency": args.per_url_concurrency,
        "rate_limit_per_host": args.rate_limit,
        "request_timeout_seconds": args.timeout,
        "url_budget_seconds": args.url_timeout,
        "max_body_bytes": args.max_body,
        "header_probe_limit": args.header_probe_limit,
        "custom_origins_count": len(getattr(args, "origin", [])),
        "custom_probe_headers_count": len(getattr(args, "header", [])),
        "request_headers_count": len(getattr(args, "request_headers", {})),
        "config_file_loaded": bool(getattr(args, "config_path", "")),
        "preflight_enabled": not args.no_preflight,
        "cache_confirmation_enabled": not args.no_cache_confirm,
        "dynamic_header_discovery_enabled": (
            "cache-poisoning" in args.enabled_checks and not args.no_cache_confirm
        ),
        "follow_redirects": args.follow_redirects,
        "save_body_samples": args.save_body_samples,
        "fp_mode": args.fp_mode,
        "severity_filter": sorted(args.severity_filter),
        "live_alerts": not args.no_live_alerts,
    }


def build_metadata(args: argparse.Namespace, input_path: str | Path, url_count: int) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": uuid.uuid4().hex,
        "tool": PRODUCT_NAME,
        "version": VERSION,
        "git_commit": current_git_commit(),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "input": str(input_path),
        "url_count": url_count,
        "command": [PRODUCT_NAME.lower(), *safe_cli_args(getattr(args, "argv", []))],
        "config": scan_config(args),
    }
