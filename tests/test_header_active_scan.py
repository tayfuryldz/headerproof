from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import request
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import header_active_scan  # noqa: E402
from headerproof.output import EvidenceWriter, default_output_root, reserve_output_dir  # noqa: E402


def make_snapshot(
    headers: dict[str, str],
    body: str = "",
    status: int = 200,
    request_headers: dict[str, str] | None = None,
    request_url: str = "http://example.test/demo",
    client_context: str = "test-client",
    error: str = "",
) -> header_active_scan.HttpSnapshot:
    return header_active_scan.HttpSnapshot(
        "GET",
        request_url,
        request_headers or {},
        status=status,
        headers={name.lower(): [value] for name, value in headers.items()},
        body_sample=body,
        body_len=len(body),
        body_sample_len=len(body),
        body_sha256=hashlib.sha256(body.encode()).hexdigest(),
        client_context=client_context,
        error=error,
    )


def test_default_output_dir_uses_xdg_state_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_home = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_home))

    out_dir = reserve_output_dir()

    assert default_output_root() == state_home / "headerproof" / "runs"
    assert out_dir.parent == state_home / "headerproof" / "runs"
    assert out_dir.is_dir()


class ScannerFixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def _send_common_headers(self, cache_status: str = "MISS", age: str = "0") -> None:
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "public, max-age=120")
        self.send_header("ETag", '"scanner-test"')
        self.send_header("X-Cache", cache_status)
        self.send_header("Age", age)
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._send_common_headers()
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/slow":
            time.sleep(0.2)
        query = parse_qs(parsed.query)
        canary = self._canary_from_headers()
        reflected = []
        if canary:
            reflected.append(f"header-reflect={canary}")

        if "pa_reflect" in query:
            reflected.append(f"param-reflect={query['pa_reflect'][0]}")

        crlf_value = query.get("pa_crlf", [""])[0]
        crlf_match = re.search(r"X-PA-Injected:\s*(pa-scan-[a-f0-9]+)", crlf_value)

        self.send_response(200)
        self._send_common_headers(cache_status="MISS", age="0")
        if canary:
            self.send_header("X-Reflected-Header", canary)
        if crlf_match:
            self.send_header("X-PA-Injected", crlf_match.group(1))
        self.end_headers()
        body = "<html><body>" + " ".join(reflected) + "</body></html>"
        self.wfile.write(body.encode())

    def _canary_from_headers(self) -> str:
        for value in self.headers.values():
            match = re.search(r"(pa-scan-[a-f0-9]+)", value)
            if match:
                return match.group(1)
        return ""


class CacheOriginHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def do_GET(self) -> None:
        canary = ""
        for value in self.headers.values():
            match = re.search(r"(pa-scan-[a-f0-9]+)", value)
            if match:
                canary = match.group(1)
                break
        body = f"origin-response {canary}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Cache-Control", "public, max-age=120")
        self.send_header("ETag", '"proxy-fixture"')
        if canary:
            self.send_header("X-Origin-Reflection", canary)
        self.end_headers()
        self.wfile.write(body)


class SharedCacheProxyHandler(BaseHTTPRequestHandler):
    origin_port = 0
    cache: dict[str, tuple[int, list[tuple[str, str]], bytes]] = {}
    lock = threading.Lock()

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def do_GET(self) -> None:
        bypass = "no-cache" in self.headers.get("Cache-Control", "").lower()
        with self.lock:
            cached = self.cache.get(self.path) if not bypass else None
        if cached is not None:
            status, headers, body = cached
            self._send_cached(status, headers, body, "HIT", "7")
            return

        upstream_headers = {
            name: value
            for name, value in self.headers.items()
            if name.lower() not in {"host", "connection", "cache-control", "pragma"}
        }
        upstream = request.Request(
            f"http://127.0.0.1:{self.origin_port}{self.path}",
            headers=upstream_headers,
        )
        with request.urlopen(upstream, timeout=1.0) as response:
            status = response.status
            headers = [
                (name, value)
                for name, value in response.headers.items()
                if name.lower() not in {"server", "date", "content-length", "x-cache", "age"}
            ]
            body = response.read()
        if not bypass:
            with self.lock:
                self.cache[self.path] = (status, headers, body)
        self._send_cached(status, headers, body, "BYPASS" if bypass else "MISS", "0")

    def _send_cached(
        self,
        status: int,
        headers: list[tuple[str, str]],
        body: bytes,
        cache_status: str,
        age: str,
    ) -> None:
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("X-Cache", cache_status)
        self.send_header("Age", age)
        self.end_headers()
        self.wfile.write(body)


class ConcurrencyFixtureHandler(BaseHTTPRequestHandler):
    active = 0
    max_active = 0
    lock = threading.Lock()

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def do_OPTIONS(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        with ConcurrencyFixtureHandler.lock:
            ConcurrencyFixtureHandler.active += 1
            ConcurrencyFixtureHandler.max_active = max(
                ConcurrencyFixtureHandler.max_active,
                ConcurrencyFixtureHandler.active,
            )
        try:
            time.sleep(0.03)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b"ok")
        finally:
            with ConcurrencyFixtureHandler.lock:
                ConcurrencyFixtureHandler.active -= 1


class FixedBodyHandler(BaseHTTPRequestHandler):
    body = b"0123456789" * 10

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)


def test_header_active_scan_detects_core_signals(tmp_path: Path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/demo"
        input_file = tmp_path / "urls.txt"
        input_file.write_text(url + "\n")
        args = header_active_scan.parse_cli_args(["-l", str(input_file), "-c", "1"])
        args.fp_mode = "all"
        args.no_live_alerts = True
        args.no_preflight = False
        args.no_cache_confirm = False
        args.origin_mode = "standard"
        args.header_probe_limit = 0

        result = header_active_scan.scan_url(url, args)
        signal_types = {signal["type"] for signal in result["signals"]}

        assert result["status"] == "scanned"
        assert "cors_arbitrary_origin_with_credentials" in signal_types
        assert "header_reflection_candidate" in signal_types
        assert "header_based_content_spoofing" in signal_types
        assert "cache_poisoning_shared_cache_confirmed" not in signal_types
        assert "query_parameter_content_reflection" in signal_types
        assert "response_splitting_crlf_candidate" in signal_types
    finally:
        server.shutdown()
        server.server_close()


def test_header_active_scan_fast_defaults(tmp_path: Path) -> None:
    input_file = tmp_path / "urls.txt"
    input_file.write_text("https://example.com/\n")
    args = header_active_scan.parse_cli_args(["-l", str(input_file)])

    assert args.url_timeout == 9.0
    assert args.timeout == 2.5
    assert args.delay == 0.0
    assert args.concurrency == 16
    assert args.per_url_concurrency == 4
    assert args.max_body == 16384
    assert args.origin_mode == "standard"
    assert args.header_probe_limit == 5
    assert args.no_preflight is False
    assert args.no_cache_confirm is False
    assert args.fp_mode == "strict"
    assert args.min_alert_confidence == "medium"
    assert args.no_live_alerts is False


def test_header_active_scan_version(capsys) -> None:
    try:
        header_active_scan.parse_cli_args(["--version"])
    except SystemExit as exc:
        captured = capsys.readouterr()
        assert exc.code == 0
        assert "HeaderProof" in captured.out
    else:
        raise AssertionError("--version must exit cleanly")


def test_header_active_scan_missing_input_is_clean_error(capsys) -> None:
    rc = header_active_scan.main_from_args(["-l", "/path/to/urls.txt"])

    captured = capsys.readouterr()
    assert rc == 2
    assert "input URL file not found" in captured.err
    assert "Traceback" not in captured.err


def test_header_active_scan_cli_matches_roadmap_options(tmp_path: Path) -> None:
    input_file = tmp_path / "urls.txt"
    input_file.write_text("https://example.com/\n")
    output_file = tmp_path / "findings.jsonl"

    args = header_active_scan.parse_cli_args(
        [
            "-l",
            str(input_file),
            "-c",
            "2",
            "-rl",
            "4",
            "-severity",
            "high,medium",
            "-o",
            str(output_file),
            "-json",
            "-v",
            "-timeout",
            "1.5",
        ]
    )

    assert args.list_path == str(input_file)
    assert args.concurrency == 2
    assert args.rate_limit == 4.0
    assert args.severity_filter == {"high", "medium"}
    assert args.output == str(output_file)
    assert args.json is True
    assert args.verbose is True
    assert args.timeout == 1.5
    assert args.quiet is True
    assert args.no_live_alerts is False


def test_header_active_scan_rejects_removed_profile_flag(tmp_path: Path, capsys) -> None:
    input_file = tmp_path / "urls.txt"
    input_file.write_text("https://example.com/\n")

    try:
        header_active_scan.parse_cli_args(["-l", str(input_file), "--profile", "thorough"])
    except SystemExit as exc:
        captured = capsys.readouterr()
        assert exc.code == 2
        assert "unrecognized arguments" in captured.err
    else:
        raise AssertionError("removed profile flag must be rejected")


def test_load_urls_handles_jsonl_invalid_urls_duplicates_and_limits(tmp_path: Path) -> None:
    input_file = tmp_path / "urls.txt"
    input_file.write_text(
        "\n".join(
            [
                "# comment",
                "example.com",
                '{"url":"https://api.example.com/v1/me"}',
                '{"final_url":"http://example.net/path?q=1#frag"}',
                '{"url":""}',
                '{"not_json"',
                "ftp://example.org/file",
                "example.com",
            ]
        )
        + "\n"
    )

    assert header_active_scan.load_urls(input_file) == [
        "https://example.com/",
        "https://api.example.com/v1/me",
        "http://example.net/path?q=1",
    ]
    assert header_active_scan.load_urls(input_file, max_urls=2) == [
        "https://example.com/",
        "https://api.example.com/v1/me",
    ]


def test_header_active_scan_writes_verification_plan(tmp_path: Path) -> None:
    metadata = {
        "tool": "HeaderProof",
        "version": "test",
        "git_commit": "abc123",
        "command": ["headerproof", "-i", "urls.txt"],
        "config": {"profile": "fast"},
    }
    header_active_scan.write_outputs(
        [
            {
                "url": "https://example.com/",
                "status": "scanned",
                "signals": [],
                "filtered_signals": 0,
            }
        ],
        tmp_path,
        metadata,
    )

    saved_metadata = json.loads((tmp_path / "metadata.json").read_text())
    assert saved_metadata["tool"] == "HeaderProof"
    assert saved_metadata["version"] == "test"
    assert saved_metadata["git_commit"] == "abc123"
    assert saved_metadata["config"]["profile"] == "fast"
    plan = (tmp_path / "verification-plan.md").read_text()
    assert "## CORS" in plan
    assert "## CSRF" in plan
    assert "## Cache Poisoning" in plan
    assert "Report Gate:" in plan
    summary = (tmp_path / "summary.md").read_text()
    assert "## Run Metadata" in summary
    assert "- git_commit: abc123" in summary
    assert (tmp_path / "observations.jsonl").exists()
    assert (tmp_path / "probes.jsonl").exists()


def test_header_active_scan_live_alerts_and_strict_filtering(tmp_path: Path, capsys) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/demo"
        input_file = tmp_path / "urls.txt"
        input_file.write_text(url + "\n")
        args = header_active_scan.parse_cli_args(["-l", str(input_file), "-c", "1"])
        args.no_color = True

        result = header_active_scan.scan_url(url, args)
        captured = capsys.readouterr()
        signal_types = {signal["type"] for signal in result["signals"]}

        assert "[response_splitting_crlf_candidate] [high] [reproduced]" in captured.out
        assert "VERIFIED TECHNICAL SIGNAL" not in captured.out
        assert "Why it is shown" not in captured.out
        assert captured.err == ""
        assert "response_splitting_crlf_candidate" in signal_types
        assert "cors_arbitrary_origin_with_credentials" not in signal_types
        assert "query_parameter_content_reflection" not in signal_types
        assert result["filtered_signals"] >= 1
        confirmed_signal = next(signal for signal in result["signals"] if signal["type"] == "response_splitting_crlf_candidate")
        assert confirmed_signal["assessment"]["state"] == "reproduced"
        assert confirmed_signal["assessment"]["technical_gate"] == "passed"
        assert confirmed_signal["assessment"]["impact"] == "unverified"
        assert "verification_plan" in confirmed_signal
    finally:
        server.shutdown()
        server.server_close()


def test_main_json_stream_and_metadata(tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        state_home = tmp_path / "state"
        monkeypatch.setenv("XDG_STATE_HOME", str(state_home))
        url = f"http://127.0.0.1:{server.server_port}/demo"
        input_file = tmp_path / "urls.txt"
        input_file.write_text(url + "\n")

        rc = header_active_scan.main_from_args(["-l", str(input_file), "-c", "1", "-json"])
        captured = capsys.readouterr()
        records = [json.loads(line) for line in captured.out.splitlines() if line.strip()]
        run_dirs = list((state_home / "headerproof" / "runs").glob("headerproof-*"))
        assert len(run_dirs) == 1
        out_dir = run_dirs[0]
        metadata = json.loads((out_dir / "metadata.json").read_text())

        assert rc == 1
        assert captured.err == ""
        assert records
        assert all(item["url"] == url for item in records)
        assert metadata["tool"] == "HeaderProof"
        assert metadata["config"]["concurrency"] == 1
        assert "profile" not in metadata["config"]
        observations = (out_dir / "observations.jsonl").read_text().splitlines()
        probes = [json.loads(line) for line in (out_dir / "probes.jsonl").read_text().splitlines()]
        assert observations
        assert probes
        assert all(probe["exchange"] is not None for probe in probes if probe["status"] == "completed")
    finally:
        server.shutdown()
        server.server_close()


def test_main_sarif_keeps_machine_output_on_stdout_and_logs_on_stderr(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        state_home = tmp_path / "state"
        monkeypatch.setenv("XDG_STATE_HOME", str(state_home))
        url = f"http://127.0.0.1:{server.server_port}/demo"

        rc = header_active_scan.main_from_args([url, "-c", "1", "-sarif"])
        captured = capsys.readouterr()
        payload = json.loads(captured.out)

        assert rc == 1
        assert payload["version"] == "2.1.0"
        assert payload["runs"][0]["tool"]["driver"]["name"] == "HeaderProof"
        assert payload["runs"][0]["results"]
        assert "headerproof: input=" in captured.err
        assert "HeaderProof" not in captured.err
        assert not any(line.startswith("[") for line in captured.err.splitlines())
    finally:
        server.shutdown()
        server.server_close()


def test_scan_timeout_keeps_batch_moving(tmp_path: Path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/slow"
        input_file = tmp_path / "urls.txt"
        input_file.write_text(url + "\n")
        args = header_active_scan.parse_cli_args(["-l", str(input_file), "-c", "1", "-timeout", "0.05"])
        args.no_live_alerts = True
        args.url_timeout = 0.12

        result = header_active_scan.scan_url(url, args)

        assert result["status"] in {"error", "partial_timeout"}
        assert result["time_budget"]["elapsed_ms"] < 900
        assert isinstance(result["errors"], list)
    finally:
        server.shutdown()
        server.server_close()


def test_unreachable_baseline_is_error_not_scanned(tmp_path: Path) -> None:
    input_file = tmp_path / "urls.txt"
    input_file.write_text("http://127.0.0.1:1/\n")
    args = header_active_scan.parse_cli_args(["-l", str(input_file), "-timeout", "0.05"])
    args.no_live_alerts = True

    result = header_active_scan.scan_url("http://127.0.0.1:1/", args)

    assert result["status"] == "error"
    assert result["errors"]
    assert result["probes"]
    assert result["signals"] == []


def test_transport_records_full_body_hash_and_explicit_truncation() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixedBodyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/body"
        client = header_active_scan.HttpClient(1.0, 10, False, 0.0)
        snapshot = client.fetch(url, client_context="body-test")
        exchange = header_active_scan.snapshot_summary(snapshot, save_body=True)
        response = exchange["response"]

        assert response["body_len"] == 100
        assert response["body_sample_len"] == 10
        assert response["body_truncated"] is True
        assert response["body_sha256"] == hashlib.sha256(FixedBodyHandler.body).hexdigest()
        assert response["body_sha256_scope"] == "full_response"
        assert response["body_sample"] == "0123456789"
    finally:
        server.shutdown()
        server.server_close()


def test_probe_errors_make_scan_partial_and_are_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    call_lock = threading.Lock()

    def fake_fetch(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        client_context: str = "default",
    ) -> header_active_scan.HttpSnapshot:
        nonlocal calls
        with call_lock:
            calls += 1
            call_number = calls
        if call_number == 1:
            return make_snapshot(
                {"Content-Type": "text/plain", "Cache-Control": "no-store"},
                body="baseline",
                request_url=url,
                request_headers=headers,
                client_context=client_context,
            )
        return make_snapshot(
            {},
            status=0,
            request_url=url,
            request_headers=headers,
            client_context=client_context,
            error="ConnectionError: fixture failure",
        )

    monkeypatch.setattr(header_active_scan.HttpClient, "fetch", fake_fetch)
    input_file = tmp_path / "urls.txt"
    input_file.write_text("http://fixture.invalid/\n")
    args = header_active_scan.parse_cli_args(["-l", str(input_file), "-c", "2"])
    args.no_live_alerts = True

    result = header_active_scan.scan_url("http://fixture.invalid/", args)

    assert result["status"] == "partial_error"
    assert result["errors"]
    failed_probes = [probe for probe in result["probes"] if probe["status"] == "error"]
    assert failed_probes
    assert all(probe["exchange"]["response"]["error"] for probe in failed_probes)
    assert any(item["state"] == "error" for item in result["coverage"] if item["kind"] == "probe")


def test_all_failed_batch_returns_error_exit_code(tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch) -> None:
    state_home = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_home))
    input_file = tmp_path / "urls.txt"
    input_file.write_text("http://127.0.0.1:1/\n")

    rc = header_active_scan.main_from_args(
        ["-l", str(input_file), "-c", "1", "-timeout", "0.05", "-json"]
    )
    captured = capsys.readouterr()
    run_dirs = list((state_home / "headerproof" / "runs").glob("headerproof-*"))
    assert len(run_dirs) == 1
    out_dir = run_dirs[0]
    metadata = json.loads((out_dir / "metadata.json").read_text())

    assert rc == 2
    assert captured.out == ""
    assert metadata["summary"]["scanned"] == 0
    assert metadata["summary"]["error"] == 1
    assert metadata["summary"]["error_events"] >= 1
    assert (out_dir / "errors.jsonl").read_text().splitlines()


def test_output_records_match_published_json_schema(tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        state_home = tmp_path / "state"
        monkeypatch.setenv("XDG_STATE_HOME", str(state_home))
        input_file = tmp_path / "urls.txt"
        input_file.write_text(f"http://127.0.0.1:{server.server_port}/demo\n")
        rc = header_active_scan.main_from_args(["-l", str(input_file), "-c", "1", "-silent"])
        capsys.readouterr()
        run_dirs = list((state_home / "headerproof" / "runs").glob("headerproof-*"))
        assert len(run_dirs) == 1
        out_dir = run_dirs[0]
        schema = json.loads((ROOT / "schemas" / "evidence-v1.2.schema.json").read_text())
        validator = jsonschema.Draft202012Validator(schema)
        jsonschema.Draft202012Validator.check_schema(schema)

        assert rc in {0, 1}
        for filename in (
            "results.jsonl",
            "signals.jsonl",
            "observations.jsonl",
            "probes.jsonl",
            "coverage.jsonl",
            "errors.jsonl",
        ):
            for line in (out_dir / filename).read_text().splitlines():
                validator.validate(json.loads(line))
    finally:
        server.shutdown()
        server.server_close()


def test_cors_vary_origin_suppresses_cache_poisoning_candidate() -> None:
    origin = "https://pa-scan-vary.invalid"
    snap = make_snapshot(
        {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Cache-Control": "public, max-age=120",
            "Vary": "Accept-Encoding, Origin",
        }
    )

    signal_types = {signal["type"] for signal in header_active_scan.analyze_cors_probe(origin, snap, save_body=False)}

    assert "cors_arbitrary_origin_with_credentials" in signal_types
    assert "cors_cache_poisoning_candidate" not in signal_types


def test_large_input_list_deduplicates_without_expanding_scope(tmp_path: Path) -> None:
    input_file = tmp_path / "urls.txt"
    lines = [f"https://example.com/path-{index % 25}" for index in range(1000)]
    input_file.write_text("\n".join(lines) + "\n")

    urls = header_active_scan.load_urls(input_file)

    assert len(urls) == 25
    assert urls[0] == "https://example.com/path-0"


def test_main_respects_global_http_concurrency(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ConcurrencyFixtureHandler.active = 0
    ConcurrencyFixtureHandler.max_active = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), ConcurrencyFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        state_home = tmp_path / "state"
        monkeypatch.setenv("XDG_STATE_HOME", str(state_home))
        input_file = tmp_path / "urls.txt"
        urls = [f"http://127.0.0.1:{server.server_port}/demo?u={index}" for index in range(6)]
        input_file.write_text("\n".join(urls) + "\n")

        rc = header_active_scan.main_from_args(["-l", str(input_file), "-c", "2", "-silent"])
        capsys.readouterr()
        run_dirs = list((state_home / "headerproof" / "runs").glob("headerproof-*"))
        assert len(run_dirs) == 1

        assert rc in {0, 1}
        assert ConcurrencyFixtureHandler.max_active <= 2
        assert (run_dirs[0] / "probes.jsonl").exists()
    finally:
        server.shutdown()
        server.server_close()


def test_independent_header_findings_are_not_hidden_as_duplicates(tmp_path: Path) -> None:
    SharedCacheProxyHandler.cache = {}
    origin = ThreadingHTTPServer(("127.0.0.1", 0), CacheOriginHandler)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()
    SharedCacheProxyHandler.origin_port = origin.server_port
    proxy = ThreadingHTTPServer(("127.0.0.1", 0), SharedCacheProxyHandler)
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    try:
        url = f"http://127.0.0.1:{proxy.server_port}/demo"
        input_file = tmp_path / "urls.txt"
        input_file.write_text(url + "\n")
        args = header_active_scan.parse_cli_args(
            ["-l", str(input_file), "-c", "1"]
        )
        args.no_live_alerts = True
        args.header_probe_limit = 2

        result = header_active_scan.scan_url(url, args)
        cache_confirmed = [
            signal for signal in result["signals"] if signal["type"] == "cache_poisoning_shared_cache_confirmed"
        ]

        probe_headers = {signal["evidence"]["probe_header"] for signal in cache_confirmed}
        assert len(probe_headers) == len(cache_confirmed)
        assert len(cache_confirmed) >= 2
        assert result["duplicate_signals"] == 0
    finally:
        proxy.shutdown()
        proxy.server_close()
        origin.shutdown()
        origin.server_close()


def test_crlf_confirmation_requires_exact_canary_header_value() -> None:
    canary = "pa-scan-deadbeef"
    ambient_header = make_snapshot({"X-PA-Injected": "static-debug-value"})

    assert header_active_scan.analyze_crlf_probe(canary, ambient_header, save_body=False) == []

    reflected_but_not_exact = make_snapshot({"X-PA-Injected": f"prefix-{canary}"})
    weak_signal = header_active_scan.analyze_crlf_probe(canary, reflected_but_not_exact, save_body=False)[0]
    assert weak_signal["evidence"]["injected_header_seen"] is False
    assert weak_signal["assessment"]["technical_gate"] == "failed"

    exact_header = make_snapshot({"X-PA-Injected": canary})
    confirmed_signal = header_active_scan.analyze_crlf_probe(canary, exact_header, save_body=False)[0]
    assert confirmed_signal["evidence"]["injected_header_seen"] is True
    assert confirmed_signal["assessment"]["state"] == "reproduced"
    assert confirmed_signal["assessment"]["technical_gate"] == "passed"
    assert confirmed_signal["submission_status"] == "manual_validation_required"


def test_cache_confirmation_requires_complete_state_machine() -> None:
    canary = "pa-scan-cafebabe"
    cache_url = "http://example.test/demo?pa_cb=probe"
    control_url = "http://example.test/demo?pa_cb=probe-control"
    poison = make_snapshot(
        {"Cache-Control": "public, max-age=120", "ETag": '"weak-proof"'},
        body=f"poison={canary}",
        request_headers={"X-Forwarded-Host": canary},
        request_url=cache_url,
        client_context="poison",
    )
    clean_before = make_snapshot(
        {"Cache-Control": "public, max-age=120", "ETag": '"weak-proof"', "Age": "0"},
        body="clean",
        request_url=cache_url,
        client_context="clean-before",
    )
    clean_without_hit = make_snapshot(
        {"Cache-Control": "public, max-age=120", "ETag": '"weak-proof"'},
        body=f"cached={canary}",
        request_url=cache_url,
        client_context="victim",
    )
    fresh_control = make_snapshot(
        {"Cache-Control": "public, max-age=120", "ETag": '"weak-proof"', "Age": "0"},
        body="clean-control",
        request_url=control_url,
        client_context="fresh-control",
    )

    weak_signals = header_active_scan.analyze_header_probe(
        "X-Forwarded-Host",
        canary,
        "probe-weak",
        clean_before,
        poison,
        clean_without_hit,
        fresh_control,
        save_body=False,
    )
    weak_reproduction = next(
        signal for signal in weak_signals if signal["type"] == "cache_poisoning_cross_request_reproduction"
    )
    assert weak_reproduction["evidence"]["shared_cache_confirmed"] is False
    assert weak_reproduction["assessment"]["technical_gate"] == "failed"

    clean_with_hit = make_snapshot(
        {"Cache-Control": "public, max-age=120", "Age": "7", "X-Cache": "HIT"},
        body=f"cached={canary}",
        request_url=cache_url,
        client_context="victim",
    )
    strong_signals = header_active_scan.analyze_header_probe(
        "X-Forwarded-Host",
        canary,
        "probe-strong",
        clean_before,
        poison,
        clean_with_hit,
        fresh_control,
        save_body=False,
    )
    strong_confirmed = next(
        signal for signal in strong_signals if signal["type"] == "cache_poisoning_shared_cache_confirmed"
    )
    assert strong_confirmed["evidence"]["shared_cache_confirmed"] is True
    assert all(strong_confirmed["evidence"]["state_machine_checks"].values())
    assert strong_confirmed["assessment"]["state"] == "cross_request_confirmed"
    assert strong_confirmed["assessment"]["technical_gate"] == "passed"

    missing_control = header_active_scan.analyze_header_probe(
        "X-Forwarded-Host",
        canary,
        "probe-missing-control",
        clean_before,
        poison,
        clean_with_hit,
        None,
        save_body=False,
    )
    missing_control_signal = next(
        signal for signal in missing_control if signal["type"] == "cache_poisoning_cross_request_reproduction"
    )
    assert missing_control_signal["evidence"]["shared_cache_confirmed"] is False
    assert missing_control_signal["evidence"]["state_machine_checks"]["fresh_control_completed"] is False
    assert missing_control_signal["assessment"]["technical_gate"] == "failed"


def test_cache_confirmation_rejects_origin_side_state_with_static_age() -> None:
    canary = "pa-scan-originstate"
    cache_url = "http://example.test/demo?pa_cb=origin-state"
    control_url = "http://example.test/demo?pa_cb=origin-state-control"
    clean_before = make_snapshot(
        {"Cache-Control": "public, max-age=120", "Age": "5"},
        body="clean",
        request_url=cache_url,
        client_context="clean-before",
    )
    poison = make_snapshot(
        {"Cache-Control": "public, max-age=120", "Age": "5"},
        body=f"poison={canary}",
        request_headers={"X-Forwarded-Host": canary},
        request_url=cache_url,
        client_context="poison",
    )
    victim = make_snapshot(
        {"Cache-Control": "public, max-age=120", "Age": "5"},
        body=f"origin-memory={canary}",
        request_url=cache_url,
        client_context="victim",
    )
    fresh_control = make_snapshot(
        {"Cache-Control": "public, max-age=120", "Age": "5"},
        body="fresh-clean",
        request_url=control_url,
        client_context="fresh-control",
    )

    signals = header_active_scan.analyze_header_probe(
        "X-Forwarded-Host",
        canary,
        "probe-origin-state",
        clean_before,
        poison,
        victim,
        fresh_control,
        save_body=False,
    )
    reproduced = next(
        signal for signal in signals if signal["type"] == "cache_poisoning_cross_request_reproduction"
    )

    assert reproduced["evidence"]["shared_cache_confirmed"] is False
    assert reproduced["assessment"]["technical_gate"] == "failed"


def test_install_scripts_are_executable_and_valid_shell() -> None:
    for script in ("install.sh", "uninstall.sh"):
        path = ROOT / script
        assert path.exists()
        assert path.stat().st_mode & 0o111
        subprocess.run(["sh", "-n", str(path)], check=True)


def test_headerproof_yaml_loads_bulk_origins_and_headers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "headerproof.yaml").write_text(
        "origins:\n"
        "  - https://custom-origin.invalid\n"
        "headers:\n"
        "  - X-Custom-Cache-Key\n"
        "rate_limit: 7\n"
        "timeout: 1.5\n"
        "severity: high,medium\n"
    )

    args = header_active_scan.parse_cli_args(["example.com"])

    assert args.origin == ["https://custom-origin.invalid"]
    assert args.header == ["X-Custom-Cache-Key"]
    assert args.rate_limit == 7
    assert args.timeout == 1.5
    assert args.severity_filter == {"high", "medium"}
    assert args.config_path.endswith("headerproof.yaml")


def test_cli_values_override_headerproof_yaml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "headerproof.yaml").write_text(
        "concurrency: 3\nrate_limit: 2\ntimeout: 1\nseverity: low\n"
    )

    args = header_active_scan.parse_cli_args(
        ["example.com", "-c", "9", "-rl", "4", "-timeout", "2", "-severity", "high"]
    )

    assert args.concurrency == 9
    assert args.rate_limit == 4
    assert args.timeout == 2
    assert args.severity_filter == {"high"}


def test_invalid_headerproof_yaml_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "headerproof.yaml").write_text("unknown_option: true\n")

    with pytest.raises(SystemExit):
        header_active_scan.parse_cli_args(["example.com"])


def test_headerproof_yaml_request_headers_are_applied_and_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "headerproof.yaml").write_text(
        "request_headers:\n"
        "  Cookie: session=secret-value\n"
        "  Authorization: 'Bearer test-token'\n"
    )
    args = header_active_scan.parse_cli_args(["example.com"])
    assert args.request_headers == {
        "Cookie": "session=secret-value",
        "Authorization": "Bearer test-token",
    }

    metadata = header_active_scan.build_metadata(args, tmp_path / "input.txt", 1)
    encoded = json.dumps(metadata)
    assert metadata["config"]["request_headers_count"] == 2
    assert "secret-value" not in encoded
    assert "test-token" not in encoded


def test_scan_applies_configured_request_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[dict[str, str]] = []

    def fake_fetch(self, url, method="GET", headers=None, timeout=None, client_context="default"):
        seen.append(dict(headers or {}))
        return make_snapshot(
            {"Content-Type": "text/plain", "Cache-Control": "no-store"},
            request_url=url,
            request_headers=headers,
            client_context=client_context,
        )

    monkeypatch.setattr(header_active_scan.HttpClient, "fetch", fake_fetch)
    args = header_active_scan.parse_cli_args(["https://example.com/"])
    args.enabled_checks = set()
    args.request_headers = {"Cookie": "session=fixture", "Authorization": "Bearer fixture"}
    args.no_live_alerts = True

    result = header_active_scan.scan_url("https://example.com/", args)

    assert result["status"] == "scanned"
    assert seen == [{"Cookie": "session=fixture", "Authorization": "Bearer fixture"}]


def test_cache_confirmation_uses_distinct_transport_instances(monkeypatch: pytest.MonkeyPatch) -> None:
    instances_by_context: dict[str, header_active_scan.HttpClient] = {}
    original_fetch = header_active_scan.HttpClient.fetch

    def recording_fetch(self, url, method="GET", headers=None, timeout=None, client_context="default"):
        instances_by_context[client_context] = self
        return original_fetch(self, url, method, headers, timeout, client_context)

    monkeypatch.setattr(header_active_scan.HttpClient, "fetch", recording_fetch)
    origin = ThreadingHTTPServer(("127.0.0.1", 0), CacheOriginHandler)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()
    SharedCacheProxyHandler.origin_port = origin.server_port
    SharedCacheProxyHandler.cache = {}
    proxy = ThreadingHTTPServer(("127.0.0.1", 0), SharedCacheProxyHandler)
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    try:
        args = header_active_scan.parse_cli_args([f"http://127.0.0.1:{proxy.server_port}/cache"])
        args.enabled_checks = {"cache-poisoning", "header-injection", "content-spoofing"}
        args.header = ["X-Forwarded-Host"]
        args.header_probe_limit = 1
        args.per_url_concurrency = 1
        args.concurrency = 1
        args.no_live_alerts = True
        result = header_active_scan.scan_url(f"http://127.0.0.1:{proxy.server_port}/cache", args)
    finally:
        proxy.shutdown()
        proxy.server_close()
        proxy_thread.join(timeout=1)
        origin.shutdown()
        origin.server_close()
        origin_thread.join(timeout=1)

    roles = {
        probe["role"]: probe["client_context"]
        for probe in result["probes"]
        if probe["role"] in {"cache-clean-before", "cache-poison", "cache-victim", "cache-fresh-control"}
    }
    assert set(roles) == {"cache-clean-before", "cache-poison", "cache-victim", "cache-fresh-control"}
    transports = [instances_by_context[roles[role]] for role in roles]
    assert all(left is not right for index, left in enumerate(transports) for right in transports[index + 1 :])


def test_persisted_cache_finding_trace_resolves_to_probe_jsonl(tmp_path: Path) -> None:
    SharedCacheProxyHandler.cache = {}
    origin = ThreadingHTTPServer(("127.0.0.1", 0), CacheOriginHandler)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()
    SharedCacheProxyHandler.origin_port = origin.server_port
    proxy = ThreadingHTTPServer(("127.0.0.1", 0), SharedCacheProxyHandler)
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    try:
        url = f"http://127.0.0.1:{proxy.server_port}/trace"
        args = header_active_scan.parse_cli_args([url])
        args.enabled_checks = {"cache-poisoning", "header-injection", "content-spoofing"}
        args.header = ["X-Forwarded-Host"]
        args.header_probe_limit = 1
        args.per_url_concurrency = 1
        args.concurrency = 1
        args.no_live_alerts = True
        result = header_active_scan.scan_url(url, args)
    finally:
        proxy.shutdown()
        proxy.server_close()
        proxy_thread.join(timeout=1)
        origin.shutdown()
        origin.server_close()
        origin_thread.join(timeout=1)

    confirmed = next(signal for signal in result["signals"] if signal["type"] == "cache_poisoning_shared_cache_confirmed")
    out_dir = tmp_path / "evidence"
    out_dir.mkdir()
    writer = EvidenceWriter(out_dir, {"schema_version": confirmed["schema_version"], "run_id": "trace-test"})
    writer.append_result(result)
    writer.finalize()

    persisted_signal = next(
        json.loads(line)
        for line in (out_dir / "signals.jsonl").read_text().splitlines()
        if json.loads(line)["type"] == "cache_poisoning_shared_cache_confirmed"
    )
    persisted_probes = {
        (probe["probe_id"], probe["role"]): probe
        for probe in map(json.loads, (out_dir / "probes.jsonl").read_text().splitlines())
    }
    trace = persisted_signal["evidence"]["proof_trace"]
    assert len(trace) == 4
    for stage in trace.values():
        persisted = persisted_probes[(stage["probe_id"], stage["role"])]
        assert persisted["client_context"] == stage["client_context"]
        assert persisted["exchange"] is not None
        assert persisted["status"] == "completed"


def test_snapshot_summary_redacts_only_exact_configured_header_values() -> None:
    snapshot = make_snapshot(
        {},
        request_headers={
            "Authorization": "Bearer configured-secret",
            "X-Forwarded-Host": "scanner-canary",
        },
    )
    snapshot.persistence_redactions = {
        "authorization": "Bearer configured-secret",
        "X-Forwarded-Host": "configured-host-value",
    }
    exchange = header_active_scan.snapshot_summary(snapshot)
    assert exchange["request"]["headers"]["Authorization"] == "<redacted>"
    assert exchange["request"]["headers"]["X-Forwarded-Host"] == "scanner-canary"


def test_configured_request_header_secrets_are_absent_from_complete_run_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_cookie = "SYNTHETIC_COOKIE_SECRET_29"
    secret_auth = "SYNTHETIC_AUTH_SECRET_29"
    state_home = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_home))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "headerproof.yaml").write_text(
        "request_headers:\n"
        f"  Cookie: 'session={secret_cookie}'\n"
        f"  Authorization: 'Bearer {secret_auth}'\n"
    )

    server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        rc = header_active_scan.main_from_args(
            [f"http://127.0.0.1:{server.server_port}/demo", "-silent"]
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert rc in {0, 1}
    run_dirs = list((state_home / "headerproof" / "runs").glob("headerproof-*"))
    assert len(run_dirs) == 1
    persisted = b"".join(path.read_bytes() for path in run_dirs[0].rglob("*") if path.is_file())
    assert secret_cookie.encode() not in persisted
    assert secret_auth.encode() not in persisted
    assert b"<redacted>" in persisted
