from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from headerproof.cli import parse_cli_args
from headerproof.engine import scan_url


class DiscoveryHandler(BaseHTTPRequestHandler):
    cache: dict[str, bytes] = {}

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        no_cache = "no-cache" in self.headers.get("Cache-Control", "").lower()
        cached = self.cache.get(self.path)
        if cached is not None and not no_cache:
            body = cached
            cache_status = "HIT"
        else:
            scheme = self.headers.get("X-Forwarded-Scheme", "")
            body = (f"scheme={scheme}" if scheme else "scheme=https").encode()
            cache_status = "MISS"
            if not no_cache:
                self.cache[self.path] = body
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Cache-Control", "public, max-age=120")
        self.send_header("X-Cache", cache_status)
        self.end_headers()
        self.wfile.write(body)


def run_fixture(custom_headers: list[str] | None = None) -> dict[str, Any]:
    DiscoveryHandler.cache = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), DiscoveryHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/vulnerable"
        args = parse_cli_args([url])
        args.enabled_checks = {"cache-poisoning", "header-injection", "content-spoofing"}
        args.header_probe_limit = 5
        args.header = custom_headers or []
        args.per_url_concurrency = 1
        args.concurrency = 1
        args.no_live_alerts = True
        return scan_url(url, args)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_dynamic_discovery_finds_non_default_header_before_confirmation() -> None:
    result = run_fixture()
    assert result["status"] == "scanned"
    assert result["discovery"]["discovered_headers"] == [
        {"name": "X-Forwarded-Scheme", "reason": "marker_reflected"}
    ]
    assert result["discovery"]["evaluated_candidates"] <= result["discovery"]["candidate_count"]
    confirmed = [
        item
        for item in result["signals"]
        if item["type"] == "cache_poisoning_shared_cache_confirmed"
    ]
    assert len(confirmed) == 1
    assert confirmed[0]["evidence"]["probe_header"] == "X-Forwarded-Scheme"
    discovery_roles = [probe["role"] for probe in result["probes"] if probe["role"].startswith("discovery-")]
    assert discovery_roles.count("discovery-baseline") == 3
    assert "discovery-singleton" in discovery_roles


def test_explicit_header_is_removed_from_discovery_candidates() -> None:
    result = run_fixture(["X-Forwarded-Scheme"])
    assert result["discovery"]["candidate_count"] == 15
    assert result["discovery"]["discovered_headers"] == []
    confirmed = [
        item
        for item in result["signals"]
        if item["type"] == "cache_poisoning_shared_cache_confirmed"
    ]
    assert len(confirmed) == 1
    assert confirmed[0]["evidence"]["probe_header"] == "X-Forwarded-Scheme"


class AllImpactHandler(BaseHTTPRequestHandler):
    request_count = 0

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        type(self).request_count += 1
        values = [
            value
            for name, value in self.headers.items()
            if name.casefold().startswith(("x-", "front-end", "true-client"))
        ]
        body = ("stable " + " ".join(values)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Cache-Control", "public, max-age=120")
        self.send_header("X-Cache", "MISS")
        self.end_headers()
        self.wfile.write(body)


def test_discovery_reports_header_limit_truncation_and_measured_requests() -> None:
    AllImpactHandler.request_count = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), AllImpactHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/vulnerable"
        args = parse_cli_args([url])
        args.enabled_checks = {"cache-poisoning", "header-injection", "content-spoofing"}
        args.per_url_concurrency = 1
        args.concurrency = 1
        args.no_live_alerts = True
        result = scan_url(url, args)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    discovery = result["discovery"]
    assert len(discovery["discovered_headers"]) == 4
    assert discovery["truncated"] is True
    assert discovery["truncation_reason"] == "discovered_header_limit"
    assert discovery["request_limit_reached"] is False
    assert discovery["requests"] <= 32
    assert discovery["evaluated_candidates"] < discovery["candidate_count"]
    assert AllImpactHandler.request_count >= discovery["requests"]


class CancellationHandler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        scheme = self.headers.get("X-Forwarded-Scheme")
        proto = self.headers.get("X-Forwarded-Proto")
        # Deliberate cancellation: either header alone changes the response,
        # but the contiguous pair together returns the baseline body.
        if bool(scheme) ^ bool(proto):
            body = f"changed {scheme or proto}".encode()
        else:
            body = b"stable"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Cache", "MISS")
        self.end_headers()
        self.wfile.write(body)


def test_second_partition_recovers_header_masked_by_contiguous_batch_cancellation() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), CancellationHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/cancellation"
        args = parse_cli_args([url])
        args.enabled_checks = {"cache-poisoning", "header-injection", "content-spoofing"}
        args.per_url_concurrency = 1
        args.concurrency = 1
        args.no_live_alerts = True
        result = scan_url(url, args)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    names = {item["name"] for item in result["discovery"]["discovered_headers"]}
    assert {"X-Forwarded-Scheme", "X-Forwarded-Proto"} <= names



def test_discovery_probe_exchange_preserves_candidate_lineage() -> None:
    result = run_fixture()
    singleton = [
        probe
        for probe in result["probes"]
        if probe["role"] == "discovery-singleton"
        and "X-Forwarded-Scheme" in (probe.get("exchange") or {}).get("request", {}).get("headers", {})
    ]
    assert singleton
    assert singleton[0]["exchange"]["request"]["headers"]["X-Forwarded-Scheme"].endswith(".invalid")


class IgnoredQueryCacheHandler(BaseHTTPRequestHandler):
    cache: dict[str, bytes] = {}

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        key = self.path.split("?", 1)[0]
        no_cache = "no-cache" in self.headers.get("Cache-Control", "").lower()
        cached = self.cache.get(key)
        if cached is not None and not no_cache:
            body = cached
            cache_status = "HIT"
        else:
            scheme = self.headers.get("X-Forwarded-Scheme", "")
            body = (f"scheme={scheme}" if scheme else "scheme=https").encode()
            cache_status = "MISS"
            if not no_cache:
                self.cache[key] = body
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Cache-Control", "public, max-age=120")
        self.send_header("X-Cache", cache_status)
        self.end_headers()
        self.wfile.write(body)


def test_discovered_header_cannot_bypass_phase1_cache_key_gate() -> None:
    IgnoredQueryCacheHandler.cache = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), IgnoredQueryCacheHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/ignored-query"
        args = parse_cli_args([url])
        args.enabled_checks = {"cache-poisoning", "header-injection", "content-spoofing"}
        args.per_url_concurrency = 1
        args.concurrency = 1
        args.no_live_alerts = True
        result = scan_url(url, args)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    names = {item["name"] for item in result["discovery"]["discovered_headers"]}
    assert "X-Forwarded-Scheme" in names
    assert not any(item["type"] == "cache_poisoning_shared_cache_confirmed" for item in result["signals"])


class SlowDiscoveryHandler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        import time

        time.sleep(0.18)
        body = b"stable"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass


def test_discovery_url_budget_exhaustion_is_explicit() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), SlowDiscoveryHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/slow"
        args = parse_cli_args([url])
        args.enabled_checks = {"cache-poisoning", "header-injection", "content-spoofing"}
        args.per_url_concurrency = 1
        args.concurrency = 1
        args.no_live_alerts = True
        args.url_timeout = 0.85
        args.timeout = 0.5
        result = scan_url(url, args)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert result["status"] == "partial_timeout"
    assert result["discovery"]["truncated"] is True
    assert result["discovery"]["truncation_reason"] == "url_budget_exhausted"
    assert any(error.get("error_type") == "url_timeout" for error in result["errors"])


class LateVarianceHandler(BaseHTTPRequestHandler):
    request_count = 0

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        type(self).request_count += 1
        large = type(self).request_count >= 5 and type(self).request_count % 2 == 1
        body = ("page;" + ("feed=" + "x" * 420 if large else "feed=short")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Cache", "MISS")
        self.end_headers()
        self.wfile.write(body)


def test_adaptive_baseline_learns_late_natural_variance_without_exhausting_discovery() -> None:
    LateVarianceHandler.request_count = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), LateVarianceHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/dynamic"
        args = parse_cli_args([url])
        args.enabled_checks = {"cache-poisoning", "header-injection", "content-spoofing"}
        args.per_url_concurrency = 1
        args.concurrency = 1
        args.no_live_alerts = True
        result = scan_url(url, args)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    discovery = result["discovery"]
    assert discovery["discovered_headers"] == []
    assert discovery["request_limit_reached"] is False
    assert discovery["truncated"] is False
    assert discovery["requests"] < 16
    assert any(probe["role"] == "discovery-negative-control" for probe in result["probes"])


class StatusVarianceHandler(BaseHTTPRequestHandler):
    request_count = 0

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        type(self).request_count += 1
        status = 201 if type(self).request_count >= 5 and type(self).request_count % 2 == 1 else 200
        body = b"stable"
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)


def test_adaptive_baseline_can_learn_clean_status_variance() -> None:
    StatusVarianceHandler.request_count = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), StatusVarianceHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/status-dynamic"
        args = parse_cli_args([url])
        args.enabled_checks = {"cache-poisoning", "header-injection", "content-spoofing"}
        args.per_url_concurrency = 1
        args.concurrency = 1
        args.no_live_alerts = True
        result = scan_url(url, args)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert result["discovery"]["discovered_headers"] == []
    assert result["discovery"]["request_limit_reached"] is False


class RealHeaderImpactWithNoiseHandler(BaseHTTPRequestHandler):
    request_count = 0

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        type(self).request_count += 1
        scheme = self.headers.get("X-Forwarded-Scheme", "")
        # Natural size variance exists, but the candidate still has an attributable marker.
        noise = "n" * (260 if type(self).request_count % 2 else 8)
        body = f"noise={noise}; scheme={scheme or 'https'}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Age", str(type(self).request_count))
        self.send_header("ETag", f'"v{type(self).request_count}"')
        self.send_header("X-Cache", "MISS")
        self.end_headers()
        self.wfile.write(body)


def test_adaptive_baseline_never_suppresses_attributable_marker_or_cache_evidence() -> None:
    RealHeaderImpactWithNoiseHandler.request_count = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), RealHeaderImpactWithNoiseHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/impact"
        args = parse_cli_args([url])
        args.enabled_checks = {"cache-poisoning", "header-injection", "content-spoofing"}
        args.per_url_concurrency = 1
        args.concurrency = 1
        args.no_live_alerts = True
        result = scan_url(url, args)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    discovered = {item["name"]: item["reason"] for item in result["discovery"]["discovered_headers"]}
    assert discovered["X-Forwarded-Scheme"] == "marker_reflected"
    singleton = next(
        probe for probe in result["probes"]
        if probe["role"] == "discovery-singleton"
        and "X-Forwarded-Scheme" in (probe.get("exchange") or {}).get("request", {}).get("headers", {})
    )
    response_headers = singleton["exchange"]["response"]["headers"]
    assert response_headers["age"]
    assert response_headers["etag"]
    assert response_headers["x-cache"] == "MISS"
