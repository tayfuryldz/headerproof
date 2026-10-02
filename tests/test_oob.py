from __future__ import annotations

import socket
import struct
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib import request

from headerproof.detectors import analyze_oob_header_probe
from headerproof.models import HttpSnapshot
from headerproof.oob import OOBEventStore, _http_handler, make_dns_server, query_events


def snapshot() -> HttpSnapshot:
    return HttpSnapshot(
        request_method="GET",
        request_url="https://example.com/",
        status=200,
        reason="OK",
        headers={"content-type": ["text/html"]},
        body_sample="",
        elapsed_ms=1,
        request_headers={"X-Forwarded-Host": "token.oob.local"},
        client_context="oob-test",
    )


def test_http_callback_and_event_query(tmp_path: Path) -> None:
    store = OOBEventStore(tmp_path / "events.jsonl")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _http_handler(store))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        with request.urlopen(f"{base}/c/abc123", timeout=1) as response:
            assert response.status == 200
        events = query_events(base, "abc123")
        assert events == [{"protocol": "http", "token": "abc123"}]
        assert (tmp_path / "events.jsonl").exists()
    finally:
        server.shutdown()
        server.server_close()


def _dns_query(name: str) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def test_dns_callback_records_token() -> None:
    store = OOBEventStore()
    server = make_dns_server("127.0.0.1", 0, store, "oob.local", "127.0.0.1")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(_dns_query("deadbeef.oob.local"), server.server_address)
        response, _ = sock.recvfrom(512)
        assert response[:2] == b"\x12\x34"
        assert store.events("deadbeef")[0]["protocol"] == "dns"
    finally:
        server.shutdown()
        server.server_close()


def test_oob_signal_passes_template_gate() -> None:
    signals = analyze_oob_header_probe(
        "X-Forwarded-Host",
        "deadbeef",
        [
            {"protocol": "dns", "token": "deadbeef", "source": "127.0.0.1"},
            {"protocol": "http", "token": "deadbeef", "detail": "ignored"},
        ],
        snapshot(),
        False,
    )

    assert len(signals) == 1
    assert signals[0]["type"] == "blind_header_oob_confirmed"
    assert signals[0]["assessment"]["technical_gate"] == "passed"
    assert signals[0]["assessment"]["state"] == "cross_request_confirmed"
    assert signals[0]["evidence"]["oob_confirmed"] is True
    assert signals[0]["evidence"]["event_count"] == 2
    assert signals[0]["evidence"]["oob_callbacks"] == [
        {"protocol": "dns", "token": "deadbeef"},
        {"protocol": "http", "token": "deadbeef"},
    ]


def test_oob_signal_requires_exact_matching_callback_token() -> None:
    cases = [
        [{"token": "wrong-token", "protocol": "http"}],
        [{"protocol": "http"}],
        [{"token": "deadbeef"}],
        [{"token": "deadbeef", "protocol": "unrelated"}],
        ["not-an-event", None, {"token": "deadbeef", "protocol": "smtp"}],
    ]
    for events in cases:
        assert analyze_oob_header_probe("X-Forwarded-Host", "deadbeef", events, snapshot(), False) == []

    mixed = analyze_oob_header_probe(
        "X-Forwarded-Host",
        "deadbeef",
        [
            {"token": "wrong-token", "protocol": "dns"},
            {"token": "deadbeef", "protocol": "http", "source": "10.0.0.8"},
            {"token": "deadbeef", "protocol": "ftp"},
        ],
        snapshot(),
        False,
    )
    assert len(mixed) == 1
    assert mixed[0]["evidence"]["oob_callbacks"] == [{"protocol": "http", "token": "deadbeef"}]
    assert mixed[0]["evidence"]["protocols"] == ["http"]
    assert "source" not in mixed[0]["evidence"]["oob_callbacks"][0]


def test_engine_oob_probe_reaches_callback_and_promotes_finding() -> None:
    from headerproof.cli import parse_cli_args
    from headerproof.engine import scan_url

    store = OOBEventStore()
    oob = ThreadingHTTPServer(("127.0.0.1", 0), _http_handler(store))
    oob_thread = threading.Thread(target=oob.serve_forever, daemon=True)
    oob_thread.start()
    api_base = f"http://127.0.0.1:{oob.server_port}"

    class TargetHandler(__import__("http.server").server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            forwarded = self.headers.get("X-Forwarded-Host", "")
            token = forwarded.split(".", 1)[0] if forwarded.endswith(".oob.local") else ""
            if token:
                with request.urlopen(f"{api_base}/c/{token}", timeout=1) as response:
                    assert response.status == 200
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")

        def do_OPTIONS(self) -> None:  # noqa: N802
            self.send_response(204)
            self.end_headers()

        def log_message(self, _format: str, *args: object) -> None:
            return

    target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()
    url = f"http://127.0.0.1:{target.server_port}/"
    try:
        args = parse_cli_args([url])
        args.enabled_checks = {"header-injection"}
        args.header_probe_limit = 1
        args.per_url_concurrency = 1
        args.concurrency = 1
        args.oob_api = api_base
        args.oob_domain = "oob.local"
        args.oob_wait = 1.0
        args.no_live_alerts = True
        result = scan_url(url, args)
    finally:
        target.shutdown()
        target.server_close()
        oob.shutdown()
        oob.server_close()
        target_thread.join(timeout=2)
        oob_thread.join(timeout=2)

    findings = [item for item in result["signals"] if item["type"] == "blind_header_oob_confirmed"]
    assert len(findings) == 1
    assert findings[0]["assessment"]["technical_gate"] == "passed"
    assert findings[0]["assessment"]["state"] == "cross_request_confirmed"
    assert findings[0]["evidence"]["oob_confirmed"] is True
    assert findings[0]["evidence"]["oob_callbacks"] == [
        {"protocol": "http", "token": findings[0]["evidence"]["oob_token"]}
    ]
