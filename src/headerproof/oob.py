from __future__ import annotations

import argparse
import json
import secrets
import socket
import socketserver
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib import error, parse, request


class OOBEventStore:
    def __init__(self, event_log: Path | None = None) -> None:
        self.event_log = event_log
        self._events: dict[str, list[dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def record(self, token: str, protocol: str, source: str, detail: str = "") -> None:
        event = {
            "token": token,
            "protocol": protocol,
            "source": source,
            "detail": detail,
            "timestamp": time.time(),
        }
        with self._lock:
            self._events.setdefault(token, []).append(event)
            if self.event_log is not None:
                self.event_log.parent.mkdir(parents=True, exist_ok=True)
                with self.event_log.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event, sort_keys=True) + "\n")

    def events(self, token: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._events.get(token, [])]


def new_oob_token() -> str:
    return secrets.token_hex(12)


def callback_host(token: str, domain: str) -> str:
    return f"{token}.{domain.strip('.')}"


OOB_EVENT_PROTOCOLS = frozenset({"http", "dns"})


def accepted_oob_events(events: object, token: str) -> list[dict[str, str]]:
    """Keep callbacks that belong to this probe token.

    An accepted event is an object with string ``token`` exactly equal to the
    requested probe token and ``protocol`` of ``http`` or ``dns``. Source
    addresses and free-form detail are dropped.
    """
    if not isinstance(token, str) or not token or not isinstance(events, list):
        return []
    accepted: list[dict[str, str]] = []
    for item in events:
        if not isinstance(item, dict):
            continue
        event_token = item.get("token")
        protocol = item.get("protocol")
        if not isinstance(event_token, str) or event_token != token:
            continue
        if not isinstance(protocol, str) or protocol not in OOB_EVENT_PROTOCOLS:
            continue
        accepted.append({"protocol": protocol, "token": event_token})
    return accepted


def query_events(api_base: str, token: str, timeout: float = 1.0) -> list[dict[str, Any]]:
    url = f"{api_base.rstrip('/')}/api/events/{parse.quote(token, safe='')}"
    try:
        with request.urlopen(url, timeout=max(0.05, timeout)) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, error.URLError, json.JSONDecodeError):
        return []
    events = payload.get("events", []) if isinstance(payload, dict) else []
    return accepted_oob_events(events, token)


def wait_for_event(api_base: str, token: str, timeout: float = 0.75) -> list[dict[str, Any]]:
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        events = query_events(api_base, token, timeout=min(0.25, max(0.05, timeout)))
        if events or time.monotonic() >= deadline:
            return events
        time.sleep(0.05)


def _http_handler(store: OOBEventStore) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "HeaderProofOOB/1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


        def do_GET(self) -> None:
            path = parse.urlsplit(self.path).path
            if path.startswith("/c/"):
                token = path.removeprefix("/c/").split("/", 1)[0]
                if not token:
                    self._json(400, {"error": "missing token"})
                    return
                store.record(token, "http", self.client_address[0], self.headers.get("Host", ""))
                self._json(200, {"ok": True})
                return
            if path.startswith("/api/events/"):
                token = path.removeprefix("/api/events/").split("/", 1)[0]
                events = store.events(token)
                self._json(200, {"token": token, "count": len(events), "events": events})
                return
            if path == "/healthz":
                self._json(200, {"ok": True})
                return
            self._json(404, {"error": "not found"})

    return Handler


def parse_dns_question(data: bytes) -> tuple[str, int, int, bytes] | None:
    if len(data) < 17:
        return None
    offset = 12
    labels: list[str] = []
    while offset < len(data):
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or offset + length > len(data):
            return None
        labels.append(data[offset : offset + length].decode("ascii", errors="ignore"))
        offset += length
    if offset + 4 > len(data):
        return None
    qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
    question = data[12 : offset + 4]
    return ".".join(labels).lower(), qtype, qclass, question


def _token_from_qname(qname: str, domain: str) -> str:
    domain = domain.strip(".").lower()
    if not domain or qname == domain or not qname.endswith("." + domain):
        return ""
    prefix = qname[: -(len(domain) + 1)]
    return prefix.split(".")[-1]


class OOBDNSHandler(socketserver.BaseRequestHandler):
    store: OOBEventStore
    domain: str
    answer_ip: str

    def handle(self) -> None:
        data, sock = self.request
        parsed = parse_dns_question(data)
        if parsed is None:
            return
        qname, qtype, qclass, question = parsed
        token = _token_from_qname(qname, self.domain)
        if token:
            self.store.record(token, "dns", self.client_address[0], qname)

        request_id = data[:2]
        answer_count = 1 if qtype == 1 and qclass == 1 else 0
        response = request_id + struct.pack("!HHHHH", 0x8180, 1, answer_count, 0, 0) + question
        if answer_count:
            response += b"\xc0\x0c" + struct.pack(
                "!HHIH4s",
                1,
                1,
                0,
                4,
                socket.inet_aton(self.answer_ip),
            )
        sock.sendto(response, self.client_address)


def make_dns_server(
    listen: str,
    port: int,
    store: OOBEventStore,
    domain: str,
    answer_ip: str,
) -> socketserver.ThreadingUDPServer:
    handler = type(
        "ConfiguredOOBDNSHandler",
        (OOBDNSHandler,),
        {"store": store, "domain": domain, "answer_ip": answer_ip},
    )
    server = socketserver.ThreadingUDPServer((listen, port), handler)
    server.daemon_threads = True
    return server


def build_oob_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="headerproof oob-server")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--dns-port", type=int, default=5353)
    parser.add_argument("--domain", default="oob.local")
    parser.add_argument("--answer-ip", default="127.0.0.1")
    parser.add_argument("--event-log", type=Path)
    return parser


def run_oob_server(argv: list[str] | None = None) -> int:
    args = build_oob_parser().parse_args(argv)
    store = OOBEventStore(args.event_log)
    http = ThreadingHTTPServer((args.listen, args.http_port), _http_handler(store))
    dns = make_dns_server(args.listen, args.dns_port, store, args.domain, args.answer_ip)
    http_thread = threading.Thread(target=http.serve_forever, daemon=True)
    dns_thread = threading.Thread(target=dns.serve_forever, daemon=True)
    http_thread.start()
    dns_thread.start()

    http_port = http.server_address[1]
    dns_port = dns.server_address[1]
    print(
        f"headerproof-oob: http={args.listen}:{http_port} "
        f"dns={args.listen}:{dns_port} domain={args.domain}",
        flush=True,
    )
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        http.shutdown()
        dns.shutdown()
        http.server_close()
        dns.server_close()
    return 0
