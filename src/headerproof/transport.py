from __future__ import annotations

import hashlib
import re
import socket
import ssl
import threading
import time
from typing import Any, Protocol
from urllib import error, parse, request

from .constants import VERSION
from .models import ExchangeEvidence, HttpSnapshot


class ReadableBody(Protocol):
    def read(self, size: int = -1) -> bytes: ...


class NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class HostRateLimiter:
    """Thread-safe per-host request pacing."""

    def __init__(self, requests_per_second: float) -> None:
        self.interval = 0.0 if requests_per_second <= 0 else 1.0 / requests_per_second
        self._lock = threading.Lock()
        self._next_allowed: dict[str, float] = {}

    def wait(self, url: str) -> None:
        if self.interval <= 0:
            return
        host = (parse.urlsplit(url).hostname or "").lower()
        if not host:
            return
        with self._lock:
            now = time.monotonic()
            ready = self._next_allowed.get(host, now)
            delay = max(0.0, ready - now)
            self._next_allowed[host] = max(now, ready) + self.interval
        if delay > 0:
            time.sleep(delay)


class UrlBudget:
    def __init__(self, seconds: float) -> None:
        self.seconds = max(0.1, seconds)
        self.started = time.monotonic()

    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def remaining(self) -> float:
        return max(0.0, self.seconds - self.elapsed())

    def expired(self) -> bool:
        return self.remaining() <= 0

    def request_timeout(self, preferred: float) -> float:
        remaining = self.remaining()
        if remaining <= 0:
            return 0.0
        return max(0.05, min(preferred, remaining))


def headers_from_message(message: Any) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    for key, value in message.items():
        headers.setdefault(key.lower(), []).append(value)
    return headers


def serialise_headers(headers: dict[str, list[str]]) -> dict[str, str | list[str]]:
    out: dict[str, str | list[str]] = {}
    for key, values in sorted(headers.items()):
        out[key] = values[0] if len(values) == 1 else values
    return out


def decode_body(raw: bytes, content_type: str) -> str:
    charset = "utf-8"
    match = re.search(r"charset=([^;\s]+)", content_type, re.I)
    if match:
        charset = match.group(1).strip("\"'")
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def consume_body(stream: ReadableBody, sample_limit: int) -> tuple[bytes, int, str, bool]:
    digest = hashlib.sha256()
    sample = bytearray()
    total = 0
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
        if len(sample) < sample_limit:
            sample.extend(chunk[: sample_limit - len(sample)])
    return bytes(sample), total, digest.hexdigest(), total > len(sample)


class HttpClient:
    def __init__(self, timeout: float, max_body: int, follow_redirects: bool, delay: float) -> None:
        self.timeout = timeout
        self.max_body = max_body
        self.delay = delay
        handlers: list[Any] = []
        if not follow_redirects:
            handlers.append(NoRedirectHandler())
        self.opener = request.build_opener(*handlers)

    def fetch(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        client_context: str = "default",
    ) -> HttpSnapshot:
        request_headers = {
            "User-Agent": f"headerproof/{VERSION}",
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        request_headers.update(headers or {})
        snap = HttpSnapshot(method, url, request_headers, client_context=client_context)
        req = request.Request(url, headers=request_headers, method=method)
        start = time.monotonic()
        effective_timeout = self.timeout if timeout is None else max(0.05, timeout)
        if self.delay > 0:
            time.sleep(min(self.delay, effective_timeout))
        try:
            with self.opener.open(req, timeout=effective_timeout) as resp:
                raw, body_len, body_sha256, body_truncated = consume_body(resp, self.max_body)
                snap.status = resp.status
                snap.reason = resp.reason
                snap.headers = headers_from_message(resp.headers)
        except error.HTTPError as exc:
            raw, body_len, body_sha256, body_truncated = consume_body(exc, self.max_body)
            snap.status = exc.code
            snap.reason = exc.reason
            snap.headers = headers_from_message(exc.headers)
        except (error.URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError) as exc:
            snap.error = f"{type(exc).__name__}: {exc}"
            raw = b""
            body_len = 0
            body_sha256 = ""
            body_truncated = False
        snap.elapsed_ms = int((time.monotonic() - start) * 1000)
        snap.body_len = body_len
        snap.body_sample_len = len(raw)
        snap.body_truncated = body_truncated
        snap.body_sha256 = body_sha256
        snap.body_sample = decode_body(raw, snap.first("content-type")) if raw else ""
        return snap


def persisted_request_headers(snap: HttpSnapshot) -> dict[str, str]:
    redactions = {name.casefold(): value for name, value in snap.persistence_redactions.items()}
    return {
        name: "<redacted>" if redactions.get(name.casefold()) == value else value
        for name, value in snap.request_headers.items()
    }


def snapshot_summary(snap: HttpSnapshot, save_body: bool = False) -> ExchangeEvidence:
    data: ExchangeEvidence = {
        "request": {
            "method": snap.request_method,
            "url": snap.request_url,
            "headers": persisted_request_headers(snap),
            "client_context": snap.client_context,
        },
        "response": {
            "status": snap.status,
            "reason": snap.reason,
            "error": snap.error,
            "elapsed_ms": snap.elapsed_ms,
            "headers": serialise_headers(snap.headers),
            "body_len": snap.body_len,
            "body_sample_len": snap.body_sample_len,
            "body_truncated": snap.body_truncated,
            "body_sha256": snap.body_sha256,
            "body_sha256_scope": "full_response",
        },
    }
    if save_body:
        data["response"]["body_sample"] = snap.body_sample
    return data
