from __future__ import annotations

import argparse
import concurrent.futures
import secrets
import threading
from collections.abc import Sequence
from typing import Any
from urllib import parse

from .constants import SCHEMA_VERSION, SEVERITY_ORDER
from .coverage import CoverageTracker
from .detectors import (
    analyze_content_param,
    analyze_cors_probe,
    analyze_crlf_probe,
    analyze_csrf,
    analyze_header_probe,
    analyze_oob_header_probe,
    canary_locations,
    default_header_probe_names,
    default_origin_variants,
    header_probe_value,
)
from .discovery import (
    BASELINE_SAMPLES,
    BATCH_SIZE,
    DISCOVERY_HEADERS,
    MAX_DISCOVERED_HEADERS,
    MAX_DISCOVERY_REQUESTS,
    DiscoveredHeader,
    DiscoveryDecision,
    build_discovery_baseline,
    dedupe_candidates,
    discovery_batches,
    isolate_candidates,
    response_differs,
    update_discovery_baseline,
)
from .evidence import make_signal, signal_passes_fp_filter
from .input import add_query, add_raw_query
from .models import HttpSnapshot, ProbeState
from .oob import callback_host, new_oob_token, wait_for_event
from .templates import (
    extract_http_template_evidence,
    http_template_context,
    http_template_matches,
    render_template_value,
    templates_for_request,
)
from .transport import HttpClient, UrlBudget, snapshot_summary
from .ui import emit_live_alert


def scan_url(url: str, args: argparse.Namespace) -> dict[str, Any]:
    checks = args.enabled_checks
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "result",
        "url": url,
        "status": "pending",
        "time_budget": {"seconds": args.url_timeout, "elapsed_ms": 0},
        "baseline": None,
        "probes": [],
        "observations": [],
        "signals": [],
        "filtered_signals": 0,
        "duplicate_signals": 0,
        "errors": [],
        "coverage": [],
    }

    budget = UrlBudget(args.url_timeout)
    coverage = CoverageTracker()
    parsed = parse.urlsplit(url)
    hostname = parsed.hostname or ""
    save_body = args.save_body_samples
    timeout_recorded = False
    result_lock = threading.Lock()

    def new_canary() -> str:
        return f"pa-scan-{secrets.token_hex(6)}"

    def new_probe_id(prefix: str) -> str:
        return f"{prefix}-{secrets.token_hex(5)}"

    def mark_timeout() -> None:
        nonlocal timeout_recorded
        with result_lock:
            if not timeout_recorded:
                result["errors"].append(
                    {
                        "error_type": "url_timeout",
                        "message": f"url-timeout reached after {args.url_timeout:.2f}s",
                    }
                )
                timeout_recorded = True
            result["status"] = "partial_timeout"

    def fetch_budgeted(
        request_url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        probe_id: str = "",
        role: str = "",
        detector: str = "",
        coverage_sequence: int = 0,
        request_client: HttpClient | None = None,
        client_context: str = "",
    ) -> HttpSnapshot | None:
        if not coverage_sequence:
            coverage_sequence = coverage.plan("probe", detector or role or "unknown", probe_id, role or "probe")
        if budget.expired():
            mark_timeout()
            coverage.transition(coverage_sequence, "skipped", reason="url_budget_exhausted")
            with result_lock:
                result["probes"].append(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "record_type": "probe",
                        "sequence": coverage_sequence,
                        "probe_id": probe_id or new_probe_id("probe"),
                        "url": request_url,
                        "detector": detector or role or "unknown",
                        "role": role or "probe",
                        "status": "skipped",
                        "client_context": client_context or "default",
                        "exchange": None,
                        "error": "url_budget_exhausted",
                    }
                )
            return None
        coverage.transition(coverage_sequence, "attempted")
        active_client = request_client or HttpClient(
            args.timeout,
            args.max_body,
            args.follow_redirects,
            args.delay,
        )
        merged_headers = dict(getattr(args, "request_headers", {}))
        merged_headers.update(headers or {})
        request_headers = merged_headers or None
        context = client_context or f"{probe_id or role}-{coverage_sequence}"
        rate_limiter = getattr(args, "rate_limiter", None)
        if rate_limiter is not None:
            rate_limiter.wait(request_url)
        semaphore = getattr(args, "request_semaphore", None)
        if semaphore is None:
            snap = active_client.fetch(
                request_url,
                method,
                request_headers,
                timeout=budget.request_timeout(args.timeout),
                client_context=context,
            )
        else:
            with semaphore:
                snap = active_client.fetch(
                    request_url,
                    method,
                    request_headers,
                    timeout=budget.request_timeout(args.timeout),
                    client_context=context,
                )
        probe_status: ProbeState = "error" if snap.error else "completed"
        coverage.transition(coverage_sequence, probe_status, error=snap.error)
        with result_lock:
            result["probes"].append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "record_type": "probe",
                    "sequence": coverage_sequence,
                    "probe_id": probe_id or new_probe_id("probe"),
                    "url": request_url,
                    "detector": detector or role or "unknown",
                    "role": role or "probe",
                    "status": probe_status,
                    "client_context": context,
                    "exchange": snapshot_summary(snap, save_body=save_body),
                    "error": snap.error,
                }
            )
            if snap.error:
                result["errors"].append(
                    {
                        "error_type": "request_error",
                        "message": snap.error,
                        "probe_id": probe_id,
                        "detector": detector or role or "unknown",
                        "role": role or "probe",
                        "url": request_url,
                    }
                )
        if budget.expired():
            mark_timeout()
        return snap

    baseline_sequence = coverage.plan("probe", "baseline", "baseline", "baseline")
    baseline = fetch_budgeted(
        url,
        probe_id="baseline",
        role="baseline",
        detector="baseline",
        coverage_sequence=baseline_sequence,
        client_context="baseline",
    )
    if baseline is None:
        result["time_budget"]["elapsed_ms"] = int(budget.elapsed() * 1000)
        result["coverage"] = coverage.records()
        return result
    result["baseline"] = snapshot_summary(baseline, save_body=save_body)
    if baseline.error:
        result["status"] = "error"
        result["time_budget"]["elapsed_ms"] = int(budget.elapsed() * 1000)
        result["coverage"] = coverage.records()
        return result

    options: HttpSnapshot | None = None
    if not args.no_preflight and ({"cors", "csrf"} & checks):
        preflight_sequence = coverage.plan("probe", "csrf", "preflight", "preflight")
        options = fetch_budgeted(
            url,
            "OPTIONS",
            probe_id="preflight",
            role="preflight",
            detector="csrf",
            coverage_sequence=preflight_sequence,
            client_context="preflight",
        )

    signals: list[dict[str, Any]] = []
    seen_signal_keys: set[tuple[str, str, str, str]] = set()

    def add_signals(new_signals: list[dict[str, Any]]) -> None:
        for signal in new_signals:
            observation = {
                **signal,
                "record_type": "observation",
                "url": url,
                "kept": False,
                "filter_mode": args.fp_mode,
                "filter_reason": "",
            }
            if not signal_passes_fp_filter(signal, args.fp_mode):
                observation["filter_reason"] = "technical_evidence_gate_not_met"
                result["observations"].append(observation)
                result["filtered_signals"] += 1
                continue
            severity_filter: set[str] = set(getattr(args, "severity_filter", set()))
            if severity_filter and signal.get("severity", "info") not in severity_filter:
                observation["filter_reason"] = "severity_filtered"
                result["observations"].append(observation)
                result["filtered_signals"] += 1
                continue
            signal_evidence = signal.get("evidence", {})
            signal_key = (
                signal.get("check", ""),
                signal.get("type", ""),
                signal_evidence.get("probe_header", ""),
                signal_evidence.get("origin", ""),
            )
            if args.fp_mode == "strict" and signal_key in seen_signal_keys:
                observation["filter_reason"] = "duplicate_type_in_strict_mode"
                result["observations"].append(observation)
                result["duplicate_signals"] += 1
                continue
            seen_signal_keys.add(signal_key)
            observation["kept"] = True
            observation["filter_reason"] = "kept_as_finding"
            result["observations"].append(observation)
            signals.append(signal)
            emit_live_alert(url, signal, args)

    if "csrf" in checks:
        add_signals(analyze_csrf(baseline, options, save_body))

    def run_probe_tasks(tasks: list[tuple[str, str, int, Any]]) -> None:
        if not tasks:
            return
        if budget.expired():
            mark_timeout()
            for _name, _detector, detector_sequence, _task in tasks:
                coverage.transition(detector_sequence, "skipped", reason="url_budget_exhausted_before_submit")
            return

        max_workers = max(1, min(args.per_url_concurrency, len(tasks)))
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        futures: dict[concurrent.futures.Future, tuple[str, int]] = {}
        try:
            for name, _detector, detector_sequence, task in tasks:
                coverage.transition(detector_sequence, "attempted")
                futures[executor.submit(task)] = (name, detector_sequence)

            while futures:
                remaining = budget.remaining()
                if remaining <= 0:
                    mark_timeout()
                    break
                done, _ = concurrent.futures.wait(
                    futures,
                    timeout=remaining,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                if not done:
                    mark_timeout()
                    break
                for future in done:
                    name, detector_sequence = futures.pop(future)
                    try:
                        add_signals(future.result())
                        coverage.transition(detector_sequence, "completed")
                    except Exception as exc:  # noqa: BLE001 - keep the URL scan moving.
                        coverage.transition(
                            detector_sequence,
                            "error",
                            error=f"{type(exc).__name__}: {exc}",
                        )
                        with result_lock:
                            result["errors"].append(
                                {
                                    "error_type": "detector_error",
                                    "message": f"{type(exc).__name__}: {exc}",
                                    "detector": name,
                                }
                            )
        finally:
            for future, (_name, detector_sequence) in futures.items():
                if future.cancel():
                    coverage.transition(detector_sequence, "skipped", reason="cancelled_after_url_budget")
            executor.shutdown(wait=True, cancel_futures=True)
            for future, (name, detector_sequence) in list(futures.items()):
                if future.cancelled():
                    continue
                try:
                    add_signals(future.result())
                    coverage.transition(detector_sequence, "completed")
                except Exception as exc:  # noqa: BLE001 - preserve detector failure evidence.
                    coverage.transition(detector_sequence, "error", error=f"{type(exc).__name__}: {exc}")
                    with result_lock:
                        result["errors"].append(
                            {
                                "error_type": "detector_error",
                                "message": f"{type(exc).__name__}: {exc}",
                                "detector": name,
                            }
                        )

    probe_tasks: list[tuple[str, str, int, Any]] = []

    def add_task(name: str, detector: str, task: Any) -> None:
        detector_sequence = coverage.plan("detector", detector, name, name)
        probe_tasks.append((name, detector, detector_sequence, task))

    if "cors" in checks:
        cors_canary = new_canary()
        for origin in default_origin_variants(hostname, cors_canary, args.origin, args.origin_mode):
            cors_probe_id = new_probe_id("cors")
            cors_sequence = coverage.plan("probe", "cors", cors_probe_id, "cors")

            def cors_task(
                origin: str = origin,
                probe_id: str = cors_probe_id,
                probe_sequence: int = cors_sequence,
            ) -> list[dict[str, Any]]:
                cors_resp = fetch_budgeted(
                    url,
                    headers={"Origin": origin},
                    probe_id=probe_id,
                    role="cors",
                    detector="cors",
                    coverage_sequence=probe_sequence,
                    client_context=f"{probe_id}:cors",
                )
                if cors_resp is None:
                    return []
                return analyze_cors_probe(origin, cors_resp, save_body)

            add_task(f"cors:{origin}", "cors", cors_task)
            if not args.no_preflight:
                cors_preflight_id = new_probe_id("cors-preflight")
                cors_preflight_sequence = coverage.plan(
                    "probe",
                    "cors",
                    cors_preflight_id,
                    "cors-preflight",
                )

                def preflight_task(
                    origin: str = origin,
                    probe_id: str = cors_preflight_id,
                    probe_sequence: int = cors_preflight_sequence,
                ) -> list[dict[str, Any]]:
                    preflight = fetch_budgeted(
                        url,
                        "OPTIONS",
                        {
                            "Origin": origin,
                            "Access-Control-Request-Method": "POST",
                            "Access-Control-Request-Headers": "content-type,x-requested-with",
                        },
                        probe_id=probe_id,
                        role="cors-preflight",
                        detector="cors",
                        coverage_sequence=probe_sequence,
                        client_context=f"{probe_id}:preflight",
                    )
                    if preflight is None:
                        return []
                    return analyze_cors_probe(origin, preflight, save_body)

                add_task(f"cors-preflight:{origin}", "cors", preflight_task)

    if "content-spoofing" in checks:
        canary = new_canary()
        content_url = add_query(url, {args.content_param: canary})
        content_probe_id = new_probe_id("content")
        content_sequence = coverage.plan("probe", "content-spoofing", content_probe_id, "content-param")

        def content_task(
            canary: str = canary,
            content_url: str = content_url,
            probe_id: str = content_probe_id,
            probe_sequence: int = content_sequence,
        ) -> list[dict[str, Any]]:
            content_probe = fetch_budgeted(
                content_url,
                probe_id=probe_id,
                role="content-param",
                detector="content-spoofing",
                coverage_sequence=probe_sequence,
                client_context=f"{probe_id}:content",
            )
            if content_probe is None:
                return []
            return analyze_content_param(canary, content_probe, save_body)

        add_task("content-param", "content-spoofing", content_task)

    if "header-injection" in checks and not args.no_crlf:
        canary = new_canary()
        crlf_url = add_raw_query(url, "pa_crlf", f"%0d%0aX-PA-Injected%3A%20{canary}")
        crlf_probe_id = new_probe_id("crlf")
        crlf_sequence = coverage.plan("probe", "header-injection", crlf_probe_id, "crlf")

        def crlf_task(
            canary: str = canary,
            crlf_url: str = crlf_url,
            probe_id: str = crlf_probe_id,
            probe_sequence: int = crlf_sequence,
        ) -> list[dict[str, Any]]:
            crlf_probe = fetch_budgeted(
                crlf_url,
                probe_id=probe_id,
                role="crlf",
                detector="header-injection",
                coverage_sequence=probe_sequence,
                client_context=f"{probe_id}:crlf",
            )
            if crlf_probe is None:
                return []
            return analyze_crlf_probe(canary, crlf_probe, save_body)

        add_task("crlf", "header-injection", crlf_task)

    discovered_headers: list[str] = []
    discovery_proof_ids: dict[str, list[str]] = {}
    if "cache-poisoning" in checks and not args.no_cache_confirm:
        default_headers = default_header_probe_names(args.header, args.header_probe_limit)
        candidates = dedupe_candidates(DISCOVERY_HEADERS, [*default_headers, *args.header])
        discovery_marker = f"{new_canary()}.invalid"
        baseline_samples: list[HttpSnapshot] = []
        for _ in range(BASELINE_SAMPLES):
            probe_id = new_probe_id("discovery-baseline")
            discovery_url = add_query(url, {"pa_discovery": probe_id})
            sample = fetch_budgeted(
                discovery_url,
                headers={"Cache-Control": "no-cache", "Pragma": "no-cache"},
                probe_id=probe_id,
                role="discovery-baseline",
                detector="cache-poisoning",
                client_context=f"{probe_id}:discovery-baseline",
            )
            if sample is not None:
                baseline_samples.append(sample)
        discovery_baseline = build_discovery_baseline(baseline_samples)
        discovery_requests = len(baseline_samples)
        if discovery_baseline is not None and not budget.expired():
            def affects(candidate_names: Sequence[str]) -> DiscoveryDecision:
                nonlocal discovery_requests
                if discovery_requests >= MAX_DISCOVERY_REQUESTS or budget.expired():
                    return DiscoveryDecision("inconclusive", "discovery_budget_exhausted")
                probe_id = new_probe_id("discovery")
                discovery_url = add_query(url, {"pa_discovery": probe_id})
                headers = {name: discovery_marker for name in candidate_names}
                headers.update({"Cache-Control": "no-cache", "Pragma": "no-cache"})
                role = "discovery-batch" if len(candidate_names) > 1 else "discovery-singleton"
                response = fetch_budgeted(
                    discovery_url,
                    headers=headers,
                    probe_id=probe_id,
                    role=role,
                    detector="cache-poisoning",
                    client_context=f"{probe_id}:discovery",
                )
                discovery_requests += 1
                if response is None:
                    return DiscoveryDecision("inconclusive", "request_not_completed")
                decision = response_differs(discovery_baseline, response, discovery_marker)
                if len(candidate_names) == 1 and decision.outcome == "affected":
                    discovery_proof_ids.setdefault(candidate_names[0].casefold(), []).append(probe_id)
                if decision.outcome != "affected" or decision.reason == "marker_reflected":
                    return decision
                controls: list[HttpSnapshot] = []
                for _ in range(2):
                    if discovery_requests >= MAX_DISCOVERY_REQUESTS or budget.expired():
                        return DiscoveryDecision("inconclusive", "negative_control_budget_exhausted")
                    control_id = new_probe_id("discovery-control")
                    control_url = add_query(url, {"pa_discovery": control_id})
                    control = fetch_budgeted(
                        control_url,
                        headers={"Cache-Control": "no-cache", "Pragma": "no-cache"},
                        probe_id=control_id,
                        role="discovery-negative-control",
                        detector="cache-poisoning",
                        client_context=f"{control_id}:discovery-control",
                    )
                    discovery_requests += 1
                    if control is None:
                        return DiscoveryDecision("inconclusive", "negative_control_not_completed")
                    controls.append(control)
                learned = False
                for control in controls:
                    control_decision = response_differs(discovery_baseline, control, discovery_marker)
                    if control_decision.outcome == "affected":
                        learned = update_discovery_baseline(discovery_baseline, control) or learned
                if learned and response_differs(discovery_baseline, response, discovery_marker).outcome == "unaffected":
                    return DiscoveryDecision("unaffected", "natural_variance_learned")
                return decision

            discovered: list[DiscoveredHeader] = []
            evaluated_candidate_names: set[str] = set()
            truncation_reason = ""
            for batch in discovery_batches(candidates, BATCH_SIZE):
                discovered_keys = {item.name.casefold() for item in discovered}
                batch = [name for name in batch if name.casefold() not in discovered_keys]
                if not batch:
                    continue
                if budget.expired():
                    truncation_reason = "url_budget_exhausted"
                    break
                if discovery_requests >= MAX_DISCOVERY_REQUESTS:
                    truncation_reason = "discovery_request_limit"
                    break
                if len(discovered) >= MAX_DISCOVERED_HEADERS:
                    truncation_reason = "discovered_header_limit"
                    break
                remaining = MAX_DISCOVERED_HEADERS - len(discovered)
                before_requests = discovery_requests
                batch_discovered = isolate_candidates(batch, affects, limit=remaining)
                discovered.extend(batch_discovered)
                # A batch is fully evaluated only when isolation did not stop on
                # the discovered-header/request/URL budget. This is evidence
                # accounting, not a claim that every candidate was singleton-probed.
                if (
                    len(discovered) < MAX_DISCOVERED_HEADERS
                    and discovery_requests < MAX_DISCOVERY_REQUESTS
                    and not budget.expired()
                ):
                    evaluated_candidate_names.update(name.casefold() for name in batch)
                elif discovery_requests == before_requests:
                    truncation_reason = truncation_reason or "discovery_not_progressed"
                    break
                else:
                    truncation_reason = (
                        "url_budget_exhausted" if budget.expired()
                        else "discovery_request_limit" if discovery_requests >= MAX_DISCOVERY_REQUESTS
                        else "discovered_header_limit"
                    )
                    break
            discovered_headers = [item.name for item in discovered]
            result["discovery"] = {
                "baseline_samples": len(baseline_samples),
                "candidate_count": len(candidates),
                "evaluated_candidates": len(evaluated_candidate_names),
                "requests": discovery_requests,
                "discovered_headers": [
                    {"name": item.name, "reason": item.reason} for item in discovered
                ],
                "truncated": bool(truncation_reason),
                "truncation_reason": truncation_reason or None,
                "request_limit_reached": discovery_requests >= MAX_DISCOVERY_REQUESTS,
                "cache_isolation": "unverified_during_discovery",
            }
        else:
            result["discovery"] = {
                "baseline_samples": len(baseline_samples),
                "candidate_count": len(candidates),
                "evaluated_candidates": 0,
                "requests": discovery_requests,
                "discovered_headers": [],
                "truncated": False,
                "truncation_reason": None,
                "request_limit_reached": discovery_requests >= MAX_DISCOVERY_REQUESTS,
                "status": "baseline_unavailable",
                "cache_isolation": "unverified_during_discovery",
            }

    if {"header-injection", "cache-poisoning", "content-spoofing"} & checks:
        header_names = dedupe_candidates(
            [*default_header_probe_names(args.header, args.header_probe_limit), *discovered_headers]
        )
        for header_name in header_names:
            probe_id = new_probe_id("header")
            oob_capable = header_name.lower() in {"x-forwarded-host", "x-host", "x-forwarded-server", "forwarded"}
            oob_enabled = bool(args.oob_api and args.oob_domain and oob_capable)
            canary = new_oob_token() if oob_enabled else new_canary()
            oob_host = callback_host(canary, args.oob_domain) if oob_enabled else ""
            header_value = header_probe_value(header_name, canary, oob_host)
            cache_url = add_query(url, {"pa_cb": probe_id})
            control_url = add_query(url, {"pa_cb": f"{probe_id}-control"})
            cache_confirmation = "cache-poisoning" in checks and not args.no_cache_confirm
            clean_sequence = (
                coverage.plan("probe", "cache-poisoning", f"{probe_id}-clean-before", "cache-clean-before")
                if cache_confirmation
                else 0
            )
            poison_sequence = coverage.plan("probe", "header-injection", f"{probe_id}-poison", "cache-poison")
            victim_sequence = (
                coverage.plan("probe", "cache-poisoning", f"{probe_id}-victim", "cache-victim")
                if cache_confirmation
                else 0
            )
            control_sequence = (
                coverage.plan("probe", "cache-poisoning", f"{probe_id}-fresh-control", "cache-fresh-control")
                if cache_confirmation
                else 0
            )

            def header_task(
                header_name: str = header_name,
                probe_id: str = probe_id,
                canary: str = canary,
                header_value: str = header_value,
                cache_url: str = cache_url,
                control_url: str = control_url,
                poison_sequence: int = poison_sequence,
                clean_sequence: int = clean_sequence,
                victim_sequence: int = victim_sequence,
                control_sequence: int = control_sequence,
                cache_confirmation: bool = cache_confirmation,
                oob_enabled: bool = oob_enabled,
            ) -> list[dict[str, Any]]:
                clean_before = None
                if cache_confirmation:
                    clean_before = fetch_budgeted(
                        cache_url,
                        headers={"Cache-Control": "no-cache", "Pragma": "no-cache"},
                        probe_id=f"{probe_id}-clean-before",
                        role="cache-clean-before",
                        detector="cache-poisoning",
                        coverage_sequence=clean_sequence,
                        client_context=f"{probe_id}:clean-before",
                    )
                probe = fetch_budgeted(
                    cache_url,
                    headers={header_name: header_value},
                    probe_id=f"{probe_id}-poison",
                    role="cache-poison",
                    detector="header-injection",
                    coverage_sequence=poison_sequence,
                    client_context=f"{probe_id}:poison",
                )
                if probe is None:
                    if cache_confirmation:
                        coverage.transition(victim_sequence, "skipped", reason="poison_probe_not_completed")
                        coverage.transition(control_sequence, "skipped", reason="poison_probe_not_completed")
                    return []
                victim: HttpSnapshot | None = None
                control: HttpSnapshot | None = None
                if cache_confirmation and canary_locations(probe, canary):
                    victim = fetch_budgeted(
                        cache_url,
                        probe_id=f"{probe_id}-victim",
                        role="cache-victim",
                        detector="cache-poisoning",
                        coverage_sequence=victim_sequence,
                        client_context=f"{probe_id}:victim",
                    )
                    control = fetch_budgeted(
                        control_url,
                        probe_id=f"{probe_id}-fresh-control",
                        role="cache-fresh-control",
                        detector="cache-poisoning",
                        coverage_sequence=control_sequence,
                        client_context=f"{probe_id}:fresh-control",
                    )
                elif cache_confirmation:
                    coverage.transition(victim_sequence, "skipped", reason="poison_response_did_not_reflect_canary")
                    coverage.transition(control_sequence, "skipped", reason="poison_response_did_not_reflect_canary")

                found = analyze_header_probe(
                    header_name,
                    canary,
                    probe_id,
                    clean_before,
                    probe,
                    victim,
                    control,
                    save_body,
                )
                discovery_ids = discovery_proof_ids.get(header_name.casefold(), [])
                if discovery_ids:
                    for signal in found:
                        evidence = signal.get("evidence")
                        if isinstance(evidence, dict):
                            evidence["discovery_trace"] = {
                                "header": header_name,
                                "probe_ids": list(discovery_ids),
                                "role": "discovery-singleton",
                            }
                if oob_enabled and budget.remaining() > 0:
                    events = wait_for_event(args.oob_api, canary, timeout=min(args.oob_wait, budget.remaining()))
                    found.extend(analyze_oob_header_probe(header_name, canary, events, probe, save_body))
                return found

            add_task(f"header:{header_name}", "header-injection", header_task)

    # Generic declarative HTTP templates are intentionally constrained to same-target,
    # safe-method probes. This lets a new header-driven detector ship as template data
    # without adding Python detector code.
    for template in templates_for_request("http"):
        template_id = str(template["id"])
        detector = str(template["check"])
        request_spec = template["request"]
        finding_spec = template["finding"]
        canary = new_canary()
        variables = {"canary": canary, "hostname": hostname, "url": url}
        query = {
            str(name): render_template_value(str(value), variables)
            for name, value in request_spec.get("query", {}).items()
        }
        request_url = add_query(url, query) if query else url
        request_headers = {
            str(name): render_template_value(str(value), variables)
            for name, value in request_spec.get("headers", {}).items()
        }
        method = str(request_spec.get("method", "GET")).upper()
        probe_id = new_probe_id("template")
        probe_sequence = coverage.plan("probe", detector, probe_id, template_id)

        def declarative_template_task(
            template: dict[str, Any] = template,
            template_id: str = template_id,
            detector: str = detector,
            variables: dict[str, str] = variables,
            request_url: str = request_url,
            request_headers: dict[str, str] = request_headers,
            method: str = method,
            probe_id: str = probe_id,
            probe_sequence: int = probe_sequence,
            finding_spec: dict[str, Any] = finding_spec,
        ) -> list[dict[str, Any]]:
            snap = fetch_budgeted(
                request_url,
                method,
                request_headers,
                probe_id=probe_id,
                role=template_id,
                detector=detector,
                coverage_sequence=probe_sequence,
                client_context=f"{probe_id}:template",
            )
            if snap is None:
                return []
            context = http_template_context(snap, variables)
            if not http_template_matches(template, context, variables):
                return []
            evidence = extract_http_template_evidence(template, context)
            evidence["template_id"] = template_id
            return [
                make_signal(
                    detector,
                    template_id,
                    str(finding_spec["severity"]),
                    str(finding_spec["confidence"]),
                    str(finding_spec["title"]),
                    evidence,
                    snap,
                    str(finding_spec.get("next_step", "")),
                    save_body,
                )
            ]

        add_task(f"template:{template_id}", detector, declarative_template_task)

    run_probe_tasks(probe_tasks)

    signals.sort(
        key=lambda item: (
            {"observed": 1, "reproduced": 2, "cross_request_confirmed": 3}.get(
                item.get("assessment", {}).get("state", "observed"),
                0,
            ),
            SEVERITY_ORDER.get(item["severity"], 0),
        ),
        reverse=True,
    )
    result["signals"] = signals
    result["probes"].sort(key=lambda item: item.get("sequence", 0))
    result["coverage"] = coverage.records()
    result["time_budget"]["elapsed_ms"] = int(budget.elapsed() * 1000)
    if result["status"] == "partial_timeout":
        pass
    elif result["errors"]:
        result["status"] = "partial_error"
    else:
        result["status"] = "scanned"
    return result
