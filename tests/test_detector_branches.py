from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import header_active_scan  # noqa: E402
from headerproof.detectors import (  # noqa: E402
    analyze_content_param,
    analyze_cors_probe,
    analyze_csrf,
    analyze_header_probe,
    cache_hit_progressed,
    cache_indicators,
    default_header_probe_names,
    default_origin_variants,
    has_cache_hit_header,
    header_int,
    header_probe_value,
    looks_cacheable,
    parse_cookie,
    parse_methods,
    request_contains_canary,
    shared_cache_hit_markers,
    snapshot_completed,
    snippet_around,
)
from headerproof.evidence import (  # noqa: E402
    assess_signal,
    evidence_locations,
    make_signal,
    response_status_from_signal,
    signal_passes_fp_filter,
    verification_template,
)


def snap(
    headers: dict[str, str] | None = None,
    *,
    body: str = "",
    status: int | None = 200,
    request_headers: dict[str, str] | None = None,
    url: str = "http://example.test/path",
    context: str = "client",
    error: str = "",
) -> header_active_scan.HttpSnapshot:
    raw = body.encode()
    return header_active_scan.HttpSnapshot(
        "GET",
        url,
        request_headers or {},
        status=status,
        headers={name.lower(): [value] for name, value in (headers or {}).items()},
        body_sample=body,
        body_len=len(raw),
        body_sample_len=len(raw),
        body_sha256=hashlib.sha256(raw).hexdigest(),
        error=error,
        client_context=context,
    )


def signal_for(
    signal_type: str,
    evidence: dict[str, object] | None = None,
    *,
    status: int | None = 200,
) -> dict[str, object]:
    exchange: object = {"response": {"status": status}}
    return {
        "type": signal_type,
        "severity": "high",
        "confidence": "high",
        "evidence": evidence or {},
        "exchange": exchange,
    }


def test_cache_utility_branch_matrix() -> None:
    indicators = cache_indicators(
        snap(
            {
                "Cache-Control": "private, no-store",
                "Age": "4",
                "Expires": "soon",
                "ETag": '"x"',
                "X-Cache": "HIT",
                "X-Cache-Hits": "2",
                "Cache-Status": "hit",
                "CF-Cache-Status": "HIT",
                "CDN-Cache-Control": "max-age=3",
                "Surrogate-Control": "max-age=3",
                "Akamai-Cache-Status": "hit",
                "Server-Timing": "cdn-cache;desc=HIT",
            }
        )
    )
    assert "private" in indicators
    assert "no-store" in indicators
    assert looks_cacheable(snap({"Cache-Control": "public"}, status=500))[0] is False
    assert looks_cacheable(snap({"Cache-Control": "private, max-age=30"}))[0] is False
    assert looks_cacheable(snap({"Cache-Control": "public, max-age=30"}))[0] is True
    assert looks_cacheable(snap({}))[0] is False

    markers = shared_cache_hit_markers(
        [
            "age=4",
            "age=0",
            "age=none",
            "x-cache-hits=2",
            "x-cache-hits=0",
            "x-cache=HIT",
            "x-cache=HIT, MISS",
            "x-cache-hits=0, 3",
            "cf-cache-status=DYNAMIC",
            "cf-cache-status=STALE",
            "cf-cache-status=UPDATING",
            "cf-cache-status=REVALIDATED",
            "cache-status=revalidated",
            "unknown=hit",
        ]
    )
    assert markers == [
        "age=4",
        "x-cache-hits=2",
        "x-cache=HIT",
        "x-cache=HIT, MISS",
        "x-cache-hits=0, 3",
        "cf-cache-status=STALE",
        "cf-cache-status=UPDATING",
        "cf-cache-status=REVALIDATED",
        "cache-status=revalidated",
    ]
    assert header_int(None, "age") == 0
    assert header_int(snap({"Age": "none"}), "age") == 0
    assert has_cache_hit_header(None) is False
    assert has_cache_hit_header(snap({"X-Cache": "HIT"})) is True
    assert has_cache_hit_header(snap({"X-Cache": "HIT, MISS"})) is True
    assert has_cache_hit_header(snap({"CF-Cache-Status": "STALE"})) is True
    assert has_cache_hit_header(snap({"CF-Cache-Status": "UPDATING"})) is True
    assert has_cache_hit_header(snap({"CF-Cache-Status": "DYNAMIC"})) is False
    assert cache_hit_progressed(None, None, None) is False
    assert cache_hit_progressed(snap({"Age": "0"}), snap({"Age": "0"}), snap({"X-Cache": "HIT"})) is True
    assert cache_hit_progressed(snap({"Age": "1"}), snap({"Age": "2"}), snap({"Age": "3"})) is True
    assert cache_hit_progressed(snap({"Age": "3"}), snap({"Age": "2"}), snap({"Age": "3"})) is False


def test_snapshot_and_parser_branch_matrix() -> None:
    canary = "pa-scan-aabbcc"
    assert snapshot_completed(None) is False
    assert snapshot_completed(snap(status=None)) is False
    assert snapshot_completed(snap(error="failed")) is False
    assert snapshot_completed(snap()) is True
    assert request_contains_canary(None, canary) is False
    assert request_contains_canary(snap(request_headers={"X-Test": canary}), canary) is True
    assert request_contains_canary(snap(request_headers={"X-Test": "other"}), canary) is False
    assert snippet_around("hello", "absent") == ""
    assert "\\n" in snippet_around(f"prefix\n{canary}\rpostfix", canary)
    assert parse_methods("", "get, POST PATCH") == {"GET", "POST", "PATCH"}
    assert parse_cookie("")["name"] == ""
    parsed = parse_cookie("sessionid=x; Secure; SameSite=None; Unknown=value")
    assert parsed == {"name": "sessionid", "secure": True, "samesite": "none", "likely_auth": True}
    assert parse_cookie("theme=dark")["likely_auth"] is False


def test_csrf_detector_cookie_and_method_branches() -> None:
    baseline = snap(
        {
            "Set-Cookie": "sessionid=x; SameSite=None",
            "Allow": "GET, POST",
        }
    )
    baseline.headers["set-cookie"].append("theme=dark")
    baseline.headers["set-cookie"].append("pref=x; SameSite=None; Secure")
    options = snap({"Access-Control-Allow-Methods": "PUT, DELETE"})
    types = {item["type"] for item in analyze_csrf(baseline, options, False)}
    assert types == {
        "csrf_cookie_cross_site_auth",
        "cookie_samesite_none_without_secure",
        "csrf_cookie_samesite_missing",
        "csrf_cookie_auth_unsafe_methods_exposed",
    }
    assert analyze_csrf(snap({"Set-Cookie": "theme=x; SameSite=Lax"}), None, False) == []


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({}, set()),
        ({"Access-Control-Allow-Origin": "https://evil.test"}, {"cors_arbitrary_origin_reflection"}),
        (
            {
                "Access-Control-Allow-Origin": "https://evil.test",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "POST",
            },
            {"cors_arbitrary_origin_with_credentials"},
        ),
        ({"Access-Control-Allow-Origin": "*"}, {"cors_wildcard_origin"}),
        (
            {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
            {"cors_wildcard_origin"},
        ),
        ({"Access-Control-Allow-Origin": "null"}, {"cors_arbitrary_origin_reflection"}),
    ],
)
def test_cors_detector_branch_matrix(headers: dict[str, str], expected: set[str]) -> None:
    origin = "null" if headers.get("Access-Control-Allow-Origin") == "null" else "https://evil.test"
    types = {item["type"] for item in analyze_cors_probe(origin, snap(headers), False)}
    assert expected <= types


def test_cors_cache_candidate_and_vary_suppression() -> None:
    origin = "https://evil.test"
    cache_headers = {
        "Access-Control-Allow-Origin": origin,
        "Cache-Control": "public, max-age=30",
    }
    types = {item["type"] for item in analyze_cors_probe(origin, snap(cache_headers), False)}
    assert "cors_cache_poisoning_candidate" in types
    cache_headers["Vary"] = "Accept-Encoding, Origin"
    types = {item["type"] for item in analyze_cors_probe(origin, snap(cache_headers), False)}
    assert "cors_cache_poisoning_candidate" not in types


def test_probe_variant_helpers_cover_all_value_forms() -> None:
    origins = default_origin_variants(
        "",
        "token",
        ["null", "https://custom.test", "https://custom.test"],
        "standard",
    )
    assert origins == ["https://token.invalid", "null", "https://custom.test"]
    assert default_origin_variants("target.test", "token", [], "standard")[2].endswith(".attacker.invalid")
    assert default_origin_variants("target.test", "token", [], "single") == ["https://token.invalid"]
    headers = default_header_probe_names(["X-Custom"], 2)
    assert headers == ["X-Forwarded-Host", "Forwarded", "X-Custom"]
    assert len(default_header_probe_names([], 0)) == 7
    assert header_probe_value("Forwarded", "token").startswith("for=")
    assert header_probe_value("X-Original-URL", "token") == "/token"
    assert header_probe_value("X-Rewrite-URL", "token") == "/token"
    assert header_probe_value("X-Forwarded-Prefix", "token") == "/token"
    assert header_probe_value("X-Host", "token") == "token.invalid"


def test_header_and_content_detector_negative_and_security_header_branches() -> None:
    canary = "pa-scan-aabbcc"
    assert analyze_header_probe("X-Test", canary, "p", None, snap(), None, None, False) == []

    security_header = snap(
        {
            "Location": f"https://{canary}.invalid/",
            "Cache-Control": "public, max-age=30",
        },
        request_headers={"X-Forwarded-Host": canary},
    )
    types = {
        item["type"]
        for item in analyze_header_probe("X-Forwarded-Host", canary, "p", None, security_header, None, None, False)
    }
    assert types == {"header_poisoning_candidate", "unkeyed_header_cache_poisoning_candidate"}

    binary_body = snap({"Content-Type": "image/png"}, body=canary)
    types = {
        item["type"]
        for item in analyze_header_probe("X-Test", canary, "p", None, binary_body, None, None, False)
    }
    assert "header_based_content_spoofing" not in types

    assert analyze_content_param(canary, snap(), False) == []
    content = snap({"Content-Type": "text/plain", "X-Reflect": canary}, body=canary)
    assert {item["type"] for item in analyze_content_param(canary, content, False)} == {
        "query_parameter_content_reflection",
        "query_parameter_header_reflection",
    }
    non_text = snap({"Content-Type": "image/png"}, body=canary)
    assert analyze_content_param(canary, non_text, False) == []


@pytest.mark.parametrize(
    "signal_type",
    [
        "cors_arbitrary_origin_with_credentials",
        "cors_arbitrary_origin_reflection",
        "cors_wildcard_origin",
        "cors_cache_poisoning_candidate",
        "csrf_cookie_samesite_missing",
        "csrf_cookie_cross_site_auth",
        "csrf_cookie_auth_unsafe_methods_exposed",
        "cookie_samesite_none_without_secure",
        "header_poisoning_candidate",
        "header_reflection_candidate",
        "header_based_content_spoofing",
        "unkeyed_header_cache_poisoning_candidate",
        "query_parameter_content_reflection",
        "query_parameter_header_reflection",
    ],
)
def test_assessment_observation_branches(signal_type: str) -> None:
    assessment = assess_signal(signal_for(signal_type, {"likely_auth_cookie": True}))
    assert assessment["state"] == "observed"
    assert assessment["technical_gate"] == "failed"
    assert assessment["missing_proof"]


def test_assessment_cache_crlf_and_invalid_exchange_branches() -> None:
    cache = assess_signal(
        signal_for(
            "cache_poisoning_shared_cache_confirmed",
            {"shared_cache_confirmed": True, "state_machine_checks": {"all_stages": True}},
        )
    )
    assert cache["state"] == "cross_request_confirmed"
    assert cache["technical_gate"] == "passed"

    reproduced = assess_signal(
        signal_for(
            "cache_poisoning_cross_request_reproduction",
            {"shared_cache_confirmed": False, "state_machine_checks": "invalid"},
        )
    )
    assert reproduced["state"] == "reproduced"
    assert reproduced["technical_gate"] == "failed"

    exact = assess_signal(signal_for("response_splitting_crlf_candidate", {"injected_header_seen": True}))
    assert exact["technical_gate"] == "passed"
    missing_status = assess_signal(
        signal_for("response_splitting_crlf_candidate", {"injected_header_seen": True}, status=None)
    )
    assert missing_status["technical_gate"] == "failed"
    weak = assess_signal(signal_for("response_splitting_crlf_candidate", {"injected_header_seen": False}))
    assert weak["technical_gate"] == "failed"

    assert response_status_from_signal({"exchange": []}) is None
    assert response_status_from_signal({"exchange": {"response": []}}) is None
    assert response_status_from_signal({"exchange": {"response": {"status": "200"}}}) is None
    assert evidence_locations({"locations": "bad", "poison_locations": [1, {"where": "body"}]}) == [
        {"where": "body"}
    ]


def test_templates_make_signal_and_filter_branches() -> None:
    for signal_type in (
        "cors_test",
        "csrf_test",
        "cookie_test",
        "cache_test",
        "crlf_test",
        "header_test",
        "content_test",
        "unknown",
    ):
        assert verification_template(signal_type)["report_gate"]

    with pytest.raises(ValueError, match="no validated template"):
        make_signal("test", "unknown", "info", "low", "title", {})
    with pytest.raises(ValueError, match="detector/template check mismatch"):
        make_signal("wrong-check", "response_splitting_crlf_candidate", "high", "high", "title", {})

    def filter_signal(
        signal_type: str,
        *,
        gate: str = "passed",
        state: str = "reproduced",
        severity: str = "high",
        confidence: str = "high",
        evidence: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return {
            "type": signal_type,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence or {},
            "assessment": {"technical_gate": gate, "state": state},
        }

    assert signal_passes_fp_filter(
        filter_signal("csrf_cookie_samesite_missing", evidence={"likely_auth_cookie": False}),
        "balanced",
    ) is False
    assert signal_passes_fp_filter(filter_signal("cookie_samesite_none_without_secure"), "balanced") is True
    assert signal_passes_fp_filter(filter_signal("cookie_samesite_none_without_secure"), "strict") is False
    assert signal_passes_fp_filter(filter_signal("cors_wildcard_origin"), "balanced") is True
    assert signal_passes_fp_filter(filter_signal("cors_wildcard_origin"), "strict") is False
    assert signal_passes_fp_filter(filter_signal("header_reflection_candidate"), "strict") is False
    assert signal_passes_fp_filter(filter_signal("response_splitting_crlf_candidate", severity="low"), "strict") is False
    assert signal_passes_fp_filter(
        filter_signal("response_splitting_crlf_candidate", confidence="low"),
        "strict",
    ) is False
    assert signal_passes_fp_filter(filter_signal("response_splitting_crlf_candidate"), "strict") is True


@pytest.mark.parametrize("name", ["X-LiteSpeed-Cache", "X-LSADC-Cache", "X-QC-Cache"])
def test_litespeed_family_cache_headers_record_exact_hit_evidence(name: str) -> None:
    indicators = cache_indicators(snap({name: "hit"}))
    expected = f"{name.lower()}=hit"
    assert expected in indicators
    assert shared_cache_hit_markers(indicators) == [expected]
    assert looks_cacheable(snap({name: "hit"}))[0] is True


@pytest.mark.parametrize(
    "value",
    ["miss", "bypass", "hit-ish", "not-hit", "hit, miss", "cache-hit", ""],
)
def test_litespeed_cache_status_does_not_accept_ambiguous_or_non_hit_values(value: str) -> None:
    indicators = cache_indicators(snap({"X-LiteSpeed-Cache": value}))
    assert shared_cache_hit_markers(indicators) == []
