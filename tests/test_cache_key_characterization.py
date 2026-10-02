from headerproof.detectors import analyze_header_probe, cache_identity_evidence
from headerproof.models import HttpSnapshot


def snap(url: str, x_cache: str) -> HttpSnapshot:
    return HttpSnapshot(
        request_method="GET",
        request_url=url,
        request_headers={},
        status=200,
        headers={"x-cache": [x_cache]},
        client_context=url,
    )


def test_url_difference_is_not_cache_key_proof() -> None:
    evidence = cache_identity_evidence(
        snap("https://example.test/?pa_cb=a", "MISS"),
        snap("https://example.test/?pa_cb=b", "MISS"),
    )
    assert evidence["request_urls_differ"] is True
    assert evidence["relationship"] == "unverified"


def test_second_candidate_hit_rejects_fresh_cache_identity_claim() -> None:
    evidence = cache_identity_evidence(
        snap("https://example.test/?pa_cb=a", "MISS"),
        snap("https://example.test/?pa_cb=b", "HIT"),
        snap("https://example.test/?pa_cb=a", "HIT"),
    )
    assert evidence["relationship"] == "same_or_unverified"
    assert evidence["second_hit_markers"] == ["x-cache=HIT"]


def test_reference_hit_plus_distinct_candidate_miss_is_separate_evidence() -> None:
    evidence = cache_identity_evidence(
        snap("https://example.test/?pa_cb=a", "MISS"),
        snap("https://example.test/?pa_cb=b", "MISS"),
        snap("https://example.test/?pa_cb=a", "HIT"),
    )
    assert evidence["relationship"] == "separate"
    assert evidence["reference_hit_markers"] == ["x-cache=HIT"]
    assert "reference_object_hit_while_second_candidate_not_hit" in evidence["reasons"]


def test_missing_snapshot_is_unverified() -> None:
    evidence = cache_identity_evidence(None, snap("https://example.test/?pa_cb=b", "MISS"))
    assert evidence == {
        "relationship": "unverified",
        "request_urls_differ": False,
        "reasons": ["missing_snapshot"],
    }

CANARY = "pa-scan-cache-key-proof"


def cache_snap(url: str, body: str, x_cache: str, context: str, request_headers: dict[str, str] | None = None) -> HttpSnapshot:
    return HttpSnapshot(
        request_method="GET",
        request_url=url,
        request_headers=request_headers or {},
        status=200,
        reason="OK",
        headers={
            "content-type": ["text/plain"],
            "cache-control": ["public, max-age=120"],
            "x-cache": [x_cache],
        },
        body_sample=body,
        body_len=len(body.encode()),
        body_sample_len=len(body.encode()),
        client_context=context,
    )


def cache_signals(control_cache: str) -> list[dict[str, object]]:
    cache_url = "https://fixture.test/v?pa_cb=probe"
    control_url = "https://fixture.test/v?pa_cb=control"
    return analyze_header_probe(
        "X-Forwarded-Host",
        CANARY,
        "probe",
        cache_snap(cache_url, "origin", "MISS", "clean"),
        cache_snap(cache_url, f"poison {CANARY}", "MISS", "poison", {"X-Forwarded-Host": CANARY}),
        cache_snap(cache_url, f"poison {CANARY}", "HIT", "victim"),
        cache_snap(
            control_url,
            "origin" if control_cache == "MISS" else f"poison {CANARY}",
            control_cache,
            "control",
        ),
        False,
    )


def test_distinct_query_with_fresh_control_can_pass_cache_key_gate() -> None:
    confirmed = [item for item in cache_signals("MISS") if item["type"] == "cache_poisoning_shared_cache_confirmed"]
    assert len(confirmed) == 1
    evidence = confirmed[0]["evidence"]
    assert evidence["state_machine_checks"]["cache_key_relationship_valid"] is True
    assert evidence["cache_key_evidence"]["relationship"] == "separate"


def test_query_ignored_by_cache_cannot_pass_cache_key_gate() -> None:
    signals = cache_signals("HIT")
    assert not any(item["type"] == "cache_poisoning_shared_cache_confirmed" for item in signals)
    reproduced = [item for item in signals if item["type"] == "cache_poisoning_cross_request_reproduction"]
    assert len(reproduced) == 1
    evidence = reproduced[0]["evidence"]
    assert evidence["state_machine_checks"]["cache_key_relationship_valid"] is False
    assert evidence["cache_key_evidence"]["relationship"] == "same_or_unverified"
    assert evidence["cache_key_evidence"]["second_hit_markers"] == ["x-cache=HIT"]
