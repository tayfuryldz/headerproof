from collections.abc import Sequence

from headerproof.discovery import (
    DiscoveryDecision,
    build_discovery_baseline,
    dedupe_candidates,
    discovery_batches,
    isolate_candidates,
    response_differs,
)
from headerproof.models import HttpSnapshot


def snap(*, status: int = 200, body: str = "", headers: dict[str, list[str]] | None = None) -> HttpSnapshot:
    return HttpSnapshot(
        request_method="GET",
        request_url="https://example.test/",
        request_headers={},
        status=status,
        headers=headers or {"content-type": ["text/plain"]},
        body_sample=body,
        body_len=len(body.encode()),
        body_sample_len=len(body.encode()),
    )


def test_baseline_learns_natural_body_length_spread() -> None:
    baseline = build_discovery_baseline([snap(body="x" * 100), snap(body="x" * 140), snap(body="x" * 180)])
    assert baseline is not None
    assert baseline.statuses == {200}
    assert baseline.min_body_len == 100
    assert baseline.max_body_len == 180
    assert baseline.length_tolerance == 160



def test_incomplete_baseline_is_not_used_for_discovery() -> None:
    assert build_discovery_baseline([snap(body="stable"), snap(body="stable")]) is None

def test_marker_reflection_is_an_explicit_discovery_signal() -> None:
    baseline = build_discovery_baseline([snap(body="stable")] * 3)
    assert baseline is not None
    assert response_differs(baseline, snap(body="stable marker-123"), "marker-123") == DiscoveryDecision(
        "affected", "marker_reflected"
    )


def test_rejection_status_is_not_discovery_signal() -> None:
    baseline = build_discovery_baseline([snap(body="stable")] * 3)
    assert baseline is not None
    assert response_differs(baseline, snap(status=431, body="too large"), "marker") == DiscoveryDecision(
        "inconclusive", "batch_rejected"
    )


def test_transport_error_is_inconclusive() -> None:
    baseline = build_discovery_baseline([snap(body="stable")] * 3)
    assert baseline is not None
    failed = snap(body="")
    failed.error = "timeout"
    assert response_differs(baseline, failed, "marker") == DiscoveryDecision(
        "inconclusive", "request_not_completed"
    )


def test_repeatable_status_change_is_discovery_signal() -> None:
    baseline = build_discovery_baseline([snap(body="stable")] * 3)
    assert baseline is not None
    assert response_differs(baseline, snap(status=201, body="stable"), "marker") == DiscoveryDecision(
        "affected", "status_changed:201"
    )


def test_body_length_outside_learned_range_is_discovery_signal() -> None:
    baseline = build_discovery_baseline([snap(body="x" * 200)] * 3)
    assert baseline is not None
    assert response_differs(baseline, snap(body="x" * 400), "marker") == DiscoveryDecision(
        "affected", "body_length_above_baseline"
    )
    assert response_differs(baseline, snap(body="x" * 20), "marker") == DiscoveryDecision(
        "affected", "body_length_below_baseline"
    )


def test_natural_variance_stays_inside_baseline() -> None:
    baseline = build_discovery_baseline([snap(body="x" * 100), snap(body="x" * 140), snap(body="x" * 180)])
    assert baseline is not None
    assert response_differs(baseline, snap(body="x" * 250), "marker").affected is False


def test_candidate_deduplication_is_case_insensitive() -> None:
    assert dedupe_candidates(["X-Test", "x-test", "X-Other"], ["x-other"]) == ["X-Test"]


def test_isolation_requires_singleton_repeat() -> None:
    calls: dict[tuple[str, ...], int] = {}

    def affects(names: Sequence[str]) -> DiscoveryDecision:
        key = tuple(names)
        calls[key] = calls.get(key, 0) + 1
        affected = "X-Impact" in names
        return DiscoveryDecision(
            "affected" if affected else "unaffected",
            "marker_reflected" if affected else "within_baseline_variance",
        )

    found = isolate_candidates(["X-A", "X-Impact", "X-B", "X-C"], affects)
    assert [item.name for item in found] == ["X-Impact"]
    assert calls[("X-Impact",)] == 2


def test_singleton_that_does_not_repeat_is_dropped() -> None:
    count = 0

    def flaky(names: Sequence[str]) -> DiscoveryDecision:
        nonlocal count
        count += 1
        return DiscoveryDecision("affected" if count == 1 else "unaffected", "status_changed:201")

    assert isolate_candidates(["X-Flaky"], flaky) == []


def test_rejected_batch_is_split_without_promoting_rejection() -> None:
    calls: list[tuple[str, ...]] = []

    def affects(names: Sequence[str]) -> DiscoveryDecision:
        key = tuple(names)
        calls.append(key)
        if len(names) > 1 and "X-Reject" in names:
            return DiscoveryDecision("inconclusive", "batch_rejected")
        if names == ["X-Reject"] or key == ("X-Reject",):
            return DiscoveryDecision("inconclusive", "batch_rejected")
        if "X-Impact" in names:
            return DiscoveryDecision("affected", "marker_reflected")
        return DiscoveryDecision("unaffected", "within_baseline_variance")

    found = isolate_candidates(["X-Reject", "X-Impact", "X-Other"], affects)
    assert [item.name for item in found] == ["X-Impact"]
    assert ("X-Reject",) in calls


def test_isolation_limit_stops_after_requested_number_of_headers() -> None:
    calls = 0

    def all_affected(_names: Sequence[str]) -> DiscoveryDecision:
        nonlocal calls
        calls += 1
        return DiscoveryDecision("affected", "marker_reflected")

    found = isolate_candidates(["X-A", "X-B", "X-C", "X-D"], all_affected, limit=2)
    assert [item.name for item in found] == ["X-A", "X-B"]
    # Root + left subtree + two singleton repeats. The right half is never probed.
    assert calls == 6


def test_discovery_batches_add_interleaved_partition() -> None:
    names = [f"X-{index}" for index in range(8)]
    batches = discovery_batches(names, batch_size=4)
    assert batches[:2] == [["X-0", "X-1", "X-2", "X-3"], ["X-4", "X-5", "X-6", "X-7"]]
    assert ["X-0", "X-2", "X-4", "X-6"] in batches
    assert ["X-1", "X-3", "X-5", "X-7"] in batches


def test_discovery_batches_validate_batch_size() -> None:
    import pytest

    with pytest.raises(ValueError, match="batch_size must be positive"):
        discovery_batches(["X-A"], batch_size=0)


def test_interleaved_partition_can_break_contiguous_cancellation_pair() -> None:
    names = ["X-A", "X-B", "X-C", "X-D"]
    batches = discovery_batches(names, batch_size=2)
    # A and B cancel only when sent together. The second partition separates them.
    assert ["X-A", "X-C"] in batches
    assert ["X-B", "X-D"] in batches


def test_clean_control_expands_adaptive_baseline() -> None:
    from headerproof.discovery import update_discovery_baseline

    baseline = build_discovery_baseline([snap(body="x" * 100) for _ in range(3)])
    assert baseline is not None
    changed = update_discovery_baseline(baseline, snap(body="x" * 420))
    assert changed is True
    assert baseline.max_body_len == 420
    assert baseline.length_tolerance == 640
    assert response_differs(baseline, snap(body="x" * 420), "marker") == DiscoveryDecision(
        "unaffected", "within_baseline_variance"
    )


def test_failed_clean_control_does_not_expand_adaptive_baseline() -> None:
    from headerproof.discovery import update_discovery_baseline

    baseline = build_discovery_baseline([snap(body="x" * 100) for _ in range(3)])
    assert baseline is not None
    failed = snap(body="x" * 500)
    failed.error = "timeout"
    assert update_discovery_baseline(baseline, failed) is False
    assert baseline.max_body_len == 100


def test_adaptive_baseline_does_not_learn_auth_rate_limit_or_server_errors() -> None:
    from headerproof.discovery import update_discovery_baseline

    baseline = build_discovery_baseline([snap(status=200, body="stable") for _ in range(3)])
    assert baseline is not None
    for status in (401, 403, 429, 500, 503):
        assert update_discovery_baseline(baseline, snap(status=status, body="error")) is False
    assert baseline.statuses == {200}


def test_new_auth_rate_limit_or_server_error_is_inconclusive_not_header_impact() -> None:
    baseline = build_discovery_baseline([snap(status=200, body="stable") for _ in range(3)])
    assert baseline is not None
    for status in (401, 403, 429, 500, 503):
        assert response_differs(baseline, snap(status=status, body="error"), "marker") == DiscoveryDecision(
            "inconclusive", "batch_rejected"
        )


def test_dynamic_response_policy_is_detector_scoped_and_preserves_cache_evidence() -> None:
    from headerproof.discovery import dynamic_response_policy

    baseline = build_discovery_baseline([snap(status=200, body="stable") for _ in range(3)])
    assert baseline is not None
    policy = dynamic_response_policy(baseline)
    assert policy["detector"] == "cache-poisoning-discovery"
    assert policy["learned_dimensions"] == ["status", "body_length"]
    assert policy["preserved_dimensions"] == ["response_headers", "body_content", "cache_evidence"]
    assert policy["generic_similarity"] is False
    assert policy["timing_gate"] is False


def test_adaptive_learning_never_mutates_response_cache_evidence() -> None:
    from headerproof.detectors import cache_indicators, shared_cache_hit_markers
    from headerproof.discovery import update_discovery_baseline

    baseline = build_discovery_baseline([snap(status=200, body="short") for _ in range(3)])
    assert baseline is not None
    dynamic = snap(status=201, body="x" * 500)
    dynamic.headers = {
        "age": ["9"],
        "x-cache": ["HIT"],
        "etag": ['"dynamic"'],
        "cache-status": ["hit"],
    }
    before = cache_indicators(dynamic)
    before_markers = shared_cache_hit_markers(before)
    assert update_discovery_baseline(baseline, dynamic) is True
    assert cache_indicators(dynamic) == before
    assert shared_cache_hit_markers(cache_indicators(dynamic)) == before_markers
    assert {"age=9", "x-cache=HIT", 'etag="dynamic"', "cache-status=hit"} <= set(before)
