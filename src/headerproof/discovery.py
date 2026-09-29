from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal, Sequence

from .detectors import canary_locations
from .models import HttpSnapshot

REJECTION_STATUSES = frozenset({400, 413, 414, 431, 494, 502})
BASELINE_SAMPLES = 3
MIN_LENGTH_DELTA = 128
BATCH_SIZE = 8
MAX_DISCOVERED_HEADERS = 4
MAX_DISCOVERY_REQUESTS = 32

# Bounded, intermediary-controlled request inputs that are not already in the
# default confirmation list. Keep this corpus reviewable; discovery is not a
# substitute for an unbounded wordlist.
DISCOVERY_HEADERS: tuple[str, ...] = (
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
    "X-Original-Host",
    "X-Forwarded-Uri",
    "X-Original-URI",
    "X-Forwarded-SSL",
    "Front-End-Https",
    "X-Url-Scheme",
    "X-Forwarded-Protocol",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Client-IP",
    "X-Cluster-Client-IP",
    "True-Client-IP",
    "X-HTTP-Method-Override",
    "X-Forwarded-Port",
)


@dataclass(frozen=True)
class DiscoveryBaseline:
    statuses: frozenset[int]
    min_body_len: int
    max_body_len: int
    length_tolerance: int


DiscoveryOutcome = Literal["affected", "unaffected", "inconclusive"]


@dataclass(frozen=True)
class DiscoveryDecision:
    outcome: DiscoveryOutcome
    reason: str

    @property
    def affected(self) -> bool:
        return self.outcome == "affected"


@dataclass(frozen=True)
class DiscoveredHeader:
    name: str
    reason: str


def build_discovery_baseline(samples: Sequence[HttpSnapshot]) -> DiscoveryBaseline | None:
    completed = [sample for sample in samples if sample.status is not None and not sample.error]
    if len(completed) < BASELINE_SAMPLES:
        return None
    lengths = [sample.body_len for sample in completed]
    spread = max(lengths) - min(lengths)
    return DiscoveryBaseline(
        statuses=frozenset(int(sample.status) for sample in completed if sample.status is not None),
        min_body_len=min(lengths),
        max_body_len=max(lengths),
        length_tolerance=max(MIN_LENGTH_DELTA, spread * 2),
    )


def response_differs(
    baseline: DiscoveryBaseline,
    response: HttpSnapshot,
    marker: str,
) -> DiscoveryDecision:
    if response.error or response.status is None:
        return DiscoveryDecision("inconclusive", "request_not_completed")
    if response.status in REJECTION_STATUSES and response.status not in baseline.statuses:
        return DiscoveryDecision("inconclusive", "batch_rejected")
    if canary_locations(response, marker):
        return DiscoveryDecision("affected", "marker_reflected")
    if response.status not in baseline.statuses:
        return DiscoveryDecision("affected", f"status_changed:{response.status}")
    if response.body_len < baseline.min_body_len - baseline.length_tolerance:
        return DiscoveryDecision("affected", "body_length_below_baseline")
    if response.body_len > baseline.max_body_len + baseline.length_tolerance:
        return DiscoveryDecision("affected", "body_length_above_baseline")
    return DiscoveryDecision("unaffected", "within_baseline_variance")


def dedupe_candidates(
    candidates: Sequence[str],
    excluded: Sequence[str] = (),
) -> list[str]:
    seen = {name.casefold() for name in excluded}
    output: list[str] = []
    for candidate in candidates:
        key = candidate.casefold()
        if key in seen:
            continue
        seen.add(key)
        output.append(candidate)
    return output


def isolate_candidates(
    names: Sequence[str],
    affects: Callable[[Sequence[str]], DiscoveryDecision],
    *,
    limit: int | None = None,
) -> list[DiscoveredHeader]:
    if not names or limit == 0:
        return []
    decision = affects(names)
    if decision.outcome == "unaffected":
        return []
    if len(names) == 1:
        if decision.outcome != "affected":
            return []
        repeated = affects(names)
        if repeated.outcome != "affected":
            return []
        return [DiscoveredHeader(names[0], repeated.reason or decision.reason)]
    middle = len(names) // 2
    left = isolate_candidates(names[:middle], affects, limit=limit)
    remaining = None if limit is None else max(0, limit - len(left))
    if remaining == 0:
        return left
    return left + isolate_candidates(names[middle:], affects, limit=remaining)


def discovery_batches(candidates: Sequence[str], batch_size: int = BATCH_SIZE) -> list[list[str]]:
    """Return two deterministic partitions to reduce batch-cancellation false negatives.

    The second interleaved pass changes which candidates share a request. A candidate
    masked by another header in the contiguous partition can therefore still reach
    singleton isolation without falling back to one request per candidate.
    """
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    contiguous = [list(candidates[start : start + batch_size]) for start in range(0, len(candidates), batch_size)]
    if len(candidates) <= 1:
        return contiguous
    bucket_count = max(1, (len(candidates) + batch_size - 1) // batch_size)
    interleaved = [list(candidates[offset::bucket_count]) for offset in range(bucket_count)]
    return contiguous + [batch for batch in interleaved if batch and batch not in contiguous]
