from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Callable

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import header_active_scan  # noqa: E402

CANARY = "pa-scan-deadbeef"
CACHE_URL = "http://cache.test/page?pa_cb=gate"
CONTROL_URL = "http://cache.test/page?pa_cb=gate-control"


def snap(
    *,
    body: str,
    headers: dict[str, str],
    request_headers: dict[str, str] | None,
    url: str,
    context: str,
    status: int | None = 200,
    error: str = "",
) -> header_active_scan.HttpSnapshot:
    raw = body.encode()
    return header_active_scan.HttpSnapshot(
        "GET",
        url,
        request_headers or {},
        status=status,
        headers={name.lower(): [value] for name, value in headers.items()},
        body_sample=body,
        body_len=len(raw),
        body_sample_len=len(raw),
        body_sha256=hashlib.sha256(raw).hexdigest(),
        error=error,
        client_context=context,
    )


def valid_flow() -> dict[str, header_active_scan.HttpSnapshot | None]:
    return {
        "clean": snap(
            body="clean",
            headers={"Cache-Control": "public, max-age=120", "Age": "0", "X-Cache": "MISS"},
            request_headers={"Cache-Control": "no-cache"},
            url=CACHE_URL,
            context="clean",
        ),
        "poison": snap(
            body=f"poison={CANARY}",
            headers={"Cache-Control": "public, max-age=120", "Age": "0", "X-Cache": "MISS"},
            request_headers={"X-Forwarded-Host": CANARY},
            url=CACHE_URL,
            context="poison",
        ),
        "victim": snap(
            body=f"cached={CANARY}",
            headers={"Cache-Control": "public, max-age=120", "Age": "7", "X-Cache": "HIT"},
            request_headers={},
            url=CACHE_URL,
            context="victim",
        ),
        "control": snap(
            body="fresh-clean",
            headers={"Cache-Control": "public, max-age=120", "Age": "0", "X-Cache": "MISS"},
            request_headers={},
            url=CONTROL_URL,
            context="control",
        ),
    }


def replace_snapshot(
    flow: dict[str, header_active_scan.HttpSnapshot | None],
    key: str,
    **changes: object,
) -> None:
    original = flow[key]
    assert isinstance(original, header_active_scan.HttpSnapshot)
    values = {
        "body": original.body_sample,
        "headers": {name: entries[0] for name, entries in original.headers.items()},
        "request_headers": original.request_headers,
        "url": original.request_url,
        "context": original.client_context,
        "status": original.status,
        "error": original.error,
    }
    values.update(changes)
    flow[key] = snap(**values)  # type: ignore[arg-type]


Mutation = Callable[[dict[str, header_active_scan.HttpSnapshot | None]], None]


def remove_clean(flow: dict[str, header_active_scan.HttpSnapshot | None]) -> None:
    flow["clean"] = None


def remove_control(flow: dict[str, header_active_scan.HttpSnapshot | None]) -> None:
    flow["control"] = None


def fail_clean(flow: dict[str, header_active_scan.HttpSnapshot | None]) -> None:
    replace_snapshot(flow, "clean", error="timeout")


def mismatch_status(flow: dict[str, header_active_scan.HttpSnapshot | None]) -> None:
    replace_snapshot(flow, "control", status=404)


def reuse_context(flow: dict[str, header_active_scan.HttpSnapshot | None]) -> None:
    replace_snapshot(flow, "control", context="victim")


def reuse_cache_key(flow: dict[str, header_active_scan.HttpSnapshot | None]) -> None:
    replace_snapshot(flow, "control", url=CACHE_URL)


def poison_clean_baseline(flow: dict[str, header_active_scan.HttpSnapshot | None]) -> None:
    replace_snapshot(flow, "clean", body=f"already={CANARY}")


def poison_fresh_control(flow: dict[str, header_active_scan.HttpSnapshot | None]) -> None:
    replace_snapshot(flow, "control", body=f"control={CANARY}")


def omit_poison_header(flow: dict[str, header_active_scan.HttpSnapshot | None]) -> None:
    replace_snapshot(flow, "poison", request_headers={})


def contaminate_victim_request(flow: dict[str, header_active_scan.HttpSnapshot | None]) -> None:
    replace_snapshot(flow, "victim", request_headers={"X-Forwarded-Host": CANARY})


def contaminate_control_request(flow: dict[str, header_active_scan.HttpSnapshot | None]) -> None:
    replace_snapshot(flow, "control", request_headers={"X-Forwarded-Host": CANARY})


def remove_shared_hit(flow: dict[str, header_active_scan.HttpSnapshot | None]) -> None:
    replace_snapshot(
        flow,
        "victim",
        headers={"Cache-Control": "public, max-age=120", "Age": "0", "X-Cache": "MISS"},
    )


def static_age(flow: dict[str, header_active_scan.HttpSnapshot | None]) -> None:
    for key in ("clean", "poison", "victim"):
        replace_snapshot(
            flow,
            key,
            headers={"Cache-Control": "public, max-age=120", "Age": "5"},
        )


@pytest.mark.parametrize(
    "mutate",
    [
        remove_clean,
        remove_control,
        fail_clean,
        mismatch_status,
        reuse_context,
        reuse_cache_key,
        poison_clean_baseline,
        poison_fresh_control,
        omit_poison_header,
        contaminate_victim_request,
        contaminate_control_request,
        remove_shared_hit,
        static_age,
    ],
    ids=lambda function: function.__name__,
)
def test_each_cache_proof_gate_mutation_blocks_confirmation(mutate: Mutation) -> None:
    flow = valid_flow()
    mutate(flow)
    poison = flow["poison"]
    assert isinstance(poison, header_active_scan.HttpSnapshot)
    signals = header_active_scan.analyze_header_probe(
        "X-Forwarded-Host",
        CANARY,
        "gate",
        flow["clean"],
        poison,
        flow["victim"],
        flow["control"],
        False,
    )

    assert not any(signal["type"] == "cache_poisoning_shared_cache_confirmed" for signal in signals)
    reproduced = [
        signal for signal in signals if signal["type"] == "cache_poisoning_cross_request_reproduction"
    ]
    if reproduced:
        assert reproduced[0]["assessment"]["technical_gate"] == "failed"


def test_unmodified_cache_flow_passes_every_gate() -> None:
    flow = valid_flow()
    poison = flow["poison"]
    assert isinstance(poison, header_active_scan.HttpSnapshot)
    signals = header_active_scan.analyze_header_probe(
        "X-Forwarded-Host",
        CANARY,
        "gate",
        flow["clean"],
        poison,
        flow["victim"],
        flow["control"],
        False,
    )
    confirmed = next(signal for signal in signals if signal["type"] == "cache_poisoning_shared_cache_confirmed")
    assert all(confirmed["evidence"]["state_machine_checks"].values())
    assert confirmed["assessment"]["technical_gate"] == "passed"


def test_confirmed_cache_flow_records_explicit_negative_control_attribution() -> None:
    flow = valid_flow()
    poison = flow["poison"]
    assert isinstance(poison, header_active_scan.HttpSnapshot)
    signals = header_active_scan.analyze_header_probe(
        "X-Forwarded-Host", CANARY, "gate", flow["clean"], poison, flow["victim"], flow["control"], False
    )
    confirmed = next(signal for signal in signals if signal["type"] == "cache_poisoning_shared_cache_confirmed")
    evidence = confirmed["evidence"]
    assert evidence["state_machine_checks"]["negative_control_attribution_valid"] is True
    assert all(evidence["negative_control_evidence"].values())


@pytest.mark.parametrize(
    "mutate",
    [
        remove_clean,
        remove_control,
        poison_clean_baseline,
        poison_fresh_control,
        omit_poison_header,
        contaminate_victim_request,
        contaminate_control_request,
    ],
    ids=lambda function: function.__name__,
)
def test_negative_control_mutations_fail_explicit_attribution_gate(mutate: Mutation) -> None:
    flow = valid_flow()
    mutate(flow)
    poison = flow["poison"]
    assert isinstance(poison, header_active_scan.HttpSnapshot)
    signals = header_active_scan.analyze_header_probe(
        "X-Forwarded-Host", CANARY, "gate", flow["clean"], poison, flow["victim"], flow["control"], False
    )
    reproduced = next(
        (signal for signal in signals if signal["type"] == "cache_poisoning_cross_request_reproduction"), None
    )
    if reproduced is not None:
        assert reproduced["evidence"]["state_machine_checks"]["negative_control_attribution_valid"] is False
        assert reproduced["assessment"]["technical_gate"] == "failed"
    assert not any(signal["type"] == "cache_poisoning_shared_cache_confirmed" for signal in signals)


def test_confirmed_flow_records_independent_clean_victim_proof() -> None:
    flow = valid_flow()
    poison = flow["poison"]
    assert isinstance(poison, header_active_scan.HttpSnapshot)
    signals = header_active_scan.analyze_header_probe(
        "X-Forwarded-Host", CANARY, "gate", flow["clean"], poison, flow["victim"], flow["control"], False
    )
    confirmed = next(signal for signal in signals if signal["type"] == "cache_poisoning_shared_cache_confirmed")
    evidence = confirmed["evidence"]
    assert evidence["state_machine_checks"]["independent_clean_victim_confirmed"] is True
    assert all(evidence["independent_victim_evidence"].values())


def test_reused_poison_context_blocks_independent_victim_confirmation() -> None:
    flow = valid_flow()
    replace_snapshot(flow, "victim", context="poison")
    poison = flow["poison"]
    assert isinstance(poison, header_active_scan.HttpSnapshot)
    signals = header_active_scan.analyze_header_probe(
        "X-Forwarded-Host", CANARY, "gate", flow["clean"], poison, flow["victim"], flow["control"], False
    )
    reproduced = next(signal for signal in signals if signal["type"] == "cache_poisoning_cross_request_reproduction")
    assert reproduced["evidence"]["state_machine_checks"]["independent_clean_victim_confirmed"] is False
    assert reproduced["evidence"]["independent_victim_evidence"]["victim_context_differs_from_poison"] is False
    assert reproduced["assessment"]["technical_gate"] == "failed"
    assert not any(signal["type"] == "cache_poisoning_shared_cache_confirmed" for signal in signals)
