from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, TypedDict

EvidenceState = Literal["observed", "reproduced", "cross_request_confirmed"]
TechnicalGate = Literal["passed", "failed"]
ProbeState = Literal["planned", "attempted", "completed", "skipped", "error"]


class RequestEvidence(TypedDict):
    method: str
    url: str
    headers: dict[str, str]
    client_context: str


class ResponseEvidence(TypedDict, total=False):
    status: int | None
    reason: str
    error: str
    elapsed_ms: int
    headers: dict[str, str | list[str]]
    body_len: int
    body_sample_len: int
    body_truncated: bool
    body_sha256: str
    body_sha256_scope: Literal["full_response"]
    body_sample: str


class ExchangeEvidence(TypedDict):
    request: RequestEvidence
    response: ResponseEvidence


class EvidenceAssessment(TypedDict):
    state: EvidenceState
    technical_gate: TechnicalGate
    impact: Literal["unverified"]
    reasons: list[str]
    missing_proof: list[str]
    gate_checks: dict[str, bool]


class CoverageRecord(TypedDict, total=False):
    sequence: int
    kind: Literal["detector", "probe"]
    detector: str
    probe_id: str
    role: str
    state: ProbeState
    reason: str
    error: str


class ProbeRecord(TypedDict, total=False):
    schema_version: str
    record_type: Literal["probe"]
    sequence: int
    probe_id: str
    detector: str
    role: str
    status: ProbeState
    client_context: str
    exchange: ExchangeEvidence | None
    error: str


class SignalRecord(TypedDict, total=False):
    schema_version: str
    record_type: Literal["finding", "observation"]
    check: str
    type: str
    severity: str
    confidence: str
    title: str
    evidence: dict[str, Any]
    exchange: ExchangeEvidence
    assessment: EvidenceAssessment
    verification_plan: dict[str, Any]
    submission_status: Literal["manual_validation_required"]
    next_step: str


@dataclass
class HttpSnapshot:
    request_method: str
    request_url: str
    request_headers: dict[str, str]
    status: int | None = None
    reason: str = ""
    headers: dict[str, list[str]] = field(default_factory=dict)
    body_sample: str = ""
    body_len: int = 0
    body_sample_len: int = 0
    body_truncated: bool = False
    body_sha256: str = ""
    elapsed_ms: int = 0
    error: str = ""
    client_context: str = "default"
    persistence_redactions: dict[str, str] = field(default_factory=dict, repr=False)

    def values(self, name: str) -> list[str]:
        return self.headers.get(name.lower(), [])

    def first(self, name: str, default: str = "") -> str:
        values = self.values(name)
        return values[0] if values else default
