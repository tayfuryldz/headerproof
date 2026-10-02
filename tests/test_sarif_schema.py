"""SARIF 2.1.0 schema-validity for generated output (issue #3).

Validates sarif_payload() against tests/fixtures/sarif-2.1.0.min.json --
a vendored MINIMAL subset covering exactly what we emit. A tiny stdlib
validator is used on purpose: no jsonschema dependency, fully offline and
deterministic.
"""
from __future__ import annotations

import json
from pathlib import Path

from headerproof.output import sarif_payload

FIXTURE = Path(__file__).parent / "fixtures" / "sarif-2.1.0.min.json"


def finding(severity="high"):
    return {
        "url": "https://example.com/demo",
        "type": "response_splitting_crlf_candidate",
        "check": "header-injection",
        "title": "CRLF query probe influenced response headers",
        "severity": severity,
        "confidence": "high",
        "assessment": {"state": "reproduced"},
    }


def validate(instance, schema, path="$"):
    """Minimal JSON-Schema subset: type/required/const/enum/minItems/recursion."""
    errors = []
    kind = schema.get("type")
    if kind == "object":
        if not isinstance(instance, dict):
            return ["%s: expected object" % path]
        for key in schema.get("required", []):
            if key not in instance:
                errors.append("%s: missing %r" % (path, key))
        for key, subschema in schema.get("properties", {}).items():
            if key in instance:
                errors += validate(instance[key], subschema, "%s.%s" % (path, key))
    elif kind == "array":
        if not isinstance(instance, list):
            return ["%s: expected array" % path]
        if len(instance) < schema.get("minItems", 0):
            errors.append("%s: need >= %d items" % (path, schema["minItems"]))
        for i, item in enumerate(instance):
            errors += validate(item, schema["items"], "%s[%d]" % (path, i))
    elif kind == "string":
        if not isinstance(instance, str):
            errors.append("%s: expected string" % path)
    if "const" in schema and instance != schema["const"]:
        errors.append("%s: expected %r" % (path, schema["const"]))
    if "enum" in schema and instance not in schema["enum"]:
        errors.append("%s: %r not in %r" % (path, instance, schema["enum"]))
    return errors


def assert_valid(payload):
    schema = json.loads(FIXTURE.read_text(encoding="utf-8"))
    errors = validate(payload, schema)
    assert not errors, "SARIF schema violations: %s" % errors


def test_sarif_payload_is_schema_valid():
    assert_valid(sarif_payload([finding()]))


def test_sarif_payload_empty_findings_is_schema_valid():
    assert_valid(sarif_payload([]))


def test_sarif_payload_all_severities_are_schema_valid():
    for severity in ("critical", "high", "medium", "low", "info"):
        assert_valid(sarif_payload([finding(severity)]))


def test_sarif_payload_multiple_rules_are_schema_valid():
    second = finding()
    second["type"] = "missing_security_headers"
    second["check"] = "header-presence"
    assert_valid(sarif_payload([finding(), second]))
