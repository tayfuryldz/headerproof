"""Focused tests for malformed headerproof.yaml configs (issue #1).

- invalid types / unsupported keys / malformed request_headers fail fast
  with a concise (single-line) ConfigError
- secret header values are never echoed in error messages
"""
from pathlib import Path

import pytest

from headerproof.config import ConfigError, load_config

SECRET = "Bearer SUPERSECRET-abc-123"


def write(tmp_path, text):
    path = tmp_path / "headerproof.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def fails_concise(path):
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    message = str(excinfo.value)
    assert message, "error must not be empty"
    assert "\n" not in message, "error must be concise (single line): %r" % message
    return message


def test_unknown_key_yaml_fails(tmp_path):
    message = fails_concise(write(tmp_path, "bogus_key: 1\n"))
    assert "bogus_key" in message


def test_unknown_key_json_fails(tmp_path):
    message = fails_concise(write(tmp_path, '{"bogus_key": 1}\n'))
    assert "bogus_key" in message


def test_origins_wrong_type_fails(tmp_path):
    message = fails_concise(write(tmp_path, '{"origins": "https://a.example"}\n'))
    assert "origins" in message


def test_headers_wrong_type_fails(tmp_path):
    message = fails_concise(write(tmp_path, '{"headers": 42}\n'))
    assert "headers" in message


def test_request_headers_scalar_fails(tmp_path):
    message = fails_concise(write(tmp_path, "request_headers: %s\n" % SECRET))
    assert "request_headers" in message
    assert SECRET not in message


def test_request_headers_scalar_json_fails(tmp_path):
    message = fails_concise(write(tmp_path, '{"request_headers": "%s"}\n' % SECRET))
    assert "request_headers" in message
    assert SECRET not in message


def test_request_headers_non_string_value_fails(tmp_path):
    message = fails_concise(
        write(tmp_path, '{"request_headers": {"Authorization": 12345}}\n'))
    assert "request_headers" in message


def test_request_headers_entry_without_value_fails(tmp_path):
    message = fails_concise(
        write(tmp_path, "request_headers:\n  Authorization:\n"))
    assert "request_headers" in message.lower() or "header" in message.lower()


def test_list_item_without_key_fails(tmp_path):
    fails_concise(write(tmp_path, "- orphan\n"))


def test_top_level_list_fails(tmp_path):
    fails_concise(write(tmp_path, '["origins"]\n'))


def test_secret_value_never_echoed_in_any_failure(tmp_path):
    bodies = [
        "request_headers: %s\n" % SECRET,
        '{"request_headers": "%s"}\n' % SECRET,
        # note: `origins: <scalar>` is valid by design (comma-split inline list),
        # so only genuinely-invalid bodies go here
        '{"origins": ["%s", 42]}\n' % SECRET,
    ]
    for body in bodies:
        try:
            load_config(write(tmp_path, body))
        except ConfigError as exc:
            assert SECRET not in str(exc), "secret echoed: %s" % exc
        else:
            pytest.fail("expected ConfigError for %r" % body)


def test_valid_config_with_secrets_still_loads(tmp_path):
    path = write(
        tmp_path,
        "origins:\n  - https://a.example\nrequest_headers:\n  Authorization: %s\n"
        % SECRET,
    )
    payload, found = load_config(path)
    assert found == path
    assert payload["request_headers"]["Authorization"] == SECRET
