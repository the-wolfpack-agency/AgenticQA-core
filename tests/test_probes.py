"""Tests for security_headers + error_disclosure probes."""

from __future__ import annotations

import io
import json
from email.message import Message
from unittest.mock import patch

import pytest

from agenticqa_core.probes import error_disclosure, security_headers


class _FakeResponse:
    def __init__(self, headers: dict[str, str], status: int = 200, body: bytes = b""):
        msg = Message()
        for k, v in headers.items():
            msg[k] = v
        self.headers = msg
        self.status = status
        self._body = body

    def read(self, n: int | None = None) -> bytes:
        return self._body if n is None else self._body[:n]


def test_security_headers_all_present_returns_zero_missing():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    with patch("urllib.request.urlopen", return_value=_FakeResponse(headers)):
        result = security_headers.probe("https://example.com")
    assert result["missing_count"] == 0
    assert result["status"] == 200
    assert all(h["present"] for h in result["headers"])


def test_security_headers_missing_some():
    with patch("urllib.request.urlopen", return_value=_FakeResponse({})):
        result = security_headers.probe("https://example.com")
    assert result["missing_count"] == len(security_headers.REQUIRED)


def test_security_headers_main_help_returns_zero(capsys):
    rc = security_headers.main(["--help"])
    assert rc == 0
    assert "usage" in capsys.readouterr().out


def test_security_headers_main_missing_arg():
    rc = security_headers.main([])
    assert rc == 2


def test_error_disclosure_no_leak_when_body_clean():
    fake = _FakeResponse({}, status=404, body=b'{"error":"not found"}')
    with patch("urllib.request.urlopen", return_value=fake):
        result = error_disclosure.probe("https://example.com")
    assert result["leak_count"] == 0


def test_error_disclosure_flags_stack_trace():
    leaked = b'TypeError: cannot read property "foo" of undefined at handler (/Users/x/site/app.ts:42:10)'
    fake = _FakeResponse({}, status=500, body=leaked)
    with patch("urllib.request.urlopen", return_value=fake):
        result = error_disclosure.probe("https://example.com")
    assert result["leak_count"] >= 1
    assert any(f["leak"].startswith("TypeError:") or "/Users/" in f["leak"]
               for f in result["leaks"])


def test_error_disclosure_main_returns_nonzero_on_leak():
    leaked = b"TypeError: nope"
    fake = _FakeResponse({}, status=500, body=leaked)
    buf = io.StringIO()
    with patch("urllib.request.urlopen", return_value=fake), \
         patch("sys.stdout", buf):
        rc = error_disclosure.main(["https://example.com"])
    assert rc == 1
    parsed = json.loads(buf.getvalue())
    assert parsed["leak_count"] >= 1


def test_error_disclosure_main_help():
    rc = error_disclosure.main(["--help"])
    assert rc == 0


@pytest.mark.parametrize("argv", [[], ["a", "b"]])
def test_error_disclosure_main_bad_args(argv):
    assert error_disclosure.main(argv) == 2
