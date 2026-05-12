"""Shared pytest fixtures."""

from __future__ import annotations

import io
from contextlib import contextmanager

import pytest


@pytest.fixture
def capture_stdout(monkeypatch):
    """Capture sys.stdout for a block; return the buffer."""
    @contextmanager
    def _cap():
        buf = io.StringIO()
        monkeypatch.setattr("sys.stdout", buf)
        yield buf

    return _cap
