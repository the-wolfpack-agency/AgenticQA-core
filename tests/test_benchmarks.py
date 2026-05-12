"""Tests for sdet_trend benchmark recorder."""

from __future__ import annotations

import io
import json
from unittest.mock import patch

from agenticqa_core.benchmarks import sdet_trend


def test_summarize_happy_path(tmp_path):
    payload = {
        "numTotalTests": 100,
        "numPassedTests": 95,
        "numFailedTests": 5,
        "numPendingTests": 0,
        "numTodoTests": 0,
        "numTotalTestSuites": 10,
        "numFailedTestSuites": 1,
        "success": False,
    }
    p = tmp_path / "jest.json"
    p.write_text(json.dumps(payload))
    record = sdet_trend.summarize(str(p))
    assert record["num_total_tests"] == 100
    assert record["num_passed_tests"] == 95
    assert record["pass_rate"] == 0.95
    assert record["jest_success"] is False


def test_summarize_zero_total_gives_zero_rate(tmp_path):
    p = tmp_path / "jest.json"
    p.write_text(json.dumps({}))
    record = sdet_trend.summarize(str(p))
    assert record["num_total_tests"] == 0
    assert record["pass_rate"] == 0.0


def test_summarize_missing_file_reports_error():
    record = sdet_trend.summarize("/does/not/exist.json")
    assert "error" in record
    assert record["num_total_tests"] == 0


def test_summarize_malformed_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    record = sdet_trend.summarize(str(p))
    assert "error" in record


def test_main_help(capsys):
    rc = sdet_trend.main(["--help"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "usage" in out


def test_main_writes_json_record(tmp_path):
    p = tmp_path / "jest.json"
    p.write_text(json.dumps({"numTotalTests": 1, "numPassedTests": 1}))
    buf = io.StringIO()
    with patch("sys.stdout", buf):
        rc = sdet_trend.main([str(p)])
    assert rc == 0
    parsed = json.loads(buf.getvalue())
    assert parsed["num_total_tests"] == 1
    assert parsed["pass_rate"] == 1.0


def test_main_bad_args():
    assert sdet_trend.main([]) == 2
