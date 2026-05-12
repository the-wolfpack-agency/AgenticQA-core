"""Emit a single JSONL trend record summarizing a jest --json result file.

Consumed by the reusable `sdet-trend-benchmark.yml` workflow. Tracks
total tests, passed, failed, pass rate, and timestamp.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

__all__ = ["summarize", "main"]


def summarize(jest_json_path: str) -> dict:
    try:
        with open(jest_json_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": f"failed to read jest results: {exc}",
            "num_total_tests": 0,
            "num_passed_tests": 0,
            "num_failed_tests": 0,
            "pass_rate": 0.0,
        }

    total = int(data.get("numTotalTests", 0))
    passed = int(data.get("numPassedTests", 0))
    failed = int(data.get("numFailedTests", 0))
    pending = int(data.get("numPendingTests", 0))
    todo = int(data.get("numTodoTests", 0))
    suites_total = int(data.get("numTotalTestSuites", 0))
    suites_failed = int(data.get("numFailedTestSuites", 0))

    pass_rate = round(passed / total, 4) if total else 0.0

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "git_sha": os.environ.get("GITHUB_SHA", ""),
        "git_ref": os.environ.get("GITHUB_REF", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "num_total_tests": total,
        "num_passed_tests": passed,
        "num_failed_tests": failed,
        "num_pending_tests": pending,
        "num_todo_tests": todo,
        "num_total_suites": suites_total,
        "num_failed_suites": suites_failed,
        "pass_rate": pass_rate,
        "jest_success": bool(data.get("success", False)),
    }


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) == 1 and argv[0] in {"-h", "--help"}:
        print("usage: agenticqa-sdet-trend <jest-results.json>")
        return 0
    if len(argv) != 1:
        print("usage: agenticqa-sdet-trend <jest-results.json>", file=sys.stderr)
        return 2
    record = summarize(argv[0])
    print(json.dumps(record))
    return 0


if __name__ == "__main__":
    sys.exit(main())
