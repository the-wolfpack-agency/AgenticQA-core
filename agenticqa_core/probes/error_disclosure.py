"""Probe endpoints designed to trigger errors and assert no leak.

Detects (in response bodies):
  - "TypeError:" / "RangeError:" / "AttributeError:" framework exceptions
  - "/Users/" / "/home/" filesystem path leaks
  - "node_modules" / "site-packages" framework leaks
  - "at <frame> (<file>:<line>:<col>)" stack frames
  - "next-server/..." Next.js internals

Used by the reusable `nightly-dast.yml` workflow.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request

__all__ = ["PROBE_PATHS", "LEAK_PATTERNS", "probe", "main"]

PROBE_PATHS: list[str] = [
    "/api/automations/__nope__/poll",
    "/api/sites/__nope__",
    "/api/contacts/__nope__",
    "/api/__bogus_endpoint__",
]

LEAK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(?:TypeError|RangeError|AttributeError|ReferenceError|SyntaxError):", re.IGNORECASE),
    re.compile(r"/(?:Users|home|var|opt)/[A-Za-z0-9_./-]+\.(?:ts|tsx|js|py)"),
    re.compile(r"\bnode_modules/[A-Za-z0-9_./-]+"),
    re.compile(r"\bsite-packages/[A-Za-z0-9_./-]+"),
    re.compile(r"\bat\s+[A-Za-z0-9_$.<>]+\s+\([^)]+:\d+:\d+\)"),
    re.compile(r"\bnext-server/[A-Za-z0-9_./-]+"),
]


def probe(url: str, *, timeout: int = 15) -> dict:
    findings: list[dict] = []
    for path in PROBE_PATHS:
        full = url.rstrip("/") + path
        try:
            req = urllib.request.Request(full, method="GET")
            resp = urllib.request.urlopen(req, timeout=timeout)  # noqa: S310
            status = resp.status
            body = resp.read(64_000).decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            status = e.code
            body = e.read(64_000).decode("utf-8", errors="ignore")
        except Exception as exc:  # noqa: BLE001
            findings.append({"path": path, "error": str(exc)})
            continue
        for pat in LEAK_PATTERNS:
            m = pat.search(body)
            if m:
                findings.append(
                    {
                        "path": path,
                        "status": status,
                        "leak": m.group(0)[:100],
                        "leak_pattern": pat.pattern[:60],
                    }
                )
                break
    return {"url": url, "leaks": findings, "leak_count": len(findings)}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) == 1 and argv[0] in {"-h", "--help"}:
        print("usage: agenticqa-probe-errors <url>")
        return 0
    if len(argv) != 1:
        print("usage: agenticqa-probe-errors <url>", file=sys.stderr)
        return 2
    result = probe(argv[0])
    print(json.dumps(result, indent=2))
    return 1 if result["leak_count"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
