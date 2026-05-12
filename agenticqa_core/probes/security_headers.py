"""Probe a deployed URL for the recommended security response headers.

Emits JSON to stdout. Stdlib only — no Playwright / Vibium needed for
header probes. Used by the reusable `nightly-dast.yml` workflow.

Usage:
    agenticqa-probe-headers https://wolfpack-instinct.vercel.app
"""

from __future__ import annotations

import json
import sys
import urllib.request

__all__ = ["REQUIRED", "probe", "main"]

REQUIRED: list[dict[str, str]] = [
    {"name": "content-security-policy", "severity": "high"},
    {"name": "strict-transport-security", "severity": "high"},
    {"name": "x-frame-options", "severity": "medium"},
    {"name": "x-content-type-options", "severity": "medium"},
    {"name": "referrer-policy", "severity": "low"},
    {"name": "permissions-policy", "severity": "low"},
]


def probe(url: str, *, timeout: int = 15) -> dict:
    """Fetch the URL and return a report of header presence."""
    req = urllib.request.Request(url, method="HEAD")
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)  # noqa: S310
    except Exception:  # noqa: BLE001
        try:
            resp = urllib.request.urlopen(  # noqa: S310
                urllib.request.Request(url, method="GET"), timeout=timeout
            )
        except Exception as exc:  # noqa: BLE001
            return {"url": url, "error": str(exc), "missing_count": -1, "headers": []}

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    out: list[dict[str, object]] = []
    missing = 0
    for h in REQUIRED:
        present = h["name"] in headers_lower
        if not present:
            missing += 1
        out.append(
            {
                "name": h["name"],
                "present": present,
                "value": headers_lower.get(h["name"], ""),
                "severity": h["severity"],
            }
        )
    return {
        "url": url,
        "status": resp.status,
        "missing_count": missing,
        "headers": out,
    }


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) == 1 and argv[0] in {"-h", "--help"}:
        print("usage: agenticqa-probe-headers <url>")
        return 0
    if len(argv) != 1:
        print("usage: agenticqa-probe-headers <url>", file=sys.stderr)
        return 2
    result = probe(argv[0])
    print(json.dumps(result, indent=2))
    return 1 if result.get("missing_count", 0) < 0 else 0


if __name__ == "__main__":
    sys.exit(main())
