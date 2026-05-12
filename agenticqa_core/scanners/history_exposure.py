"""Scan git log + source for client-name / PII exposure on a public repo.

The repo is public. Anything in commit messages, PR titles, or issue
bodies is search-indexed. A client name attached to an issue or commit
becomes a permanent disclosure.

Patterns:
  H1  client / dealer name in commit messages or PR titles
  H2  email addresses (non-allowlisted) in commit messages
  H3  internal IP addresses in commit messages
  H5  dealer slugs / IDs in source files (CLAUDE.md ban — generic only)

Usage:
  agenticqa-audit-history
  agenticqa-audit-history --json
  agenticqa-audit-history --since=2026-01-01
  agenticqa-audit-history --path some/repo
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

__all__ = ["Finding", "audit", "scan_text_for_sensitive", "main"]

# Canonical "do-not-publish" sets.
SENSITIVE_UNIQUE = [
    "Aidan Mulready",
    "Aidan",
    "Mulready",
    "CFTR",
]
SENSITIVE_COMMON = [
    "Avis",
    "Hertz",
    "Enterprise Rent-A-Car",
    "Enterprise Holdings",
]

SENSITIVE_RE_UNIQUE = re.compile(
    r"\b(?:" + "|".join(re.escape(n) for n in SENSITIVE_UNIQUE) + r")\b",
    re.IGNORECASE,
)
SENSITIVE_RE_COMMON = re.compile(
    r"\b(?:" + "|".join(re.escape(n) for n in SENSITIVE_COMMON) + r")\b",
)

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)

EMAIL_ALLOWLIST_DOMAINS = (
    "@thewolfpack.agency",
    "@anthropic.com",
    "@github.com",
    "@noreply.github.com",
    "@users.noreply.github.com",
)


@dataclass
class Finding:
    pattern: str
    where: str
    ref: str
    severity: str
    snippet: str


def scan_text_for_sensitive(text: str):
    """Yield regex match objects for any sensitive name in text."""
    yield from SENSITIVE_RE_UNIQUE.finditer(text)
    yield from SENSITIVE_RE_COMMON.finditer(text)


def _git_log(root: Path, since: str | None) -> list[tuple[str, str, str]]:
    cmd = ["git", "log", "--all", "--format=%H%x1f%s%x1f%b%x1e"]
    if since:
        cmd.append(f"--since={since}")
    try:
        out = subprocess.check_output(cmd, cwd=str(root), text=True, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    commits: list[tuple[str, str, str]] = []
    for entry in out.split("\x1e"):
        # Strip only ASCII whitespace; preserve trailing \x1f separators
        # so an empty body still parses to a 3-element split.
        entry = entry.strip(" \t\r\n")
        if not entry:
            continue
        parts = entry.split("\x1f")
        if len(parts) >= 3:
            commits.append((parts[0], parts[1], parts[2]))
        elif len(parts) == 2:
            commits.append((parts[0], parts[1], ""))
    return commits


def _scan_commits(root: Path, since: str | None) -> list[Finding]:
    findings: list[Finding] = []
    for sha, subject, body in _git_log(root, since):
        text = f"{subject}\n{body}"
        for m in scan_text_for_sensitive(text):
            findings.append(
                Finding(
                    "H1", "commit", sha[:12], "high",
                    f"sensitive name in commit: {m.group(0)} — {subject[:80]}",
                )
            )
        for m in EMAIL_RE.finditer(text):
            email = m.group(0)
            if email.endswith(EMAIL_ALLOWLIST_DOMAINS):
                continue
            findings.append(
                Finding(
                    "H2", "commit", sha[:12], "medium",
                    f"external email in commit: {email}",
                )
            )
        for m in IP_RE.finditer(text):
            findings.append(
                Finding(
                    "H3", "commit", sha[:12], "medium",
                    f"internal IP in commit: {m.group(0)}",
                )
            )
    return findings


def _scan_source(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    src = root / "src"
    if not src.exists():
        return findings
    for p in src.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix not in {".ts", ".tsx", ".md"}:
            continue
        s = str(p)
        if "/node_modules/" in s or "/__tests__/" in s:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(p.relative_to(root))
        for m in scan_text_for_sensitive(text):
            line = text[: m.start()].count("\n") + 1
            findings.append(
                Finding(
                    "H5", "file", f"{rel}:{line}", "high",
                    f"sensitive name in source: {m.group(0)} ({rel}:{line})",
                )
            )
    return findings


def audit(
    root: Path | str = ".",
    *,
    since: str | None = None,
    allow_commits: list[str] | None = None,
) -> dict:
    """Audit a repo for sensitive-name exposure.

    `allow_commits`: list of commit SHAs to suppress H1/H2/H3 findings for.
    Use this for known-legacy commits that can't be rewritten because the
    branch is shared / protected. Match by prefix — 12-char SHAs OK.
    """
    root = Path(root).resolve()
    findings: list[Finding] = []
    findings.extend(_scan_commits(root, since))
    findings.extend(_scan_source(root))

    if allow_commits:
        allow = tuple(c.strip() for c in allow_commits if c.strip())
        before = len(findings)
        findings = [
            f for f in findings
            if not (
                f.where == "commit"
                and any(f.ref.startswith(prefix) for prefix in allow)
            )
        ]
        suppressed = before - len(findings)
        if suppressed:
            # Surface that suppression happened so it's visible in logs.
            print(
                f"[history_exposure] suppressed {suppressed} finding(s) "
                f"from {len(allow)} allowlisted commit(s)",
                file=sys.stderr,
            )

    sev_rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (sev_rank[f.severity], f.pattern, f.ref))
    return {
        "root": str(root),
        "finding_count": len(findings),
        "findings": [asdict(f) for f in findings],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agenticqa-audit-history")
    ap.add_argument("--path", default=".", help="repo root")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--since", help="git log --since, e.g. 2026-01-01")
    ap.add_argument(
        "--allow-commits",
        default="",
        help="Comma-separated commit SHAs (or prefixes) to suppress. "
             "Use for known-legacy exposures that can't be rewritten.",
    )
    args = ap.parse_args(argv)

    allow_commits = [c for c in args.allow_commits.split(",") if c.strip()]
    result = audit(args.path, since=args.since, allow_commits=allow_commits)
    findings = result["findings"]

    if args.json:
        json.dump(
            {"finding_count": len(findings), "findings": findings},
            sys.stdout, indent=2,
        )
        sys.stdout.write("\n")
        return 0

    sev = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev[f["severity"]] += 1
    print(f"# audit_history_exposure — {len(findings)} findings")
    print(f"#   high={sev['high']}  medium={sev['medium']}  low={sev['low']}\n")
    for f in findings:
        print(f"  [{f['severity']:>6}] {f['pattern']} {f['where']} {f['ref']}")
        print(f"           {f['snippet']}")
    if not findings:
        print("  (no exposed sensitive names / emails / IPs found)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
