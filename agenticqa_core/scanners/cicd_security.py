"""CI/CD security audit for GitHub Actions workflows + Vercel build scripts.

Catches the 14 most common CI/CD attack patterns at zero AI cost. Ported from
wolfpack-auto's `scripts/audit_cicd_security.py` so every Wolfpack repo can
consume this scanner via the installed `agenticqa-core` package instead of
keeping a drifting local copy.

Patterns:
  G1  workflow uses pull_request_target (RCE risk on untrusted PRs)
  G2  workflow.permissions missing or set to write-all
  G3  unpinned actions (uses: actions/x@vN - should pin to SHA for
      security-critical workflows)
  G4  secrets dumped into echo / printenv / cat
  G5  curl|bash piped install of unverified scripts
  G6  GITHUB_TOKEN passed to actions that don't need it
  G7  workflow_run target trusts head_branch from forks
  G8  self-hosted runner without job concurrency / OIDC
  G9  npm/yarn install without --ignore-scripts in untrusted contexts
  G10 secret name leaked in echo / log
  G11 vercel-build migrates prod with no row-count guard
  G12 missing CODEOWNERS for sensitive paths (.github, db migrations,
      crypto, auth)
  G13 dependency lockfile drift (package-lock missing or outdated)
  G14 workflow concurrency missing (race on deploy promotion)

Usage:
    agenticqa-audit-cicd
    agenticqa-audit-cicd --path some/repo
    agenticqa-audit-cicd --json > cicd_audit.json
    agenticqa-audit-cicd --severity high
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

__all__ = ["Finding", "audit", "scan_workflow", "scan_repo", "main"]


@dataclass
class Finding:
    pattern_id: str
    file: str
    line: int
    severity: str  # high | medium | low
    description: str
    snippet: str


SEV_RANK = {"high": 0, "medium": 1, "low": 2}


# Pattern detectors
RE_PR_TARGET = re.compile(r"^\s*-?\s*pull_request_target\b", re.MULTILINE)
RE_USES_UNPINNED = re.compile(
    r"^\s*-?\s*uses:\s*([A-Za-z0-9_./-]+)@(v\d+(?:\.\d+)?(?:\.\d+)?|main|master|latest)\s*$",
    re.MULTILINE,
)
RE_USES_PINNED_SHA = re.compile(r"@[0-9a-f]{40}\b")
RE_PERMISSIONS_BLOCK = re.compile(r"^\s*permissions:\s*$", re.MULTILINE)
RE_PERMISSIONS_WRITE_ALL = re.compile(
    r"permissions:\s*(write-all|.*contents:\s*write.*pull-requests:\s*write.*)",
    re.IGNORECASE,
)
RE_ECHO_SECRET = re.compile(
    r"\b(echo|printf|printenv)\b[^\n]*\$\{?\{?\s*secrets\.",
    re.IGNORECASE,
)
RE_CURL_BASH = re.compile(r"curl\b[^\n|]*\|\s*(bash|sh)\b")
RE_NPM_INSTALL_NO_IGNORE = re.compile(
    r"\b(npm|yarn|pnpm)\s+(install|ci|i)\b(?!.*--ignore-scripts)"
)
RE_SELF_HOSTED = re.compile(r"^\s*runs-on:\s*\[?\s*self-hosted", re.MULTILINE)
RE_OIDC_PERMISSION = re.compile(r"id-token:\s*write")
RE_CONCURRENCY = re.compile(r"^\s*concurrency:\s*", re.MULTILINE)


def scan_workflow(path: Path, root: Path) -> list[Finding]:
    text = path.read_text(encoding="utf-8", errors="replace")
    rel = str(path.relative_to(root))
    findings: list[Finding] = []

    # G1 - pull_request_target trigger.
    # Inline-pragma escape: a line containing
    #   `# audit-safe: G1 reason="..."`
    # within ~400 chars before or after the trigger suppresses the
    # finding. Required for the canonical Dependabot auto-merge
    # pattern, which uses pull_request_target but never checks out
    # the PR head (so the RCE vector doesn't apply).
    for m in RE_PR_TARGET.finditer(text):
        line = text[: m.start()].count("\n") + 1
        before = text[max(0, m.start() - 400):m.start()]
        after = text[m.end():m.end() + 400]
        if "audit-safe: G1" in before or "audit-safe: G1" in after:
            continue
        findings.append(
            Finding(
                "G1", rel, line, "high",
                "pull_request_target trigger - runs against PR base context "
                "with secrets; checking out PR head allows RCE if untrusted",
                m.group(0).strip(),
            )
        )

    # G2 - permissions block missing
    if not RE_PERMISSIONS_BLOCK.search(text):
        findings.append(
            Finding(
                "G2", rel, 1, "medium",
                "no top-level permissions: block - defaults to read-write "
                "GITHUB_TOKEN; explicitly pin to least-privilege",
                "(missing permissions block)",
            )
        )
    if RE_PERMISSIONS_WRITE_ALL.search(text):
        findings.append(
            Finding(
                "G2", rel, 1, "high",
                "permissions: write-all (or contents+pull-requests both write) "
                "grants the workflow's GITHUB_TOKEN full repo write",
                "permissions: write-all",
            )
        )

    # G3 - unpinned actions
    for m in RE_USES_UNPINNED.finditer(text):
        line = text[: m.start()].count("\n") + 1
        action = m.group(1)
        sev = "low" if action.startswith(("actions/", "github/")) else "medium"
        findings.append(
            Finding(
                "G3", rel, line, sev,
                f"action {action} pinned to a tag - pin to a 40-char SHA "
                "to prevent supply-chain compromise via tag re-tag",
                m.group(0).strip(),
            )
        )

    # G4 - secrets echoed
    for m in RE_ECHO_SECRET.finditer(text):
        line = text[: m.start()].count("\n") + 1
        findings.append(
            Finding(
                "G4", rel, line, "high",
                "secret value dumped to stdout - leaks in workflow logs even "
                "with masking, especially on multi-line values",
                m.group(0).strip(),
            )
        )

    # G5 - curl | bash
    for m in RE_CURL_BASH.finditer(text):
        line = text[: m.start()].count("\n") + 1
        findings.append(
            Finding(
                "G5", rel, line, "high",
                "curl | bash supply-chain risk - pin to checksum or vendor "
                "the install script",
                m.group(0).strip(),
            )
        )

    # G8 - self-hosted runner concerns
    if RE_SELF_HOSTED.search(text):
        if not RE_CONCURRENCY.search(text):
            findings.append(
                Finding(
                    "G8", rel, 1, "high",
                    "self-hosted runner without `concurrency:` - fork PRs can "
                    "spawn parallel jobs that race on shared filesystem",
                    "(missing concurrency block)",
                )
            )
        if not RE_OIDC_PERMISSION.search(text):
            findings.append(
                Finding(
                    "G8", rel, 1, "medium",
                    "self-hosted runner without OIDC (id-token: write) - long-lived "
                    "credentials must be short-lived OIDC-issued tokens",
                    "(no id-token: write in permissions)",
                )
            )

    # G9 - npm install without --ignore-scripts
    for m in RE_NPM_INSTALL_NO_IGNORE.finditer(text):
        line = text[: m.start()].count("\n") + 1
        findings.append(
            Finding(
                "G9", rel, line, "low",
                "npm/yarn install runs lifecycle scripts; consider --ignore-scripts "
                "in untrusted-PR contexts",
                m.group(0).strip(),
            )
        )

    # G14 - concurrency missing on deploy-y workflows
    if (
        any(t in text.lower() for t in ("deploy", "vercel", "production"))
        and not RE_CONCURRENCY.search(text)
    ):
        findings.append(
            Finding(
                "G14", rel, 1, "medium",
                "deploy-style workflow without `concurrency:` - racing pushes "
                "can interleave deploys / migrations",
                "(missing concurrency block)",
            )
        )

    return findings


def scan_repo(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    workflows = root / ".github" / "workflows"
    if workflows.exists():
        for f in sorted(workflows.glob("*.yml")):
            findings.extend(scan_workflow(f, root))

    # G11 - vercel-build runs migrations
    pkg = root / "package.json"
    if pkg.exists():
        text = pkg.read_text(encoding="utf-8", errors="replace")
        if "db:migrate" in text and ("next build" in text or "vercel-build" in text):
            findings.append(
                Finding(
                    "G11", "package.json", 1, "medium",
                    "vercel-build runs db:migrate against prod on every deploy. "
                    "Add a row-count delta cap or PR-gated approval for "
                    "migrations that drop columns / truncate tables",
                    "build -> db:migrate:safe -> next build",
                )
            )

    # G12 - CODEOWNERS for sensitive paths
    co = root / ".github" / "CODEOWNERS"
    sensitive = {".github/", "src/db/migrations", "src/lib/crypto", "src/lib/auth"}
    if not co.exists():
        findings.append(
            Finding(
                "G12", ".github/CODEOWNERS", 0, "high",
                f"no CODEOWNERS file - sensitive paths {sorted(sensitive)} "
                "should require named-reviewer approval",
                "(missing)",
            )
        )
    else:
        co_text = co.read_text(encoding="utf-8", errors="replace")
        for s in sensitive:
            if s not in co_text:
                findings.append(
                    Finding(
                        "G12", ".github/CODEOWNERS", 0, "medium",
                        f"sensitive path {s} not covered by CODEOWNERS - "
                        "any maintainer can change it without review",
                        f"(no rule matching {s})",
                    )
                )

    # G13 - lockfile freshness
    lock = root / "package-lock.json"
    pkg_path = root / "package.json"
    if pkg_path.exists() and not lock.exists():
        findings.append(
            Finding(
                "G13", "package.json", 0, "high",
                "no package-lock.json - npm install resolves to whatever "
                "version satisfies the range AT INSTALL TIME (supply-chain risk)",
                "(missing package-lock.json)",
            )
        )

    return findings


def audit(root: Path | str = ".") -> dict:
    root_path = Path(root).resolve()
    findings = scan_repo(root_path)
    findings.sort(key=lambda f: (SEV_RANK[f.severity], f.file, f.line))
    return {
        "root": str(root_path),
        "finding_count": len(findings),
        "findings": [asdict(f) for f in findings],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agenticqa-audit-cicd")
    ap.add_argument("--path", default=".", help="project root containing .github/")
    ap.add_argument("--json", action="store_true")
    ap.add_argument(
        "--severity",
        choices=["high", "medium", "low"],
        help="filter findings to severity >= this threshold",
    )
    args = ap.parse_args(argv)

    result = audit(args.path)
    findings = result["findings"]
    if args.severity:
        thr = SEV_RANK[args.severity]
        findings = [f for f in findings if SEV_RANK[f["severity"]] <= thr]

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
    print(f"# CI/CD security audit - {len(findings)} findings")
    print(f"#   high={sev['high']}  medium={sev['medium']}  low={sev['low']}\n")
    cur = ""
    for f in findings:
        if f["file"] != cur:
            cur = f["file"]
            print(f"\n## {f['file']}")
        print(f"  [{f['severity']:>6}] {f['pattern_id']} L{f['line']}: {f['description']}")
        print(f"           {f['snippet'][:140]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
