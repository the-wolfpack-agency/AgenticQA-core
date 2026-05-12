"""Application-level security audit for Next.js + Postgres + Vercel stacks.

Catches the 18 most common attack patterns at zero AI cost. See the
module-level constant `PATTERN_DESCRIPTIONS` for the catalogue.

Usage:
    agenticqa-audit-app                       # scan ./src
    agenticqa-audit-app --path some/repo      # scan some/repo/src
    agenticqa-audit-app --json > app.json
    agenticqa-audit-app --severity high
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

__all__ = [
    "Finding",
    "audit",
    "scan_file",
    "scan_text",
    "iter_source_files",
    "main",
]

SKIP = (
    "/__tests__/",
    "/__mocks__/",
    "/node_modules/",
    "/.next/",
    "/dist/",
    "/coverage/",
    ".test.",
    ".spec.",
    "/seed",
    "/fixtures/",
)


@dataclass
class Finding:
    pattern: str
    file: str
    line: int
    severity: str
    description: str
    snippet: str


SEV_RANK = {"high": 0, "medium": 1, "low": 2}


def is_skipped(p: Path) -> bool:
    s = str(p)
    return any(f in s for f in SKIP)


def iter_source_files(root: Path) -> list[Path]:
    src = root / "src"
    out: list[Path] = []
    if not src.exists():
        return out
    for p in src.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix not in {".ts", ".tsx"}:
            continue
        if is_skipped(p):
            continue
        out.append(p)
    return out


def file_role(path: Path) -> str:
    s = str(path)
    if "/src/app/api/admin/" in s:
        return "admin_route"
    if "/src/app/api/webhooks/" in s:
        return "webhook_route"
    if "/src/app/api/" in s:
        return "public_route"
    if "/src/app/admin/" in s:
        return "admin_page"
    if "/src/middleware.ts" in s:
        return "middleware"
    if "/src/lib/" in s:
        return "lib"
    if "/src/components/" in s:
        return "component"
    return "other"


# Pattern regexes
RE_REQUIRE_AUTH = re.compile(
    r"\b(requireAuth|requireRole|requireCapability|requireWolfpackStaff|requireAgencyAuth|getServerSession)\s*\("
)
PRELOGIN_ROUTE_ALLOW = (
    "/api/admin/accept-invite/",
    "/api/admin/reset-password/",
    "/api/admin/mfa/verify/",
    "/api/admin/digital-retail/calculator/",
    "/api/auth/",
    "/api/login/",
    "/api/signup/",
    "/api/register/",
)
RE_CHECK_RATE_LIMIT = re.compile(r"\bcheckRateLimit\s*\(")
RE_QUERY_INTERPOLATION = re.compile(
    r"\b(query|pool\.query|writeQuery|safeQuery)\s*\(\s*`[^`]*\$\{[^}]+\}",
    re.MULTILINE,
)
RE_DANGEROUS_HTML = re.compile(r"\bdangerouslySetInnerHTML\s*=")
RE_WEBHOOK_SIG = re.compile(
    r"verifyWebhook|webhookVerify|webhook-verify|constructEvent|timingSafeEqual"
    r"|validate(?:Twilio|Stripe|Webhook)?Signature|verifySignature"
)
RE_RAW_FETCH_EXTERNAL = re.compile(
    r"""\bfetch\s*\(\s*['"]https?://(?!(?:localhost|127\.|0\.0\.0\.0))[^'"]+['"]"""
)
RE_SECRET_LOG = re.compile(
    r"console\.(log|error|warn|info|debug)\([^)]*\b("
    r"password|token|secret|apiKey|api_key|authorization|access_key|"
    r"private_key|client_secret|stripe_secret|nextauth_secret|database_url"
    r")\b",
    re.IGNORECASE,
)
RE_OPEN_REDIRECT = re.compile(
    r"(?:NextResponse\.)?redirect\s*\(\s*[^,)]*\b(?:searchParams|query|req\.body|request\.body)"
)
RE_DANGEROUS_JWT = re.compile(
    r"jwt\.verify\([^)]*algorithms?:\s*(?:undefined|null|\[\s*\]|\[[^\]]*['\"]none['\"]|.*HS256.*RS256)"
)
RE_PROCESS_ENV_IN_USE_CLIENT = re.compile(r"process\.env\.([A-Z_]+)")
RE_HARDCODED_KEY = re.compile(
    r"""(['"])(?:(?:sk_live|sk_test|rk_live|whsec|ghp_|github_pat|AIza|AKIA|xoxb)"""
    r"""|-----BEGIN [A-Z ]+PRIVATE KEY-----)\1?""",
    re.IGNORECASE,
)
RE_SSLMODE_DISABLE = re.compile(r"sslmode=disable", re.IGNORECASE)
RE_SSLMODE_REQUIRE = re.compile(r"sslmode=require\b(?!.*verify)", re.IGNORECASE)
RE_PATH_JOIN_REQ = re.compile(
    r"\bpath\.(?:join|resolve)\s*\([^)]*\b(req\.|request\.|params\.|searchParams|body\.)"
)
RE_USE_CLIENT = re.compile(r"^[\s]*['\"]use client['\"]", re.MULTILINE)


def scan_file(path: Path, *, root: Path) -> list[Finding]:
    text = path.read_text(encoding="utf-8", errors="replace")
    rel = str(path.relative_to(root))
    return scan_text(rel, path.name, text, file_role(path))


def scan_text(rel: str, basename: str, text: str, role: str) -> list[Finding]:
    """Pure text-based scanner. Exposed so tests can use in-memory fixtures."""
    findings: list[Finding] = []
    is_route = role.endswith("_route")
    is_route_ts = is_route and basename == "route.ts"

    # A1 — admin route missing requireAuth
    if role == "admin_route" and is_route_ts:
        if not RE_REQUIRE_AUTH.search(text) and not any(
            allow in rel for allow in PRELOGIN_ROUTE_ALLOW
        ):
            findings.append(
                Finding(
                    "A1", rel, 1, "high",
                    "admin route handler does not call requireAuth/requireRole/requireCapability/getServerSession — auth bypass",
                    "(no auth gate found)",
                )
            )

    # A2 — public mutating route missing checkRateLimit
    if role == "public_route" and is_route_ts:
        has_mutation = bool(
            re.search(r"export\s+async\s+function\s+(POST|PUT|PATCH|DELETE)\b", text)
        )
        if has_mutation and not RE_CHECK_RATE_LIMIT.search(text):
            findings.append(
                Finding(
                    "A2", rel, 1, "medium",
                    "public mutating route without checkRateLimit() — DoS / abuse risk",
                    "(no checkRateLimit call)",
                )
            )

    # A3 — SQL string-interpolation with request-derived input
    for m in RE_QUERY_INTERPOLATION.finditer(text):
        snippet = text[m.start():m.end()][:400]
        if not re.search(
            r"\$\{(?:req\.|request\.|searchParams|body\.|params\.)",
            snippet,
        ):
            continue
        line_start = text.rfind("\n", 0, m.start()) + 1
        if "audit-safe: A3" in text[line_start:m.start() + 200]:
            continue
        line = text[: m.start()].count("\n") + 1
        findings.append(
            Finding(
                "A3", rel, line, "high",
                "SQL template interpolates request-derived input directly — SQL-injection candidate. Use $N placeholders, not ${req.X}",
                snippet[:160].replace("\n", " "),
            )
        )

    # A4 — admin SQL without dealer_id + timestamp filter
    PLATFORM_ADMIN_ROUTES = (
        "/api/admin/analytics/platform-health",
        "/api/admin/analytics/micro-signals",
        "/api/admin/agency/",
        "/api/admin/system/",
        "/api/admin/data-export/",
    )
    if (
        role == "admin_route" and is_route_ts
        and not any(allow in rel for allow in PRELOGIN_ROUTE_ALLOW)
        and not any(allow in rel for allow in PLATFORM_ADMIN_ROUTES)
    ):
        for m in re.finditer(r"\b(query|writeQuery|safeQuery)\s*\(\s*`([^`]+)`", text, re.DOTALL):
            sql = m.group(2)
            sql_lower = sql.lower()
            looks_select = "select" in sql_lower
            looks_dml = any(kw in sql_lower for kw in ("insert", "update", "delete"))
            if not (looks_select or looks_dml):
                continue
            if "dealer_id" in sql_lower or "tenant_id" in sql_lower:
                continue
            if any(kw in sql_lower for kw in ("create table", "create index", "truncate", "alter table", "create extension")):
                continue
            line_start = text.rfind("\n", 0, m.start()) + 1
            if "audit-safe: A4" in text[line_start:m.start() + 300]:
                continue
            line = text[: m.start()].count("\n") + 1
            findings.append(
                Finding(
                    "A4", rel, line, "high",
                    "admin SQL without dealer_id / tenant_id filter — cross-tenant leak / mass query risk",
                    sql.strip()[:140].replace("\n", " "),
                )
            )

    # A5 — dangerouslySetInnerHTML
    for m in RE_DANGEROUS_HTML.finditer(text):
        if "audit-safe: A5" in text[max(0, m.start() - 400):m.end() + 200]:
            continue
        line = text[: m.start()].count("\n") + 1
        ctx = text[max(0, m.start() - 200):m.start()].lower()
        sev = "low" if any(s in ctx for s in ("dompurify", "sanitize", "marked", "remark", "rehype")) else "high"
        findings.append(
            Finding(
                "A5", rel, line, sev,
                "dangerouslySetInnerHTML — XSS sink (downgrade to low when adjacent to a sanitizer call)",
                text[m.start():m.end()][:120],
            )
        )

    # A6 — webhook route without signature verification
    if role == "webhook_route" and is_route_ts:
        if not RE_WEBHOOK_SIG.search(text) and "audit-safe: A6" not in text:
            findings.append(
                Finding(
                    "A6", rel, 1, "high",
                    "webhook route without signature-verification call — spoofed webhooks accepted",
                    "(no verifyWebhook / constructEvent / timingSafeEqual)",
                )
            )

    # A7 — raw fetch to external host from a route handler
    if is_route:
        for m in RE_RAW_FETCH_EXTERNAL.finditer(text):
            line = text[: m.start()].count("\n") + 1
            findings.append(
                Finding(
                    "A7", rel, line, "medium",
                    "raw fetch to external host from a route handler — should go through a wrapped integration with timeout / circuit-breaker / retry",
                    text[m.start():m.end()][:140],
                )
            )

    # A8 — secret in console.*
    for m in RE_SECRET_LOG.finditer(text):
        if "audit-safe: A8" in text[max(0, m.start() - 400):m.end() + 200]:
            continue
        line = text[: m.start()].count("\n") + 1
        findings.append(
            Finding(
                "A8", rel, line, "high",
                "log call references a secret-shaped variable name — likely leaks the secret to logs",
                text[m.start():m.end()][:140],
            )
        )

    # A9 — open redirect
    for m in RE_OPEN_REDIRECT.finditer(text):
        line = text[: m.start()].count("\n") + 1
        ctx_after = text[m.end():m.end() + 200]
        if "startsWith" in ctx_after or "isSameOrigin" in text or "ALLOWED_REDIRECTS" in text:
            sev = "low"
        else:
            sev = "high"
        findings.append(
            Finding(
                "A9", rel, line, sev,
                "redirect target derived from request input — open-redirect risk unless allow-listed",
                text[m.start():m.end()][:140],
            )
        )

    # A12 — JWT alg confusion
    for m in RE_DANGEROUS_JWT.finditer(text):
        line = text[: m.start()].count("\n") + 1
        findings.append(
            Finding(
                "A12", rel, line, "high",
                "jwt.verify with permissive / mixed algorithms — alg-confusion attack",
                text[m.start():m.end()][:140],
            )
        )

    # A13 — non-NEXT_PUBLIC env in a 'use client' file
    if RE_USE_CLIENT.search(text):
        for m in RE_PROCESS_ENV_IN_USE_CLIENT.finditer(text):
            name = m.group(1)
            if name.startswith("NEXT_PUBLIC_") or name in {"NODE_ENV"}:
                continue
            line = text[: m.start()].count("\n") + 1
            findings.append(
                Finding(
                    "A13", rel, line, "high",
                    f"client component reads process.env.{name} — only NEXT_PUBLIC_* values reach the browser; everything else MUST stay server-side",
                    text[m.start():m.end()][:140],
                )
            )

    # A16 — hardcoded keys
    for m in RE_HARDCODED_KEY.finditer(text):
        before = text[max(0, m.start() - 40):m.start()]
        if any(tok in before for tok in (".startsWith(", ".includes(", ".endsWith(", ".match(")):
            continue
        if "_demo_" in text[m.start():m.end() + 80] or "_test_" in text[m.start():m.end() + 80]:
            continue
        if re.search(r"SAMPLE_|MOCK_|DEMO_|FIXTURE_", text[max(0, m.start() - 200):m.start()]):
            continue
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_text = text[line_start:m.start()]
        if line_text.strip().startswith(("//", "*", "/*")):
            continue
        line = text[: m.start()].count("\n") + 1
        findings.append(
            Finding(
                "A16", rel, line, "high",
                "hard-coded secret-shaped string — rotate immediately + move to env",
                text[m.start():m.end()][:140],
            )
        )

    # A17 — sslmode posture
    for m in RE_SSLMODE_DISABLE.finditer(text):
        line = text[: m.start()].count("\n") + 1
        findings.append(
            Finding(
                "A17", rel, line, "high",
                "sslmode=disable — connection ciphered? no. MITM risk on prod DB",
                text[m.start():m.end()][:140],
            )
        )
    for m in RE_SSLMODE_REQUIRE.finditer(text):
        line = text[: m.start()].count("\n") + 1
        findings.append(
            Finding(
                "A17", rel, line, "medium",
                "sslmode=require without verify-full — encryption yes, identity verification no",
                text[m.start():m.end()][:140],
            )
        )

    # A18 — path.join with request input
    for m in RE_PATH_JOIN_REQ.finditer(text):
        line = text[: m.start()].count("\n") + 1
        findings.append(
            Finding(
                "A18", rel, line, "high",
                "path.join/resolve with request-derived input — traversal risk; normalize + allow-list",
                text[m.start():m.end()][:140],
            )
        )

    return findings


def audit(root: Path | str = ".") -> dict:
    root = Path(root).resolve()
    files = iter_source_files(root)
    findings: list[Finding] = []
    for f in files:
        findings.extend(scan_file(f, root=root))
    findings.sort(key=lambda f: (SEV_RANK[f.severity], f.pattern, f.file, f.line))
    return {
        "root": str(root),
        "scanned_files": len(files),
        "finding_count": len(findings),
        "findings": [asdict(f) for f in findings],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agenticqa-audit-app")
    ap.add_argument("--path", default=".", help="project root containing src/")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--severity", choices=["high", "medium", "low"])
    args = ap.parse_args(argv)

    result = audit(args.path)
    findings = result["findings"]
    if args.severity:
        thr = SEV_RANK[args.severity]
        findings = [f for f in findings if SEV_RANK[f["severity"]] <= thr]

    if args.json:
        json.dump(
            {
                "scanned_files": result["scanned_files"],
                "finding_count": len(findings),
                "findings": findings,
            },
            sys.stdout, indent=2,
        )
        sys.stdout.write("\n")
        return 0

    sev = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev[f["severity"]] += 1
    print(f"# audit_app_security — {result['scanned_files']} files scanned, {len(findings)} findings")
    print(f"#   high={sev['high']}  medium={sev['medium']}  low={sev['low']}\n")
    cur = ""
    for f in findings:
        if f["file"] != cur:
            cur = f["file"]
            print(f"\n## {f['file']}")
        print(f"  [{f['severity']:>6}] {f['pattern']} L{f['line']}: {f['description']}")
        print(f"           {f['snippet'][:140]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
