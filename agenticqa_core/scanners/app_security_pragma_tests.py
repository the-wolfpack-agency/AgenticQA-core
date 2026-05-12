"""Self-tests for `app_security` pragma suppression.

Run as part of the security-audit workflow so that pragma support for
A3/A4/A5/A6/A8 cannot silently regress. Runs in-memory using fixture
inputs - no filesystem, no network.

Run:  agenticqa-test-app-security-pragmas
Exits 0 on success, 1 on any failure.
"""

from __future__ import annotations

import sys
from pathlib import Path

from agenticqa_core.scanners import app_security


def _scan(text: str, rel_path: str) -> list[app_security.Finding]:
    """Run the in-memory scanner with synthesized rel_path + role."""
    basename = rel_path.rsplit("/", 1)[-1]
    role = app_security.file_role(Path("/repo") / rel_path)
    return app_security.scan_text(rel_path, basename, text, role)


def _expect(
    label: str,
    findings: list[app_security.Finding],
    pattern: str,
    *,
    present: bool,
) -> bool:
    matched = [f for f in findings if f.pattern == pattern]
    actually_present = bool(matched)
    if actually_present != present:
        print(f"FAIL {label}: expected pattern {pattern} present={present}, got {matched}")
        return False
    print(f"  ok  {label}")
    return True


def run_self_tests() -> bool:
    ok = True

    # A4 - cross-tenant SQL pragma
    sql_no_pragma = """
import { requireAuth } from "@/lib/auth-guard";
export async function POST() {
  await requireAuth();
  await query(`INSERT INTO dealers (id, name) VALUES ($1, $2)`, [a, b]);
}
"""
    f = _scan(sql_no_pragma, "src/app/api/admin/x/route.ts")
    ok &= _expect("A4 fires when admin SQL has no dealer_id and no pragma", f, "A4", present=True)

    sql_with_pragma = """
import { requireAuth } from "@/lib/auth-guard";
export async function POST() {
  await requireAuth();
  await query( /* audit-safe: A4 reason="creating tenant" */
    `INSERT INTO dealers (id, name) VALUES ($1, $2)`, [a, b]);
}
"""
    f = _scan(sql_with_pragma, "src/app/api/admin/x/route.ts")
    ok &= _expect("A4 suppressed by inline pragma", f, "A4", present=False)

    # A5 - dangerouslySetInnerHTML pragma
    html_no_pragma = """
export default function Page() {
  return <div dangerouslySetInnerHTML={{ __html: untrusted }} />;
}
"""
    f = _scan(html_no_pragma, "src/app/page.tsx")
    ok &= _expect("A5 fires on bare dangerouslySetInnerHTML", f, "A5", present=True)

    html_with_pragma_jsx_comment = """
export default function Page() {
  return (
    <>
      {/* audit-safe: A5 reason="JSON-LD of static strings, JSON-encoded" */}
      <script dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
    </>
  );
}
"""
    f = _scan(html_with_pragma_jsx_comment, "src/app/page.tsx")
    ok &= _expect("A5 suppressed by JSX comment pragma on prior line", f, "A5", present=False)

    long_reason = "A" * 250
    html_with_long_pragma = f"""
export default function Page() {{
  return (
    <>
      {{/* audit-safe: A5 reason="{long_reason}" */}}
      <script dangerouslySetInnerHTML={{{{ __html: x }}}} />
    </>
  );
}}
"""
    f = _scan(html_with_long_pragma, "src/app/page.tsx")
    ok &= _expect("A5 suppressed by pragma even with 250-char reason on prior line", f, "A5", present=False)

    # A6 - webhook signature pragma + broadened regex
    webhook_no_sig = """
export async function POST(request) {
  const body = await request.json();
  await processWebhook(body);
  return NextResponse.json({ ok: true });
}
"""
    f = _scan(webhook_no_sig, "src/app/api/webhooks/foo/route.ts")
    ok &= _expect("A6 fires when webhook route has no signature call", f, "A6", present=True)

    webhook_twilio = """
import { validateTwilioSignature } from "@/lib/sms";
export async function POST(request) {
  if (!validateTwilioSignature(sig, url, params)) return NextResponse.json({}, { status: 403 });
  return NextResponse.json({ ok: true });
}
"""
    f = _scan(webhook_twilio, "src/app/api/webhooks/twilio/route.ts")
    ok &= _expect("A6 NOT fired when validateTwilioSignature is called (broadened regex)", f, "A6", present=False)

    webhook_pragma = """
// audit-safe: A6 reason="signature verified by upstream proxy"
export async function POST(request) {
  return NextResponse.json({ ok: true });
}
"""
    f = _scan(webhook_pragma, "src/app/api/webhooks/baz/route.ts")
    ok &= _expect("A6 suppressed by file-level pragma", f, "A6", present=False)

    # A8 - secret-shaped console.* pragma
    log_no_pragma = """
export async function GET() {
  console.error("token=" + tok);
}
"""
    f = _scan(log_no_pragma, "src/app/api/admin/x/route.ts")
    ok &= _expect("A8 fires on bare secret-named console.error", f, "A8", present=True)

    log_pragma = """
export async function GET() {
  // audit-safe: A8 reason="literal env var NAME, value not logged"
  console.warn("[x] No DATABASE_URL - skipping");
}
"""
    f = _scan(log_pragma, "src/app/api/admin/x/route.ts")
    ok &= _expect("A8 suppressed by inline pragma", f, "A8", present=False)

    return ok


def main(argv: list[str] | None = None) -> int:  # noqa: ARG001
    ok = run_self_tests()
    print()
    if ok:
        print("All app_security pragma self-tests passed.")
        return 0
    print("Self-test failures detected.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
