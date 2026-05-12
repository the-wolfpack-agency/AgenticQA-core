"""Tests for app_security + history_exposure + sre_autofix scanners."""

from __future__ import annotations

import subprocess

import pytest

from agenticqa_core.scanners import app_security, history_exposure, sre_autofix

# ─── app_security ──────────────────────────────────────────────────


def test_app_security_admin_route_without_require_auth_flags_a1():
    text = (
        "export async function GET(req: Request) {\n"
        "  return Response.json({ ok: true });\n"
        "}\n"
    )
    findings = app_security.scan_text(
        "src/app/api/admin/users/route.ts", "route.ts", text, "admin_route"
    )
    codes = {f.pattern for f in findings}
    assert "A1" in codes


def test_app_security_admin_route_with_require_auth_no_a1():
    text = (
        "import { requireAuth } from '@/lib/auth-guard';\n"
        "export async function GET(req: Request) {\n"
        "  const session = await requireAuth(req);\n"
        "  return Response.json({ ok: true });\n"
        "}\n"
    )
    findings = app_security.scan_text(
        "src/app/api/admin/users/route.ts", "route.ts", text, "admin_route"
    )
    codes = {f.pattern for f in findings}
    assert "A1" not in codes


def test_app_security_public_mutating_route_without_rate_limit_flags_a2():
    text = (
        "export async function POST(req: Request) {\n"
        "  return Response.json({ ok: true });\n"
        "}\n"
    )
    findings = app_security.scan_text(
        "src/app/api/contact/route.ts", "route.ts", text, "public_route"
    )
    assert any(f.pattern == "A2" for f in findings)


def test_app_security_webhook_route_without_signature_flags_a6():
    text = "export async function POST(req: Request) { return Response.json({}); }\n"
    findings = app_security.scan_text(
        "src/app/api/webhooks/stripe/route.ts", "route.ts", text, "webhook_route"
    )
    assert any(f.pattern == "A6" for f in findings)


def test_app_security_hardcoded_secret_flags_a16():
    # Build the test-fixture key dynamically so GitHub secret-scanning
    # doesn't treat this test source as a leaked secret.
    fake_key = "sk_" + "live" + "_" + ("a" * 24)
    text = f'const k = "{fake_key}";\n'
    findings = app_security.scan_text(
        "src/lib/foo.ts", "foo.ts", text, "lib"
    )
    assert any(f.pattern == "A16" for f in findings)


def test_app_security_audit_returns_empty_for_missing_src(tmp_path):
    result = app_security.audit(tmp_path)
    assert result["scanned_files"] == 0
    assert result["finding_count"] == 0


def test_app_security_audit_finds_files_in_tmp_repo(tmp_path):
    src = tmp_path / "src" / "app" / "api" / "admin" / "test"
    src.mkdir(parents=True)
    (src / "route.ts").write_text(
        "export async function GET(req: Request) {\n"
        "  return Response.json({ ok: true });\n"
        "}\n"
    )
    result = app_security.audit(tmp_path)
    assert result["scanned_files"] == 1
    assert result["finding_count"] >= 1
    assert any(f["pattern"] == "A1" for f in result["findings"])


# ─── history_exposure ─────────────────────────────────────────────


def test_history_exposure_audit_empty_repo(tmp_path):
    result = history_exposure.audit(tmp_path)
    assert result["finding_count"] == 0


def test_history_exposure_flags_sensitive_name_in_source(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "demo.tsx").write_text("// Aidan Mulready was here\nexport default null;\n")
    result = history_exposure.audit(tmp_path)
    assert result["finding_count"] >= 1
    assert any(f["pattern"] == "H5" for f in result["findings"])


def test_history_exposure_scan_text_for_sensitive_finds_unique():
    matches = list(history_exposure.scan_text_for_sensitive("see CFTR docs"))
    assert len(matches) == 1
    assert matches[0].group(0) == "CFTR"


def test_history_exposure_scan_commits_in_real_git(tmp_path):
    """Initialize a tiny repo with a tainted commit and confirm detection."""
    try:
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@t"], check=True)
        subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "t"], check=True)
        subprocess.run(["git", "-C", str(tmp_path), "config", "commit.gpgsign", "false"], check=True)
        (tmp_path / "f.txt").write_text("x")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(tmp_path), "commit", "-q", "-m", "wip for Avis client"],
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        pytest.skip("git not available")
    result = history_exposure.audit(tmp_path)
    assert any(f["pattern"] == "H1" for f in result["findings"])


# ─── sre_autofix ─────────────────────────────────────────────────


def test_sre_autofix_detect_stack_python(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    stacks = sre_autofix.detect_stack(str(tmp_path))
    assert "python" in stacks


def test_sre_autofix_detect_stack_typescript(tmp_path):
    (tmp_path / "tsconfig.json").write_text("{}")
    (tmp_path / "package.json").write_text("{}")
    stacks = sre_autofix.detect_stack(str(tmp_path))
    assert "typescript" in stacks


def test_sre_autofix_detect_stack_unknown(tmp_path):
    stacks = sre_autofix.detect_stack(str(tmp_path))
    assert stacks == ["unknown"]


def test_sre_autofix_fixers_registry_complete():
    for stack in ("typescript", "python", "go", "rust", "ruby", "java", "php"):
        assert stack in sre_autofix.FIXERS
