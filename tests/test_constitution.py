"""
Tests for the OGIAM Agent Constitution.

Covers: the loader renders, the machine-enforced rules in constitution.yaml stay
in sync with the enforcement patterns in loader.py, and the deterministic gate
returns the right verdicts for known-dangerous and known-safe commands.
"""

from __future__ import annotations

from agenticqa_core.constitution import loader


def test_version_and_render():
    assert loader.version() != "unknown"
    md = loader.render_markdown()
    assert "OGIAM Agent Constitution" in md
    assert "em dashes" in md.lower()


def test_yaml_and_code_enforcement_in_sync():
    # Every machine-enforced rule in the yaml must have an enforcement pattern
    # in loader.DENY_RULES, and vice versa. This is the guard against drift.
    yaml_ids = loader.machine_enforced_ids()
    code_ids = {r.rule_id for r in loader.DENY_RULES}
    assert yaml_ids == code_ids, f"yaml={yaml_ids} code={code_ids}"


def test_force_push_to_main_is_denied():
    v = loader.check_bash_command("git push --force origin main")
    assert v.decision == "deny"
    assert v.rule_id == "T1-003"


def test_force_with_lease_on_feature_branch_is_allowed():
    # The re-author workflow uses force-with-lease on a feature branch; do not
    # block it.
    v = loader.check_bash_command("git push --force-with-lease origin feat/admin-dealer-os")
    assert v.decision == "allow"


def test_vercel_env_rm_asks():
    v = loader.check_bash_command("vercel env rm DATABASE_URL production")
    assert v.decision == "ask"
    assert v.rule_id == "T2-005"


def test_destructive_db_op_asks():
    v = loader.check_bash_command('psql "$DATABASE_URL" -c "DROP TABLE dealers"')
    assert v.decision == "ask"
    assert v.rule_id == "T2-003"


def test_ordinary_commands_are_allowed():
    for cmd in [
        "git push origin feat/thing",
        "npm run verify",
        "git commit -m 'feat: add widget'",
        "ls -la",
        "npx vercel --prod",
    ]:
        assert loader.check_bash_command(cmd).decision == "allow", cmd


def test_constitution_never_publishes_a_personal_email_address():
    # This repo is public and the constitution is copied into other public repos
    # and injected into model prompts. A rule that names the private address in
    # order to forbid it publishes it. Allowed: the GitHub noreply address and the
    # company domain. Anything else that looks like an email fails.
    import re
    from pathlib import Path

    allowed = re.compile(r"@(users\.noreply\.github\.com|thewolfpack\.agency|anthropic\.com)$", re.I)
    root = Path(loader.__file__).parent
    texts = [loader.render_markdown()] + [p.read_text() for p in root.rglob("*") if p.suffix in {".md", ".yaml", ".yml", ".py"}]
    found = {m for t in texts for m in re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", t)}
    leaked = sorted(e for e in found if not allowed.search(e))
    assert leaked == [], f"personal email addresses in the constitution: {leaked}"
