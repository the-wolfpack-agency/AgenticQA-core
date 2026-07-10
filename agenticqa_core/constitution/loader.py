"""
Constitution loader and deterministic enforcement.

Stdlib only, so the Claude Code hooks can run it straight from
~/.claude/settings.json with zero install. The same functions are importable
by any Python runtime (Instinct agents, a LangGraph gate node, a FastAPI
endpoint that serves the constitution to OpenAI agents).

Public API:
    version()                 -> str
    render_markdown()         -> str    the human-readable constitution (AGENTS.md)
    constitution_path()       -> Path   the machine-readable constitution.yaml
    machine_enforced_ids()    -> set[str]  ids marked machine_enforced in the yaml
    check_bash_command(cmd)   -> Verdict   deterministic allow / ask / deny

DENY_RULES below is the canonical source for the machine-enforced patterns.
Each rule id must also appear as `machine_enforced: true` in constitution.yaml.
tests/test_constitution.py fails if the two drift apart.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent


def version() -> str:
    try:
        return (HERE / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"


def constitution_path() -> Path:
    return HERE / "constitution.yaml"


def render_markdown() -> str:
    """The human-readable constitution injected into agent system prompts."""
    try:
        return (HERE / "AGENTS.md").read_text(encoding="utf-8")
    except OSError:
        return ""


def machine_enforced_ids() -> set[str]:
    """
    Ids flagged `machine_enforced: true` in constitution.yaml. Parsed with a
    small regex rather than PyYAML so this module stays stdlib-only. The yaml is
    line-oriented (one `- id:` block per rule) so this is robust enough, and the
    sync test proves it against DENY_RULES.
    """
    text = constitution_path().read_text(encoding="utf-8")
    ids: set[str] = set()
    current: Optional[str] = None
    for line in text.splitlines():
        m = re.match(r'\s*-?\s*id:\s*"([^"]+)"', line)
        if m:
            current = m.group(1)
            continue
        if current and re.match(r"\s*machine_enforced:\s*true\b", line):
            ids.add(current)
            current = current  # keep until next id
    return ids


@dataclass(frozen=True)
class Verdict:
    decision: str            # "allow" | "ask" | "deny"
    rule_id: str = ""
    rule_name: str = ""
    reason: str = ""


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    name: str
    decision: str            # "ask" | "deny"
    pattern: "re.Pattern[str]"
    reason: str
    # Optional second condition the command must ALSO satisfy to trip the rule.
    also: Optional["re.Pattern[str]"] = None


# --- Canonical machine-enforced patterns -----------------------------------
# Keep this list small, high-signal, and tied to a documented incident. Every
# id here must be machine_enforced: true in constitution.yaml.
DENY_RULES: list[_Rule] = [
    _Rule(
        rule_id="T1-003",
        name="no_force_push_to_protected",
        decision="deny",
        # a force flag on git push, targeting main/master
        pattern=re.compile(r"\bgit\s+push\b.*(--force\b|--force-with-lease\b|\s-f\b)", re.I | re.S),
        also=re.compile(r"\b(main|master)\b", re.I),
        reason=(
            "Force-push to a protected branch (main/master) is blocked by the "
            "constitution (T1-003). Branch, open a PR, let CI and review gate it. "
            "Force-with-lease on a FEATURE branch is fine."
        ),
    ),
    _Rule(
        rule_id="T2-005",
        name="vercel_env_rm_needs_preflight",
        decision="ask",
        pattern=re.compile(r"\bvercel\s+env\s+rm\b", re.I),
        reason=(
            "Removing a Vercel env var can strip a combined-scope value from prod "
            "(T2-005). Run the repo's verify:prod-env preflight first, and prefer "
            "re-scoping the add over removing. Confirm you have done this."
        ),
    ),
    _Rule(
        rule_id="T2-003",
        name="destructive_db_op_requires_guard",
        decision="ask",
        pattern=re.compile(r"\b(drop\s+(table|database|schema)|truncate)\b", re.I),
        reason=(
            "Destructive DB op detected (T2-003). Require an explicit guard, an "
            "owner role, and a diff against real data first. Slug-keyed cleanups "
            "have nearly deleted real rows. Confirm the guard is in place."
        ),
    ),
]

def check_bash_command(command: str) -> Verdict:
    """
    Deterministic gate over a shell command. Returns the first matching rule's
    verdict, else allow. Never raises.

    Force-push policy is intentionally narrow: DENY only when a force flag
    targets main/master. Force-with-lease on a feature branch is the operator's
    documented safe re-author path and must pass clean.
    """
    if not command or not command.strip():
        return Verdict("allow")
    cmd = command.strip()
    for rule in DENY_RULES:
        if rule.pattern.search(cmd) and (rule.also is None or rule.also.search(cmd)):
            return Verdict(rule.decision, rule.rule_id, rule.name, rule.reason)
    return Verdict("allow")
