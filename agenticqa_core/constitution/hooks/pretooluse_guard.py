#!/usr/bin/env python3
"""
Claude Code PreToolUse hook: enforce the machine-enforced constitution rules.

Runs before every Bash tool call. If the command trips a machine-enforced rule
(force-push to a protected branch, `vercel env rm`, a destructive DB op) it
returns a deny or ask decision with the rule's rationale. This is the layer that
makes the rules stick: they are enforced deterministically instead of hoping the
model remembers them.

Contract: fail OPEN. If anything goes wrong we allow the action and log to
stderr, so a bug in the guard can never wedge the operator's session. Blocking
is only ever a deliberate rule match.

Wire it in ~/.claude/settings.json under hooks.PreToolUse with matcher "Bash".
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _bootstrap_path() -> None:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "agenticqa_core" / "constitution").is_dir():
            if str(parent) not in sys.path:
                sys.path.insert(0, str(parent))
            return


_bootstrap_path()


def _read_event() -> dict:
    data = sys.stdin.read()
    if not data.strip():
        return {}
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return {}


def _emit(decision: str, reason: str) -> None:
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,          # "deny" | "ask"
            "permissionDecisionReason": reason,
        }
    }
    sys.stdout.write(json.dumps(payload))
    sys.stdout.flush()


def main() -> int:
    event = _read_event()
    if event.get("tool_name") != "Bash":
        return 0
    command = (event.get("tool_input") or {}).get("command", "")
    if not command:
        return 0

    try:
        from agenticqa_core.constitution import loader
    except Exception as err:  # pragma: no cover - fail open
        sys.stderr.write(f"[constitution] guard import failed, allowing: {err}\n")
        return 0

    verdict = loader.check_bash_command(command)
    if verdict.decision in ("deny", "ask"):
        _emit(verdict.decision, f"[{verdict.rule_id} {verdict.rule_name}] {verdict.reason}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as err:  # pragma: no cover - fail open
        sys.stderr.write(f"[constitution] PreToolUse guard failed, allowing: {err}\n")
        sys.exit(0)
