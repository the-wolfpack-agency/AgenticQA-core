#!/usr/bin/env python3
"""
Claude Code SessionStart hook: inject the Wolfpack constitution.

Emits the human-readable constitution plus the latest handoff for the repo the
session opened in, as additionalContext, so every session begins with the rules
and the last session's context already in mind. This composes with the Memory
OS SessionStart hook (which injects the recall bundle); they are additive.

Contract: this hook is always a no-op from the user's perspective. Any failure
is logged to stderr and the process exits 0. It must never break a session.

Wire it in ~/.claude/settings.json under hooks.SessionStart.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def _bootstrap_path() -> None:
    # Walk up to the dir that contains the agenticqa_core package.
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


def _latest_handoff(cwd: str) -> str:
    """Newest handoff doc for the repo, if any. Filenames are date-suffixed."""
    if not cwd:
        return ""
    root = Path(cwd)
    candidates: list[Path] = []
    for sub in ("demo", "docs"):
        d = root / sub
        if d.is_dir():
            candidates += list(d.glob("handoff-*.md"))
            candidates += list(d.glob("*handoff*.md"))
    if not candidates:
        return ""
    # Sort by any YYYY-MM-DD in the name, else by mtime.
    def key(p: Path):
        m = re.search(r"(\d{4}-\d{2}-\d{2})", p.name)
        return (m.group(1) if m else "", p.stat().st_mtime)

    latest = sorted(set(candidates), key=key)[-1]
    try:
        body = latest.read_text(encoding="utf-8")
    except OSError:
        return ""
    # Keep it bounded so we do not blow the session context budget.
    if len(body) > 6000:
        body = body[:6000] + "\n\n[handoff truncated - open the file for the rest]"
    return f"## Latest handoff: {latest.name}\n\n{body}"


def main() -> int:
    try:
        from agenticqa_core.constitution import loader
    except Exception as err:  # pragma: no cover - path bootstrap failed
        sys.stderr.write(f"[constitution] import failed: {err}\n")
        return 0

    event = _read_event()
    cwd = event.get("cwd", "")

    parts = [
        f"# Wolfpack Engineering Constitution v{loader.version()}",
        "This is the operative rule set for this session. It is enforced by "
        "deterministic tooling (a PreToolUse guard + CI), not by model memory, "
        "so it holds regardless of which agent version is running.",
        loader.render_markdown(),
    ]
    handoff = _latest_handoff(cwd)
    if handoff:
        parts.append(handoff)

    text = "\n\n".join(p for p in parts if p.strip())
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": text,
        }
    }
    sys.stdout.write(json.dumps(payload))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as err:  # pragma: no cover
        sys.stderr.write(f"[constitution] SessionStart failed: {err}\n")
        sys.exit(0)
