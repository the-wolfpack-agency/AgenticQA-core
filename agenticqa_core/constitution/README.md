# OGIAM Agent Constitution

One source of truth for how every OGIAM-governed agent works, across every
Wolfpack Agency repo and every runtime. OGIAM is the agent identity + governance
product; Wolfpack Agency owns the repos. Edit it here once; every agent picks up the change. Stop pasting rules
into sessions by hand.

## Files

| File | What it is |
|---|---|
| `AGENTS.md` | Human-readable constitution. Injected into agent system prompts. This is what used to be the paste template. |
| `constitution.yaml` | Machine-readable, tiered rules (DENY / REQUIRE_APPROVAL / ADVISE). |
| `preferences.yaml` | Operator style + workflow defaults (identity, terse, no em dashes, deploy pointers). |
| `loader.py` | Stdlib API: `render_markdown()`, `check_bash_command()`, `machine_enforced_ids()`. The enforcement patterns live here, once. |
| `hooks/session_start.py` | Claude Code SessionStart hook: injects the constitution + latest handoff. |
| `hooks/pretooluse_guard.py` | Claude Code PreToolUse hook: deny/ask on machine-enforced rule matches. |
| `VERSION` | Constitution version. Bump on any rule change. |

## Why this fixes cross-session inconsistency

The rules are enforced by deterministic tooling (a PreToolUse guard + CI), not
by model memory. A model or agent version change cannot silently drop them: the
SessionStart hook still injects them and the guard still blocks violations.

## Per-runtime adapters

### Claude Code (this IDE)
Wired in `~/.claude/settings.json`:
```jsonc
{
  "hooks": {
    "SessionStart": [
      { "matcher": "startup|resume|compact",
        "hooks": [{ "type": "command",
          "command": "python3 /Users/nicholashomyk/mono/AgenticQA-core/agenticqa_core/constitution/hooks/session_start.py" }] }
    ],
    "PreToolUse": [
      { "matcher": "Bash",
        "hooks": [{ "type": "command",
          "command": "python3 /Users/nicholashomyk/mono/AgenticQA-core/agenticqa_core/constitution/hooks/pretooluse_guard.py" }] }
    ]
  }
}
```

### OpenAI (Responses / Assistants API)
The native mechanism is the `instructions` / system message, NOT "skills".
```python
from agenticqa_core.constitution import loader
client.responses.create(model="gpt-...", instructions=loader.render_markdown(), input=user_task)
```

### LangGraph
Prepend to the system message and add a gate node before any tool/mutation.
```python
from agenticqa_core.constitution import loader
SYSTEM = loader.render_markdown()
def gate(state):
    v = loader.check_bash_command(state["proposed_command"])
    if v.decision == "deny":
        raise PermissionError(f"{v.rule_id}: {v.reason}")
    return state
```

### Anthropic API direct
```python
from agenticqa_core.constitution import loader
client.messages.create(model="claude-...", system=loader.render_markdown(), messages=[...])
```

### Instinct agents (next slice)
Load `render_markdown()` at the top of `buildSystemPrompt()` in wolfpack-apex,
and route mutations through OGIAM `authorize()`. Serve the constitution over
HTTP so non-Python runtimes fetch the same bytes.

## Editing rules

Change `AGENTS.md` for prose, `constitution.yaml` for the tiered rule set, and
`loader.py` `DENY_RULES` for a new machine-enforced pattern. If you add a
machine-enforced rule, add `machine_enforced: true` in the yaml AND a matching
`_Rule` in `loader.py` (the sync test enforces this). Bump `VERSION`.
