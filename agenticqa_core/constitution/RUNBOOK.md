# OGIAM Agent Constitution — Runbook (start here)

**Audience:** anyone at Wolfpack who builds with, operates, or extends our agents.
**Goal:** one set of engineering rules and operator preferences that every agent
follows automatically, in every session and every brand, no matter which agent
or model version you get. You stop pasting rules into prompts by hand.

## The 30-second mental model

- There is ONE source of truth: this `constitution/` folder in `AgenticQA-core`.
- Each runtime loads it through its own native mechanism (a Claude Code hook, a
  system prompt, an API `instructions` field). Same rules, everywhere.
- It is enforced by deterministic tooling (a command guard + CI + the OGIAM
  gate), not by hoping the model remembers. That is why a model or agent version
  bump cannot silently drop the rules.

If you only read one thing: **edit the rules HERE, never in a chat prompt.**

---

## 0. Set a path variable (used throughout)

Set `MONO` to wherever you cloned the Wolfpack repos, so every command below is
correct on your machine.

```bash
export MONO="$HOME/mono"   # change to your repos directory
# get the canonical repo:
cd "$MONO" && git clone https://github.com/the-wolfpack-agency/AgenticQA-core.git 2>/dev/null || (cd AgenticQA-core && git pull)
```

## 1. Where everything lives

```
AgenticQA-core/agenticqa_core/constitution/
  AGENTS.md            human-readable rules (what agents read; the old paste template)
  constitution.yaml    tiered machine-readable rules (DENY / REQUIRE_APPROVAL / ADVISE)
  preferences.yaml     identity, style, per-brand deploy pointers
  loader.py            stdlib API + the canonical enforcement patterns (DENY_RULES)
  VERSION              bump on any change
  hooks/session_start.py     Claude Code SessionStart loader
  hooks/pretooluse_guard.py  Claude Code PreToolUse command guard
  README.md            per-runtime adapters (OpenAI, LangGraph, Anthropic)
  RUNBOOK.md           this file
AgenticQA-core/tests/test_constitution.py   keeps constitution.yaml and loader.py in sync

~/.claude/settings.json                      Claude Code global hooks (per machine)

wolfpack-apex/scripts/sync-constitution.mjs        codegen apex's bundled copy
wolfpack-apex/src/lib/constitution/index.ts        apex accessor
wolfpack-apex/src/lib/constitution/generated.ts    committed, DO NOT hand-edit
```

---

## 2. One-time: wire your Claude Code (the IDE) to the constitution

Do this once per laptop. Afterward, every Claude Code session opens with the
rules and that repo's latest handoff already loaded, and a guard blocks known
footguns.

**2a. Back up your settings first.**
```bash
cp ~/.claude/settings.json ~/.claude/settings.json.bak-$(date +%Y%m%d-%H%M%S)
```

**2b. Edit `~/.claude/settings.json`.** Inside the `"hooks"` object:

- In EACH `SessionStart` matcher block (`startup`, `resume`, `compact`), add this
  as a second entry in that block's `"hooks"` array (keep any existing command):
```json
{ "type": "command",
  "command": "python3 REPLACE_MONO/AgenticQA-core/agenticqa_core/constitution/hooks/session_start.py" }
```
- Add a `PreToolUse` key (sibling of `SessionStart`):
```json
"PreToolUse": [
  { "matcher": "Bash",
    "hooks": [
      { "type": "command",
        "command": "python3 REPLACE_MONO/AgenticQA-core/agenticqa_core/constitution/hooks/pretooluse_guard.py" }
    ] }
]
```
Replace `REPLACE_MONO` with your absolute repos path (the value of `$MONO`;
`echo $MONO` to print it). The command must be an absolute path.

**2c. Validate the JSON. A broken settings file silently drops hooks.**
```bash
python3 -m json.tool ~/.claude/settings.json > /dev/null && echo "valid JSON"
```

**2d. Prove the hooks work before trusting them.**
```bash
cd "$MONO/AgenticQA-core"
# SessionStart injects the constitution + the cwd repo's latest handoff:
echo "{\"cwd\":\"$MONO/wolfpack-apex\",\"session_id\":\"t\",\"source\":\"startup\"}" \
  | python3 agenticqa_core/constitution/hooks/session_start.py | python3 -m json.tool | head
# The guard DENIES a force-push to main and stays silent on a safe command:
echo '{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}' \
  | python3 agenticqa_core/constitution/hooks/pretooluse_guard.py
echo '{"tool_name":"Bash","tool_input":{"command":"npm run verify"}}' \
  | python3 agenticqa_core/constitution/hooks/pretooluse_guard.py   # no output = allowed
```
Hooks take effect on your NEXT Claude Code session (they load at session boot).

**What the guard blocks today:** force-push to `main`/`master` (deny),
`vercel env rm` (ask, it can strip a prod var), and a destructive DB op like
`DROP TABLE` / `TRUNCATE` (ask). It fails open, so a bug in the guard can never
wedge your session; it only ever blocks on a real rule match.

---

## 3. Recurring: change a rule (the loop everyone uses)

**3a. Edit the canonical files** in `AgenticQA-core/agenticqa_core/constitution/`:
- Rules agents read: `AGENTS.md`.
- The tiered machine-readable entry: `constitution.yaml`.
- Style / identity / deploy pointers: `preferences.yaml`.
- Bump `VERSION` (for example `1.0.0` to `1.1.0`).

**3b. If the rule must be HARD-ENFORCED on a shell command**, add it in two
places (a test proves they match):
- In `constitution.yaml`, set `machine_enforced: true` on the rule.
- In `loader.py`, add a matching `_Rule` to `DENY_RULES` (a `decision` of
  `"deny"` or `"ask"`, a regex `pattern`, and an optional second `also` regex).

**3c. Test and push the canonical repo.**
```bash
cd "$MONO/AgenticQA-core"
.venv/bin/python -m pytest tests/test_constitution.py -q || python3 -m pytest tests/test_constitution.py -q
git add agenticqa_core/constitution tests/test_constitution.py
git commit -m "constitution: <what changed> (bump vX.Y.Z)"
git push origin main
```
Claude Code picks this up automatically on the next session. Nothing else to do
for the IDE.

**3d. Propagate to apps that BUNDLE the constitution (apex today).**
```bash
cd "$MONO/wolfpack-apex"
git checkout -b chore/constitution-vX.Y.Z origin/main
node scripts/sync-constitution.mjs          # regenerates src/lib/constitution/generated.ts
node scripts/sync-constitution.mjs --check  # prints "in sync"
npx jest src/lib/constitution --no-coverage
git add src/lib/constitution/generated.ts
git commit -m "chore(constitution): sync to vX.Y.Z"
git push -u origin chore/constitution-vX.Y.Z
gh pr create --fill
```
Merge the PR. apex auto-deploys. Confirm it is actually live (section 6).

---

## 4. Integrate the constitution into a NEW app or runtime

**4a. A TS / Next app (the apex pattern).**
1. Copy `scripts/sync-constitution.mjs` in; set `OGIAM_CONSTITUTION_DIR` if the
   `AgenticQA-core` checkout is not a sibling directory.
2. `node scripts/sync-constitution.mjs` to create `src/lib/constitution/generated.ts`.
3. Add an accessor like apex `src/lib/constitution/index.ts`
   (`getConstitution()`, `applyConstitutionToRequest(req)`).
4. At your single AI chokepoint, prepend the constitution when a request opts in;
   set `apply_constitution: true` on the surfaces you want governed.

**4b. OpenAI (Responses / Assistants API)** — the mechanism is `instructions`,
not "skills":
```python
from agenticqa_core.constitution import loader
client.responses.create(model="gpt-...", instructions=loader.render_markdown(), input=user_task)
```

**4c. LangGraph** — system message plus a gate node:
```python
from agenticqa_core.constitution import loader
SYSTEM = loader.render_markdown()
def gate(state):
    v = loader.check_bash_command(state["proposed_command"])
    if v.decision == "deny":
        raise PermissionError(f"{v.rule_id}: {v.reason}")
    return state
```

**4d. Anthropic API direct:**
```python
from agenticqa_core.constitution import loader
client.messages.create(model="claude-...", system=loader.render_markdown(), messages=[...])
```

**4e. Any Python runtime:**
`pip install -e "$MONO/AgenticQA-core"` then `from agenticqa_core.constitution import loader`.

---

## 5. Prove it out

- **Claude Code:** start a new session in any repo. You should see
  "OGIAM Agent Constitution vX.Y.Z" plus that repo's latest handoff at the top.
  In a scratch repo, try `git push --force origin main` and watch the guard deny it.
- **Instinct assistant:** submit a prompt. It follows the rules (no em dashes,
  terse, refuses to invent unrequested features). `ai.completion` analytics carry
  `constitution_applied: true`.
- **OGIAM agents (`/admin/agents`):** assign a task to an agent. The run logs
  `agent.constitution_applied` with the `constitution_version`.

---

## 6. Deploy safety (apex)

apex pushes to `main` auto-deploy. Confirm the live build serves your commit
BEFORE you test (the prod alias lags a minute or two):
```bash
cd "$MONO/wolfpack-apex" && git rev-parse origin/main
curl -s https://wolfpack-instinct.vercel.app/api/version   # sha must match origin/main
# health (expect 200s, never 500):
for p in /api/version /login /; do curl -s -o /dev/null -w "$p %{http_code}\n" https://wolfpack-instinct.vercel.app$p; done
```

## 7. Rollback

- **Claude Code hooks:** `cp ~/.claude/settings.json.bak-<stamp> ~/.claude/settings.json`.
- **A bad rule:** revert the `AgenticQA-core` commit, push, then re-run section 3d
  to re-sync apex.
- **apex integration:** the injection is opt-in and additive, so reverting the
  integration commit removes it cleanly with no data migration.

---

## Rules for changing the rules

- Edit the constitution HERE, never in a chat prompt. A prompt edit helps one
  session; a change here helps every agent, forever.
- Bump `VERSION` on every change so each run records which rules it obeyed.
- Keep the machine-enforced set small and high-signal. A noisy guard gets ignored.
- Never use em dashes anywhere (it is one of the rules).
