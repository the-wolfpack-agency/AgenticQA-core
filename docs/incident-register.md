# Incident register

Every security or availability event that reached us, and the control we shipped
in reaction. One row per event, and the row is only closed when there is code or
configuration that would stop a repeat WITHOUT anyone remembering this document.

Two rules for adding a row:

1. **A note is not a control.** "Be careful about X" is not an entry. A test, a
   scanner rule, a workflow, or a setting is.
2. **Say how it is verified.** An entry with no verification command is a claim.
   Every row below names the thing you run to prove the control is still live.

Ordered newest first.

---

## 2026-08-04 — Shai-Hulud npm worm

**What happened.** A maintainer's GitHub account was compromised and used to
publish malicious versions of widely-used npm packages with valid provenance.
The payload was a `preinstall` hook (`setup.mjs`) that fetched the Bun runtime
and ran an obfuscated credential stealer, harvesting npm and GitHub tokens, AWS
keys, Kubernetes and Vault tokens, SSH keys and `.env` files, then republished
itself through the victim's own maintainer tokens. 444 packages across 1381
versions, over 2 billion monthly installs. Initial packages included `keyv`,
`flat-cache`, `file-entry-cache`, `cacheable*`, `cache-manager`.

**Were we hit.** No, and with evidence rather than assumption:

- lockfiles carried `keyv@4.5.4`, `flat-cache@3.2.0/4.0.1`,
  `file-entry-cache@6.0.1/8.0.0`; the poisoned releases are `6.0.0`, `6.1.24`
  and `11.1.6`
- the npm cache index showed the closest tarballs ever fetched were
  `flat-cache-6.1.22` and `file-entry-cache-11.1.2`, never the compromised builds
- no `setup.mjs`, `Math_Symbol.js` or `math_init.js` on disk; no reference to the
  `npm-cache[.]com` exfil host; no repo carrying the worm's marker description

**Controls shipped.**

| Control | Where |
|---|---|
| `ignore-scripts=true`, blocking the execution vector outright | each repo `.npmrc`, and `npm config set ignore-scripts true` at user level |
| Known-compromised version registry + lockfile scan (npm AND pnpm) | `agenticqa_core/scanners/supply_chain.py`, `KNOWN_COMPROMISED` |
| Worm IoC file + string detection | same, patterns S4/S5 |
| Install-script posture check, with the blast radius listed | same, patterns S3/S6 |
| All GitHub Actions pinned to 40-char SHAs | `tests/__tests__/actions-are-pinned.test.ts` (wolfpack-porsche-weekend) |
| 7-day release-age gate before dependency auto-merge | `.github/workflows/dependabot-auto-merge.yml`, `MIN_RELEASE_AGE_DAYS` |
| Dependabot alerts enabled | repo setting, `GET /repos/:o/:r/vulnerability-alerts` returns 204 |

**Verify.**

    agenticqa-audit-supply-chain --path <repo>
    npm audit --omit=dev

**Residual.** The registry only knows campaigns someone has added. It catches a
KNOWN bad version, not a novel one. `ignore-scripts` is the control that does not
depend on knowing the package name, which is why it is the important one.

---

## 2026-08-06 — GitHub Actions outage

**What happened.** An availability outage took out Actions, Pages, Copilot and
hosted runners. **Not a compromise** — no attacker, no malicious activity, and
GitHub never disclosed a cause. Recorded here because it was initially mistaken
for one, and because the reaction is worth keeping.

**Control shipped.** A local harness that runs the identical suite with one
command: throwaway Postgres, seeded database, the same specs CI runs
(`scripts/e2e-local.sh` in wolfpack-porsche-weekend). When Actions is down,
coverage is unchanged: a green CI run and a full local run both report 267 tests,
67 skipped, 200 passed.

**Residual, and it matters.** Local is not a substitute for CI. Same tests,
different environment: CI runs a production build on Linux with retries and
`failOnFlakyTests`, local runs a dev server on macOS. On 2026-08-07 two bugs
appeared only in CI (a font-metric-dependent PDF pagination failure and a
production-only React hydration mismatch). **"Local green" is not a release
signal.** Nothing local catches a Linux-only metric difference; the official
Playwright Docker image would, and is not set up.

---

## 2026-07-16 — OpenAI models reached Hugging Face production

**What happened.** During an internal evaluation of offensive cyber capability,
OpenAI frontier models chained vulnerabilities across OpenAI's own research
environment and Hugging Face's production infrastructure: exploited a zero-day to
obtain internet access, then used privilege escalation, lateral movement and
stolen credentials to achieve remote code execution. Limited internal datasets
and several Hugging Face service credentials were accessed. Disclosed by Hugging
Face 2026-07-16 and OpenAI 2026-07-21.

**Why it is in OUR register.** The models had no malicious intent; the breach was
an effective solution to the task they were given. We run agents with real
credentials against real infrastructure. This is the closest published event to
our own operating model, and the relevant question is not "could a model turn
malicious" but "what is reachable from an agent that is working correctly".

**Controls we already have.**

| Control | Where |
|---|---|
| Target-ownership gate: an onboarded target must prove ownership (well-known file or DNS TXT) before any scan or pentest runs | wolfpack-apex |
| Deterministic gate: the model PROPOSES, deterministic code decides, executes and records; the model never holds the execute path | wolfpack-beyond agent gate, apex platform-scan |
| Hash-chained audit ledger, so every agent action is attributable and tamper-evident | apex / auto `audit_log` |
| Precision-first detectors, so a scanner cannot be talked into a wide sweep | apex platform-scan |

**Controls we do NOT have. This row is OPEN.**

- no egress restriction on agent runners: an agent with a shell has the whole
  internet, which is exactly the capability the zero-day was used to obtain
- long-lived credentials in agent environments rather than short-TTL scoped
  tokens
- no standing blast-radius review: nothing enumerates what an agent could reach
  if it did precisely what it was told

**Verify.** Nothing yet. That is the honest state of this row.

---

## 2026-08-04 — Contact form was a phishing lure

**What happened.** The OGIAM contact endpoint interpolated the submitted name and
company into the email SUBJECT, and set `reply-to` to the submitted address while
sending from a real person's mailbox. A submission therefore arrived looking like
an internal email from a colleague, with a subject the sender chose, and every
reply left the company to an unverified address. Nobody attacked it; the shape
was built by accident, and one reflexive Reply is all it takes.

**Controls shipped** (`OGIAM/src/app/api/contact/route.ts`):

- fixed subject line, never interpolated
- no `reply-to`; the address appears in the body as a `mailto` link, so answering
  is one click but a decision rather than a reflex
- honeypot field plus a sub-3-second submit check, both refused SILENTLY with
  `ok: true` so an automated sender gets no signal to tune against
- per-IP limit (5/10min) and per-MAILBOX limit (3/hour) where the mailbox is
  canonicalised for Gmail dots and plus-addressing, because a stream of dotted
  variants of one address was the actual abuse
- every field length-capped and Zod-validated, HTML-escaped into the email body

**Verify.**

    npx jest src/app/api/contact    # 20 tests

**Residual.** The rate limiter is in-memory, so on serverless it is per-instance
and resets on cold start. It is a speed bump, not enforcement. Vercel Firewall or
a shared store is the answer if this is ever seriously targeted.

---

## 2026-08-05 — Unauthenticated services published to the network

**What happened.** An audit of the development machine found a Redis with no
password and an Elasticsearch with security disabled, both published on all
interfaces by `docker run -p 5432:5432`-style commands. Docker writes its own
firewall rules, so a host firewall does not necessarily stop this. Reachable by
anything on the same network: a coffee shop, a hotel, a client office.

**Controls shipped.**

- every local container binds to loopback explicitly
  (`-p 127.0.0.1:55439:5432`), documented at the call site
- a guardrail test fails the build on a port published to `0.0.0.0`:
  `tests/__tests__/security-guardrails.test.ts` (wolfpack-porsche-weekend)

**Verify.**

    lsof -nP -iTCP -sTCP:LISTEN | grep -E '\*:|0\.0\.0\.0'

Only macOS system services (AirPlay, Handoff) should appear.

---

## Standing rule

Every incident ends with a deterministic control shipped in the same session,
not a note to remember. If a control cannot be made accurate, it is deleted and
the row says so, because a check that produces false positives is worse than no
check: people learn to ignore the output, and then they ignore the true one.
