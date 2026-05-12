# AgenticQA-core

Single source of truth for AgenticQA's non-bounty pipeline components: Python
scanner / probe / governance modules and reusable GitHub Actions workflows.

Consumed by every Wolfpack product repo (wolfpack-auto, wolfpack-apex,
wolfpack-feed, wolfpack-lms, wolfpack-site-template, wolfpack-weekend,
wolfpack-aidan-mulready) so we stop duplicating five maintenance-burden scripts
across seven repos.

## Install

```bash
pip install git+https://github.com/the-wolfpack-agency/AgenticQA-core.git
```

Local development:

```bash
git clone git@github.com:the-wolfpack-agency/AgenticQA-core.git
cd AgenticQA-core
pip install -e ".[dev]"
pytest
```

## CLI entrypoints

After install, eight console scripts plus a top-level `agenticqa` dispatcher
are available:

| Command | Purpose |
|---|---|
| `agenticqa-probe-headers <url>` | Probe deployed URL for recommended security response headers. |
| `agenticqa-probe-errors <url>` | Hit error-trigger endpoints; assert no stack / path / framework leaks. |
| `agenticqa-branch-protection --repo owner/name [--apply]` | Assert (and optionally apply) GitHub branch protection. |
| `agenticqa-secret-age --repo owner/name [--max-age-days N]` | List GitHub secrets and flag rotation drift. |
| `agenticqa-audit-app [--json]` | 18-pattern application security audit for Next.js + Postgres stacks. |
| `agenticqa-audit-history [--json] [--since=YYYY-MM-DD]` | Scan git log + source for client-name / PII exposure. |
| `agenticqa-sre-autofix [--path .] [--dry-run]` | Multi-language auto-fix (ts, python, go, rust, ruby, java, php). |
| `agenticqa-sdet-trend <jest-results.json>` | Emit a JSONL trend record for SDET benchmarking. |

Dispatcher form:

```bash
agenticqa probe-headers https://example.com
agenticqa audit-app --json
```

## Reusable workflow usage

From a consumer repo (`wolfpack-auto/.github/workflows/nightly-dast.yml`):

```yaml
name: Nightly DAST

on:
  schedule:
    - cron: "0 4 * * *"
  workflow_dispatch:

permissions:
  contents: read
  issues: write

jobs:
  dast:
    uses: the-wolfpack-agency/AgenticQA-core/.github/workflows/nightly-dast.yml@main
    with:
      prod_url: ${{ vars.PROD_URL }}
    secrets:
      SMOKE_TEST_EMAIL: ${{ secrets.SMOKE_TEST_EMAIL }}
      SMOKE_TEST_PASSWORD: ${{ secrets.SMOKE_TEST_PASSWORD }}
```

Available reusable workflows (`.github/workflows/`):

- `nightly-dast.yml` — security headers + error-disclosure probes.
- `red-team-governance.yml` — branch-protection enforcement check.
- `security-governance.yml` — secret-age drift report.
- `sdet-trend-benchmark.yml` — record SDET trend record from jest JSON.
- `pipeline-validation.yml` — runs the app-security + history-exposure audits.

## Layout

```
agenticqa_core/
  probes/              security_headers, error_disclosure
  governance/          branch_protection, secret_age
  scanners/            app_security, history_exposure, sre_autofix
  benchmarks/          sdet_trend
  cli.py               unified dispatcher
.github/workflows/     reusable workflows + CI for this repo
tests/                 pytest suite
```

## License

Proprietary. See `LICENSE`.
