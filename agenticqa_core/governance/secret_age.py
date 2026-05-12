"""List every GitHub Actions / Dependabot secret with its age.

Emits a warning when any secret exceeds the rotation TTL. GitHub API
does NOT expose secret values — only metadata (name + created_at +
updated_at). That's all we need to enforce rotation cadence.

Usage:
    GITHUB_TOKEN=... agenticqa-secret-age \\
        --repo the-wolfpack-agency/wolfpack-apex \\
        --max-age-days 90
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

__all__ = ["gh_api", "list_repo_secrets", "list_dependabot_secrets", "compute_ages", "main"]


def gh_api(token: str, path: str) -> dict:
    req = urllib.request.Request(
        f"https://api.github.com{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "agenticqa-secret-age-tracker",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        return json.loads(resp.read())


def list_repo_secrets(token: str, repo: str) -> list[dict]:
    data = gh_api(token, f"/repos/{repo}/actions/secrets")
    return data.get("secrets", [])


def list_dependabot_secrets(token: str, repo: str) -> list[dict]:
    try:
        data = gh_api(token, f"/repos/{repo}/dependabot/secrets")
        return data.get("secrets", [])
    except urllib.error.HTTPError:
        return []


def compute_ages(
    secrets_by_kind: dict[str, list[dict]],
    *,
    max_age_days: int,
    now: datetime | None = None,
) -> tuple[list[dict], list[dict]]:
    """Return (rotated_recently, stale) lists. Pure for testing."""
    now = now or datetime.now(timezone.utc)
    rotated: list[dict] = []
    stale: list[dict] = []
    for kind, secrets in secrets_by_kind.items():
        for s in secrets:
            updated = s.get("updated_at") or s.get("created_at")
            if not updated:
                continue
            age = (now - datetime.fromisoformat(updated.replace("Z", "+00:00"))).days
            row = {"kind": kind, "name": s["name"], "age_days": age, "updated_at": updated}
            (stale if age > max_age_days else rotated).append(row)
    return rotated, stale


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agenticqa-secret-age")
    p.add_argument("--repo", required=True, help="owner/name")
    p.add_argument("--max-age-days", type=int, default=90)
    args = p.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        print("error: GITHUB_TOKEN or GH_TOKEN env var required", file=sys.stderr)
        return 2

    actions_secrets = list_repo_secrets(token, args.repo)
    dependabot_secrets = list_dependabot_secrets(token, args.repo)

    rotated, stale = compute_ages(
        {"actions": actions_secrets, "dependabot": dependabot_secrets},
        max_age_days=args.max_age_days,
    )
    out = {
        "repo": args.repo,
        "max_age_days": args.max_age_days,
        "rotated_recently": rotated,
        "stale": stale,
        "stale_count": len(stale),
    }
    print(json.dumps(out, indent=2))
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
