"""Tests for branch_protection + secret_age governance utilities."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agenticqa_core.governance import branch_protection, secret_age


def test_diff_no_drift_when_current_matches_desired():
    current = dict(branch_protection.DESIRED)
    # Wrap any bool-with-enabled in API shape
    current["enforce_admins"] = {"enabled": True}
    drift = branch_protection.diff(current)
    assert drift == {}


def test_diff_reports_disabled_force_push_blocker():
    current = {**branch_protection.DESIRED, "allow_force_pushes": True}
    drift = branch_protection.diff(current)
    assert "allow_force_pushes" in drift
    assert drift["allow_force_pushes"]["current"] is True
    assert drift["allow_force_pushes"]["desired"] is False


def test_diff_picks_up_nested_pr_review_drift():
    current = dict(branch_protection.DESIRED)
    current["required_pull_request_reviews"] = {
        "dismiss_stale_reviews": False,  # drift
        "require_code_owner_reviews": False,
        "required_approving_review_count": 1,
    }
    drift = branch_protection.diff(current)
    assert "required_pull_request_reviews" in drift
    sub = drift["required_pull_request_reviews"]
    assert "dismiss_stale_reviews" in sub


def test_branch_protection_main_requires_token(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    rc = branch_protection.main(["--repo", "owner/name"])
    assert rc == 2
    assert "GITHUB_TOKEN" in capsys.readouterr().err


def test_compute_ages_partitions_correctly():
    now = datetime(2026, 5, 12, tzinfo=timezone.utc)
    fresh = (now - timedelta(days=5)).isoformat().replace("+00:00", "Z")
    old = (now - timedelta(days=200)).isoformat().replace("+00:00", "Z")
    secrets_by_kind = {
        "actions": [
            {"name": "FRESH", "updated_at": fresh},
            {"name": "OLD", "updated_at": old},
        ],
        "dependabot": [],
    }
    rotated, stale = secret_age.compute_ages(secrets_by_kind, max_age_days=90, now=now)
    assert len(rotated) == 1
    assert rotated[0]["name"] == "FRESH"
    assert len(stale) == 1
    assert stale[0]["name"] == "OLD"
    assert stale[0]["age_days"] == 200


def test_compute_ages_handles_missing_timestamp():
    rotated, stale = secret_age.compute_ages(
        {"actions": [{"name": "NO_DATE"}]},
        max_age_days=30,
    )
    assert rotated == [] and stale == []


def test_secret_age_main_requires_token(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    rc = secret_age.main(["--repo", "owner/name"])
    assert rc == 2
    assert "GITHUB_TOKEN" in capsys.readouterr().err
