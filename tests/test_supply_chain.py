"""Tests for the dependency supply-chain scanner.

Every one of these is a case that came up for real while establishing exposure
to Shai-Hulud on 2026-08-07, including the two that nearly produced a wrong
answer: a pnpm repo read by an npm-only check, and a compromised FAMILY being
mistaken for a compromised VERSION.
"""

from __future__ import annotations

import json

from agenticqa_core.scanners import supply_chain


def _npm_lock(pkgs: dict[str, str]) -> str:
    return json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {"": {"name": "app"}, **{f"node_modules/{n}": {"version": v} for n, v in pkgs.items()}},
        }
    )


# ─── S1: the compromised version itself ────────────────────────────


def test_compromised_version_in_npm_lock_is_high(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text(_npm_lock({"keyv": "6.0.0"}))
    result = supply_chain.audit(tmp_path)
    assert result["compromised_present"] is True
    s1 = [f for f in result["findings"] if f["pattern_id"] == "S1"]
    assert len(s1) == 1
    assert "keyv@6.0.0" in s1[0]["snippet"]
    assert s1[0]["severity"] == "high"


def test_scoped_compromised_package_is_matched(tmp_path):
    """Scoped names survive the node_modules path split. `@cacheable/memory`
    lives at `node_modules/@cacheable/memory`, and a naive basename split
    reduces it to `memory` and matches nothing."""
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text(_npm_lock({"@cacheable/memory": "2.2.1"}))
    assert supply_chain.audit(tmp_path)["compromised_present"] is True


# ─── S2: the family, which is NOT a finding ────────────────────────


def test_clean_version_of_a_compromised_family_does_not_fail_the_gate(tmp_path):
    """The exact case in every Wolfpack repo: keyv 4.5.4 against a compromised
    6.0.0. Reporting that as a hit would flag every repo using a popular
    package and teach everyone to ignore this scanner."""
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text(_npm_lock({"keyv": "4.5.4"}))
    result = supply_chain.audit(tmp_path)
    assert result["compromised_present"] is False
    s2 = [f for f in result["findings"] if f["pattern_id"] == "S2"]
    assert len(s2) == 1
    assert s2[0]["severity"] == "info"
    assert "4.5.4" in s2[0]["description"]


# ─── pnpm, the lockfile that was nearly missed ─────────────────────


def test_pnpm_lock_is_read(tmp_path):
    """An npm-only check found no lockfile in a pnpm repo and would have
    reported 'clean' from having looked at nothing."""
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n\npackages:\n\n  keyv@6.0.0:\n    resolution: {integrity: sha512-x}\n"
    )
    result = supply_chain.audit(tmp_path)
    assert result["compromised_present"] is True


def test_pnpm_parser_handles_scoped_and_leading_slash_forms():
    text = "packages:\n  /@cacheable/memory@2.2.1:\n  keyv@4.5.4:\n  '@qlik/embed-runtime@1.6.4':\n"
    got = dict(supply_chain.parse_pnpm_lock(text))
    assert got["@cacheable/memory"] == "2.2.1"
    assert got["keyv"] == "4.5.4"
    assert got["@qlik/embed-runtime"] == "1.6.4"


def test_npm_v1_nested_dependencies_are_walked():
    text = json.dumps({"dependencies": {"a": {"version": "1.0.0", "dependencies": {"keyv": {"version": "6.0.0"}}}}})
    assert ("keyv", "6.0.0") in supply_chain.parse_npm_lock(text)


# ─── S3/S6: install-script posture ─────────────────────────────────


def test_missing_ignore_scripts_is_flagged_with_its_blast_radius(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {"name": "app"},
                    "node_modules/esbuild": {"version": "0.21.0", "hasInstallScript": True},
                }
            }
        )
    )
    findings = {f["pattern_id"]: f for f in supply_chain.audit(tmp_path)["findings"]}
    assert findings["S3"]["severity"] == "high"
    assert "esbuild" in findings["S6"]["description"]


def test_ignore_scripts_true_clears_the_posture_finding(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / ".npmrc").write_text("# comment\nignore-scripts=true\naudit=true\n")
    assert not [f for f in supply_chain.audit(tmp_path)["findings"] if f["pattern_id"] == "S3"]


def test_posture_is_not_checked_for_a_non_node_repo(tmp_path):
    (tmp_path / "main.py").write_text("print(1)\n")
    assert supply_chain.audit(tmp_path)["findings"] == []


# ─── S4/S5: indicators of compromise ───────────────────────────────


def test_dropper_filename_on_disk_is_flagged(tmp_path):
    (tmp_path / "setup.mjs").write_text("// anything\n")
    ids = {f["pattern_id"] for f in supply_chain.audit(tmp_path)["findings"]}
    assert "S4" in ids


def test_exfil_host_in_content_is_flagged_with_a_line_number(tmp_path):
    (tmp_path / "x.js").write_text("const a = 1;\nfetch('https://npm-cache.com/router');\n")
    hit = [f for f in supply_chain.audit(tmp_path)["findings"] if f["pattern_id"] == "S5"][0]
    assert hit["line"] == 2


def test_node_modules_is_not_scanned(tmp_path):
    """Otherwise every repo reports the dropper the moment a dependency ships a
    file called setup.mjs, and the check becomes noise."""
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "setup.mjs").write_text("// vendor file\n")
    assert supply_chain.audit(tmp_path)["findings"] == []


# ─── exit code contract ────────────────────────────────────────────


def test_cli_exits_zero_on_posture_only_findings(tmp_path, capsys):
    """Posture must NOT fail the gate, or this cannot be switched on in CI
    until a cleanup project that nobody schedules is finished."""
    (tmp_path / "package.json").write_text("{}")
    assert supply_chain.main(["--path", str(tmp_path)]) == 0


def test_cli_exits_nonzero_only_when_actually_compromised(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text(_npm_lock({"flat-cache": "6.1.24"}))
    assert supply_chain.main(["--path", str(tmp_path), "--json"]) == 1


def test_registry_versions_are_exact_never_ranges():
    """A range would match half the ecosystem and train everyone to ignore the
    output. Every entry must be a concrete version string."""
    for name, versions in supply_chain.KNOWN_COMPROMISED.items():
        assert versions, f"{name} has no versions"
        for v in versions:
            assert not any(c in v for c in "^~*x><= "), f"{name}@{v} looks like a range"
