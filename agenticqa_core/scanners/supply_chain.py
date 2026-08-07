"""Dependency supply-chain audit: known-compromised versions, install-script
posture, and worm indicators of compromise.

WHY THIS EXISTS SEPARATELY FROM cicd_security

`cicd_security` audits the WORKFLOW: are actions pinned, are token permissions
least-privilege, does CI install with --ignore-scripts. All necessary, none of
it answers the question a maintainer actually asks the morning a supply-chain
worm is disclosed:

    "Are we running any of the poisoned versions, and did we ever install one?"

That is a DEPENDENCY question, and it is answered from lockfiles, the install
script posture of the repo itself, and the artefacts a worm leaves behind. This
module is that half.

Written on 2026-08-07 while establishing exposure to Shai-Hulud, where the
answer took six ad-hoc greps across twelve repositories. The point of a rule set
is that the thirteenth repository, and the next campaign, cost one command.

Patterns:
  S1  a KNOWN-COMPROMISED package@version is pinned in a lockfile
  S2  a compromised package FAMILY is present (any version) - not a finding on
      its own, reported as informational so an operator can see the blast radius
  S3  the repo does not set ignore-scripts, so `npm install` will execute
      lifecycle hooks (the mechanism this class of attack uses)
  S4  a worm indicator-of-compromise FILE is on disk
  S5  a worm indicator-of-compromise STRING (exfil host, marker) is in a file
  S6  a package that declares an install script is present while ignore-scripts
      is off (informational: the blast radius of S3)

Both npm (`package-lock.json`) and pnpm (`pnpm-lock.yaml`) lockfiles are read.
That is not thoroughness for its own sake: the first repo checked by hand during
the Shai-Hulud review used pnpm, the npm-only check found no lockfile, and a
"clean" result was very nearly reported from having looked at nothing.

Usage:
    agenticqa-audit-supply-chain
    agenticqa-audit-supply-chain --path some/repo
    agenticqa-audit-supply-chain --json > supply.json
    agenticqa-audit-supply-chain --severity high
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

__all__ = [
    "Finding",
    "KNOWN_COMPROMISED",
    "IOC_FILENAMES",
    "IOC_STRINGS",
    "audit",
    "scan_lockfiles",
    "scan_install_posture",
    "scan_iocs",
    "parse_npm_lock",
    "parse_pnpm_lock",
    "main",
]


@dataclass
class Finding:
    pattern_id: str
    file: str
    line: int
    severity: str  # high | medium | low | info
    description: str
    snippet: str


SEV_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


# ─── the compromised-version registry ──────────────────────────────
#
# package name -> the exact versions known to carry the payload.
#
# EXACT VERSIONS, never ranges. The whole value of this check is telling an
# operator "you are clean" with evidence, and a range would flag every repo
# using a popular package and teach everyone to ignore the output. During the
# Shai-Hulud review the repos carried keyv 4.5.4 against a compromised 6.0.0:
# same family, nowhere near the same risk.
#
# Add a campaign by adding its versions here. Nothing else needs to change.
KNOWN_COMPROMISED: dict[str, set[str]] = {
    # Shai-Hulud, npm, from 2026-08-04. Maintainer GitHub account compromised,
    # payload injected as a `preinstall` hook (setup.mjs) that fetched Bun and
    # ran an obfuscated credential stealer, then republished itself through the
    # victim's own maintainer tokens. 444 packages / 1381 versions.
    "keyv": {"6.0.0"},
    "flat-cache": {"6.1.24"},
    "file-entry-cache": {"11.1.6"},
    "cacheable-request": {"13.0.20"},
    "cacheable": {"2.5.1"},
    "cache-manager": {"7.2.10"},
    "ecto": {"5.0.1"},
    "@cacheable/memory": {"2.2.1"},
    "@cacheable/node-cache": {"3.1.2"},
    "@cacheable/utils": {"2.5.1"},
    "@cacheable/net": {"2.1.1"},
    "@deliveroo/reevent": {"1.0.1"},
    "@or-sdk/invitations": {"1.4.9"},
    "@picsart/ai-sdk": {"3.32.2"},
    "@qlik/embed-runtime": {"1.6.4"},
    "picasso.js": {"2.11.6"},
}

# Files the worm drops. Name alone is enough to warrant a look; the published
# SHA-256es are recorded in the description so an operator can confirm.
IOC_FILENAMES: dict[str, str] = {
    "setup.mjs": (
        "Shai-Hulud preinstall dropper "
        "(sha256 54dc7ea5...b350668, community variant fd3ca400...84b1eb)"
    ),
    "Math_Symbol.js": "Shai-Hulud credential-stealer payload (sha256 9fc2570b...9cf1bcc)",
    "math_init.js": "Shai-Hulud credential-stealer payload, alternate name",
}

# Strings that should never appear in a source tree.
IOC_STRINGS: dict[str, str] = {
    "npm-cache.com": "Shai-Hulud exfiltration endpoint (npm-cache[.]com/router)",
    "eth-mainnet.nodereal.io": "Shai-Hulud dead-drop resolver host",
    "Shai-Hulud: Here We Go Again": "worm marker, used on repos it publishes stolen data to",
}

SKIP_DIRS = ("/node_modules/", "/.git/", "/.next/", "/dist/", "/build/", "/coverage/")

# pnpm lockfile entries look like:  /keyv@4.5.4:  or  keyv@4.5.4:
RE_PNPM_ENTRY = re.compile(r"^\s{0,4}'?/?((?:@[^/@\s]+/)?[^@/\s']+)@([0-9][^:'\s(]*)'?:", re.MULTILINE)


def _skipped(path: Path) -> bool:
    p = "/" + str(path).replace("\\", "/").lstrip("/")
    return any(s in p for s in SKIP_DIRS)


# ─── lockfile parsing ──────────────────────────────────────────────


def parse_npm_lock(text: str) -> list[tuple[str, str]]:
    """(name, version) for every entry in a package-lock.json."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    out: list[tuple[str, str]] = []
    for key, meta in (data.get("packages") or {}).items():
        if not isinstance(meta, dict):
            continue
        version = meta.get("version")
        if not version:
            continue
        # "node_modules/a/node_modules/@scope/b" -> "@scope/b"; "" is the root.
        name = key.split("node_modules/")[-1] if "node_modules/" in key else key
        if name:
            out.append((name, str(version)))
    # v1 lockfiles use "dependencies" with nesting.
    def walk(deps: dict) -> None:
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict):
                if meta.get("version"):
                    out.append((name, str(meta["version"])))
                walk(meta.get("dependencies") or {})

    walk(data.get("dependencies") or {})
    return out


def parse_pnpm_lock(text: str) -> list[tuple[str, str]]:
    """(name, version) for every entry in a pnpm-lock.yaml.

    Parsed with a regex rather than a YAML library on purpose: this package
    takes no third-party dependencies, and a supply-chain scanner that installs
    packages to do its job is an argument against itself.
    """
    return [(m.group(1), m.group(2)) for m in RE_PNPM_ENTRY.finditer(text)]


def scan_lockfiles(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    locks = [p for p in root.rglob("package-lock.json") if not _skipped(p)]
    locks += [p for p in root.rglob("pnpm-lock.yaml") if not _skipped(p)]

    for lock in locks:
        try:
            text = lock.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        entries = parse_npm_lock(text) if lock.name == "package-lock.json" else parse_pnpm_lock(text)
        rel = str(lock.relative_to(root))
        seen_family: dict[str, set[str]] = {}
        for name, version in entries:
            if name not in KNOWN_COMPROMISED:
                continue
            seen_family.setdefault(name, set()).add(version)
            if version in KNOWN_COMPROMISED[name]:
                findings.append(
                    Finding(
                        "S1",
                        rel,
                        0,
                        "high",
                        f"{name}@{version} is a KNOWN-COMPROMISED release. Remove it, then "
                        f"rotate every credential reachable from any machine that installed it.",
                        f"{name}@{version}",
                    )
                )
        for name, versions in sorted(seen_family.items()):
            clean = sorted(v for v in versions if v not in KNOWN_COMPROMISED[name])
            if clean:
                findings.append(
                    Finding(
                        "S2",
                        rel,
                        0,
                        "info",
                        f"{name} present at {', '.join(clean)}; compromised release(s) are "
                        f"{', '.join(sorted(KNOWN_COMPROMISED[name]))}. Not affected, shown so the "
                        f"blast radius is visible rather than assumed.",
                        f"{name}@{','.join(clean)}",
                    )
                )
    return findings


# ─── install-script posture ────────────────────────────────────────


def scan_install_posture(root: Path) -> list[Finding]:
    """Does this repo stop `npm install` executing lifecycle hooks?

    This is the mechanism, not a symptom. Shai-Hulud ran from `preinstall`;
    the 2025 wave ran from `postinstall`. A repo that sets ignore-scripts is
    immune to the delivery method regardless of which package is poisoned next.
    """
    findings: list[Finding] = []
    if not (root / "package.json").exists():
        return findings

    npmrc = root / ".npmrc"
    text = npmrc.read_text(encoding="utf-8", errors="replace") if npmrc.exists() else ""
    if not re.search(r"^\s*ignore-scripts\s*=\s*true", text, re.MULTILINE):
        findings.append(
            Finding(
                "S3",
                str(npmrc.relative_to(root)) if npmrc.exists() else ".npmrc",
                0,
                "high",
                "ignore-scripts is not set, so `npm install` will run preinstall/postinstall "
                "hooks: the execution vector for npm supply-chain attacks. Add "
                "`ignore-scripts=true` to .npmrc and rebuild the few packages that genuinely "
                "need it with `npm rebuild <pkg>`, which is a reviewed decision rather than "
                "the default for everything in the tree.",
                "ignore-scripts=true (missing)",
            )
        )
        # What would actually have run. Turns an abstract risk into a list.
        lock = root / "package-lock.json"
        if lock.exists():
            try:
                data = json.loads(lock.read_text(encoding="utf-8", errors="replace"))
            except (ValueError, TypeError):
                data = {}
            scripted = sorted(
                {
                    k.split("node_modules/")[-1]
                    for k, v in (data.get("packages") or {}).items()
                    if isinstance(v, dict) and v.get("hasInstallScript")
                }
            )
            if scripted:
                findings.append(
                    Finding(
                        "S6",
                        "package-lock.json",
                        0,
                        "info",
                        f"{len(scripted)} package(s) declare an install script and would execute "
                        f"on install: {', '.join(scripted[:8])}"
                        + (" ..." if len(scripted) > 8 else ""),
                        ", ".join(scripted[:8]),
                    )
                )
    return findings


# ─── indicators of compromise ──────────────────────────────────────


def scan_iocs(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in root.rglob("*"):
        if not path.is_file() or _skipped(path):
            continue
        if path.name in IOC_FILENAMES:
            findings.append(
                Finding(
                    "S4",
                    str(path.relative_to(root)),
                    0,
                    "high",
                    f"indicator of compromise on disk: {IOC_FILENAMES[path.name]}",
                    path.name,
                )
            )
        # Only text-ish files, and only a bounded read: a scanner that loads a
        # 500MB artefact into memory is a scanner nobody runs twice.
        if path.suffix.lower() not in (".js", ".mjs", ".cjs", ".ts", ".json", ".yaml", ".yml", ".md", ".txt", ""):
            continue
        try:
            if path.stat().st_size > 4_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for needle, why in IOC_STRINGS.items():
            idx = text.find(needle)
            if idx >= 0:
                findings.append(
                    Finding(
                        "S5",
                        str(path.relative_to(root)),
                        text.count("\n", 0, idx) + 1,
                        "high",
                        f"indicator of compromise in file content: {why}",
                        needle,
                    )
                )
    return findings


# ─── entry points ──────────────────────────────────────────────────


def audit(root: Path | str = ".") -> dict:
    base = Path(root).resolve()
    findings = scan_lockfiles(base) + scan_install_posture(base) + scan_iocs(base)
    findings.sort(key=lambda f: (SEV_RANK.get(f.severity, 9), f.pattern_id, f.file))
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {
        "root": str(base),
        "findings": [asdict(f) for f in findings],
        "counts": counts,
        "compromised_present": any(f.pattern_id == "S1" for f in findings),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agenticqa-audit-supply-chain", description=__doc__)
    ap.add_argument("--path", default=".", help="repository root to scan")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument(
        "--severity",
        choices=["high", "medium", "low", "info"],
        default="info",
        help="minimum severity to report (default: info)",
    )
    args = ap.parse_args(argv)

    result = audit(args.path)
    floor = SEV_RANK[args.severity]
    shown = [f for f in result["findings"] if SEV_RANK.get(f["severity"], 9) <= floor]

    if args.json:
        print(json.dumps({**result, "findings": shown}, indent=2))
    else:
        if not shown:
            print("supply chain: no findings at or above severity", args.severity)
        for f in shown:
            loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            print(f"[{f['severity'].upper():5}] {f['pattern_id']}  {loc}\n         {f['description']}")
        if result["compromised_present"]:
            print(
                "\nA KNOWN-COMPROMISED version is installed. Remove it, then rotate npm, GitHub, "
                "cloud and CI credentials reachable from any machine that ran the install."
            )

    # Only a genuinely compromised dependency fails the gate. Posture findings
    # are reported and do not block, so this can be wired into CI on day one
    # rather than after a cleanup project nobody schedules.
    return 1 if result["compromised_present"] else 0


if __name__ == "__main__":
    sys.exit(main())
