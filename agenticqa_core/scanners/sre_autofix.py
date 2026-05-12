"""SRE Agent — Multi-Language Auto-Fix Engine.

Detects the project stack and applies automated fixes for common errors:
  - TypeScript / JavaScript: ESLint --fix, tsc type errors
  - Python: ruff --fix, mypy
  - Go: gofmt, go vet, staticcheck
  - Rust: cargo fmt, clippy --fix
  - Ruby: rubocop -A
  - Java: google-java-format
  - PHP: php-cs-fixer

Usage:
  agenticqa-sre-autofix [--path .] [--dry-run] [--max-passes 3] [--json]

Exit codes:
  0 = clean or fixes applied
  1 = unfixable errors remain
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["FixResult", "detect_stack", "FIXERS", "main"]


@dataclass
class FixResult:
    tool: str
    fixed: int = 0
    unfixed: int = 0
    errors: list[str] = field(default_factory=list)


def run(
    cmd: str, cwd: str = ".", capture: bool = True, check: bool = False
) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S602
        cmd, shell=True, cwd=cwd, capture_output=capture,
        text=True, timeout=300, check=check,
    )


def detect_stack(path: str) -> list[str]:
    """Auto-detect project stack from files present."""
    stacks: list[str] = []
    p = Path(path)
    indicators = {
        "typescript": ["tsconfig.json", "package.json"],
        "python": ["pyproject.toml", "setup.py", "requirements.txt", "Pipfile"],
        "go": ["go.mod"],
        "rust": ["Cargo.toml"],
        "ruby": ["Gemfile"],
        "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
        "php": ["composer.json"],
    }
    for stack, files in indicators.items():
        if any((p / f).exists() for f in files):
            stacks.append(stack)
    if not stacks:
        stacks.append("unknown")
    return stacks


# ─── TypeScript / JavaScript ────────────────────────────────────────


def fix_typescript(path: str, dry_run: bool) -> FixResult:
    result = FixResult(tool="typescript")

    print("  Running ESLint auto-fix...")
    eslint_exts = _find_eslint_exts(path)
    if eslint_exts:
        cmd = f"npx eslint . --ext {eslint_exts} --fix --no-error-on-unmatched-pattern"
        if dry_run:
            cmd += " --dry-run"
        run(cmd, cwd=path)

    tsconfig = Path(path) / "tsconfig.json"
    if not tsconfig.exists():
        print("  No tsconfig.json, skipping tsc")
        return result

    print("  Running TypeScript type-check...")
    r = run("npx tsc --noEmit --pretty false 2>&1", cwd=path)
    output = r.stdout or ""

    errors = _parse_tsc_errors(output)
    if not errors:
        return result

    by_file: dict[str, list[dict]] = {}
    for e in errors:
        abs_path = str(Path(path) / e["file"])
        by_file.setdefault(abs_path, []).append(e)

    for file_path, file_errors in by_file.items():
        try:
            content = Path(file_path).read_text()
        except OSError:
            result.unfixed += len(file_errors)
            continue

        lines = content.split("\n")
        modified = False
        fixed_lines: set[int] = set()

        for err in file_errors:
            line_idx = err["line"] - 1
            if line_idx < 0 or line_idx >= len(lines):
                result.unfixed += 1
                continue

            fixed = False
            if err["code"] == "TS2367" and "unintentional" in err["message"]:
                fixed = _fix_ts2367(lines, line_idx, err, fixed_lines)
            elif err["code"] == "TS2322":
                if "'never'" in err["message"]:
                    fixed = _fix_ts2322_never(lines, line_idx, err, fixed_lines)
                elif re.search(r"Type '\"(\w+)\"' is not assignable to type '\"(\w+)\"'", err["message"]):
                    fixed = _fix_ts2322_literal(lines, line_idx, err, fixed_lines)

            if fixed:
                result.fixed += 1
                modified = True
            else:
                result.unfixed += 1
                result.errors.append(f"{err['code']} at {err['file']}:{err['line']}: {err['message'][:100]}")

        if modified and not dry_run:
            Path(file_path).write_text("\n".join(lines))

    return result


def _find_eslint_exts(path: str) -> str:
    p = Path(path)
    exts: set[str] = set()
    if list(p.rglob("*.ts")) or list(p.rglob("*.tsx")):
        exts.update([".ts", ".tsx"])
    if list(p.rglob("*.js")) or list(p.rglob("*.jsx")):
        exts.update([".js", ".jsx"])
    return ",".join(sorted(exts)) if exts else ""


def _parse_tsc_errors(output: str) -> list[dict]:
    pattern = re.compile(r"^(.+?)\((\d+),(\d+)\): error (TS\d+): (.+)$", re.MULTILINE)
    return [
        {"file": m.group(1), "line": int(m.group(2)), "col": int(m.group(3)),
         "code": m.group(4), "message": m.group(5)}
        for m in pattern.finditer(output)
    ]


def _fix_ts2367(lines: list[str], line_idx: int, err: dict, fixed: set[int]) -> bool:
    m = re.search(r"types '\"(.+?)\"' and '\"(.+?)\"'", err["message"])
    if not m:
        return False
    literal = m.group(1)
    for i in range(line_idx, max(-1, line_idx - 20), -1):
        if i in fixed:
            continue
        decl = re.search(
            rf"(const|let|var)\s+(\w+)\s*=\s*\"{re.escape(literal)}\"", lines[i]
        )
        if decl:
            old = f'{decl.group(1)} {decl.group(2)} = "{literal}"'
            new = f'{decl.group(1)} {decl.group(2)}: string = "{literal}"'
            lines[i] = lines[i].replace(old, new)
            fixed.add(i)
            return True
    return False


def _fix_ts2322_never(lines: list[str], line_idx: int, err: dict, fixed: set[int]) -> bool:
    type_m = re.search(r"Type '(.+?)' is not assignable", err["message"])
    if not type_m:
        return False
    assigned_type = type_m.group(1)
    for i in range(line_idx, max(-1, line_idx - 30), -1):
        if i in fixed:
            continue
        if re.search(r"=\s*\[\]\s*[,;]?\s*$", lines[i]) or re.search(r":\s*\[\]", lines[i]):
            if re.search(r":\s*(Array|[\w<>\[\]]+\[\])\s*=", lines[i]):
                continue
            arr_m = re.search(r"(\w+)(\s*[:=]\s*)\[\]", lines[i])
            if arr_m:
                if "email" in assigned_type and "role" in assigned_type:
                    elem_type = "{ email: string; role: string }"
                else:
                    elem_type = assigned_type
                old = f"{arr_m.group(1)}{arr_m.group(2)}[]"
                new = f"{arr_m.group(1)}: Array<{elem_type}> = []"
                lines[i] = lines[i].replace(old, new)
                fixed.add(i)
                return True
    return False


def _fix_ts2322_literal(lines: list[str], line_idx: int, err: dict, fixed: set[int]) -> bool:
    m = re.search(r"Type '\"(\w+)\"' is not assignable to type '\"(\w+)\"'", err["message"])
    if not m:
        return False
    assigned = m.group(1)
    expected = m.group(2)
    for i in range(line_idx, max(-1, line_idx - 50), -1):
        if i in fixed:
            continue
        prop_m = re.search(rf'(\w+):\s*"{re.escape(expected)}"\s*[,;]', lines[i])
        if prop_m:
            old = f'{prop_m.group(1)}: "{expected}"'
            new = f'{prop_m.group(1)}: "{expected}" | "{assigned}"'
            lines[i] = lines[i].replace(old, new)
            fixed.add(i)
            return True
    return False


# ─── Other stacks ───────────────────────────────────────────────────


def fix_python(path: str, dry_run: bool) -> FixResult:
    result = FixResult(tool="python")
    if run("which ruff", cwd=path).returncode == 0:
        cmd = "ruff check --fix ." if not dry_run else "ruff check ."
        r = run(cmd, cwd=path)
        result.fixed = (r.stdout or "").count("Fixed")
        result.unfixed = (r.stdout or "").count("error")
    elif run("which autopep8", cwd=path).returncode == 0:
        cmd = "autopep8 --in-place --recursive ." if not dry_run else "autopep8 --diff --recursive ."
        run(cmd, cwd=path)

    if run("which mypy", cwd=path).returncode == 0:
        r = run("mypy . --ignore-missing-imports 2>&1", cwd=path)
        if r.stdout:
            result.unfixed += len(re.findall(r"error:", r.stdout))
    return result


def fix_go(path: str, dry_run: bool) -> FixResult:
    result = FixResult(tool="go")
    if not dry_run:
        run("gofmt -w .", cwd=path)
    r = run("go vet ./... 2>&1", cwd=path)
    if r.stdout:
        result.unfixed = len(r.stdout.strip().split("\n"))
    if run("which staticcheck", cwd=path).returncode == 0:
        r = run("staticcheck ./... 2>&1", cwd=path)
        if r.stdout:
            result.unfixed += len(r.stdout.strip().split("\n"))
    return result


def fix_rust(path: str, dry_run: bool) -> FixResult:
    result = FixResult(tool="rust")
    if not dry_run:
        run("cargo fmt", cwd=path)
    cmd = "cargo clippy --fix --allow-dirty --allow-staged 2>&1" if not dry_run else "cargo clippy 2>&1"
    r = run(cmd, cwd=path)
    if r.stdout:
        result.fixed = r.stdout.count("Fixed")
        result.unfixed = len(re.findall(r"error\[", r.stdout))
    return result


def fix_ruby(path: str, dry_run: bool) -> FixResult:
    result = FixResult(tool="ruby")
    if run("which rubocop", cwd=path).returncode == 0:
        cmd = "rubocop -A 2>&1" if not dry_run else "rubocop 2>&1"
        r = run(cmd, cwd=path)
        if r.stdout:
            m = re.search(r"(\d+) offense.*corrected", r.stdout)
            if m:
                result.fixed = int(m.group(1))
    return result


def fix_java(path: str, dry_run: bool) -> FixResult:
    result = FixResult(tool="java")
    if run("which google-java-format", cwd=path).returncode == 0 and not dry_run:
        run("find . -name '*.java' -exec google-java-format -i {} +", cwd=path)
    return result


def fix_php(path: str, dry_run: bool) -> FixResult:
    result = FixResult(tool="php")
    if run("which php-cs-fixer", cwd=path).returncode == 0:
        cmd = "php-cs-fixer fix . 2>&1" if not dry_run else "php-cs-fixer fix . --dry-run 2>&1"
        r = run(cmd, cwd=path)
        if r.stdout:
            result.fixed = r.stdout.count("Fixed")
    return result


FIXERS = {
    "typescript": fix_typescript,
    "python": fix_python,
    "go": fix_go,
    "rust": fix_rust,
    "ruby": fix_ruby,
    "java": fix_java,
    "php": fix_php,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenticqa-sre-autofix")
    parser.add_argument("--path", default=".", help="Project root path")
    parser.add_argument("--dry-run", action="store_true", help="Report fixes without applying")
    parser.add_argument("--max-passes", type=int, default=3, help="Max fix-verify passes")
    parser.add_argument("--json", action="store_true", help="Output JSON summary")
    args = parser.parse_args(argv)

    path = os.path.abspath(args.path)
    stacks = detect_stack(path)

    print("SRE Agent — Auto-Fix Engine")
    print(f"  Path: {path}")
    print(f"  Stacks: {', '.join(stacks)}")
    print(f"  Dry run: {args.dry_run}")

    results: list[FixResult] = []
    for pass_num in range(1, args.max_passes + 1):
        print(f"--- Pass {pass_num}/{args.max_passes} ---")
        pass_results: list[FixResult] = []
        for stack in stacks:
            fixer = FIXERS.get(stack)
            if not fixer:
                continue
            result = fixer(path, args.dry_run)
            pass_results.append(result)
        results.extend(pass_results)
        if sum(r.fixed for r in pass_results) == 0:
            break

    total_fixed = sum(r.fixed for r in results)
    total_unfixed = sum(r.unfixed for r in results)
    all_errors = [e for r in results for e in r.errors]

    print(f"\nSummary: stacks={stacks}, fixed={total_fixed}, unfixable={total_unfixed}")

    if args.json:
        summary = {
            "stacks": stacks,
            "total_fixed": total_fixed,
            "total_unfixed": total_unfixed,
            "results": [{"tool": r.tool, "fixed": r.fixed, "unfixed": r.unfixed} for r in results],
            "unfixed_errors": all_errors[:20],
        }
        print(json.dumps(summary, indent=2))

    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        try:
            with open(output_file, "a") as f:
                f.write(f"fixed={total_fixed}\n")
                f.write(f"unfixed={total_unfixed}\n")
                f.write(f"stacks={','.join(stacks)}\n")
        except OSError:
            pass

    return 0 if total_unfixed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
