"""Unified `agenticqa` dispatcher.

Forwards to the command-specific `main(argv)` functions so a consumer
can call either the dedicated entrypoint (`agenticqa-probe-headers`)
or the dispatcher form (`agenticqa probe-headers`).
"""

from __future__ import annotations

import sys

from agenticqa_core import __version__

COMMANDS = {
    "probe-headers": ("agenticqa_core.probes.security_headers", "Probe deployed URL for required security headers"),
    "probe-errors": ("agenticqa_core.probes.error_disclosure", "Probe error endpoints for stack/path leaks"),
    "branch-protection": ("agenticqa_core.governance.branch_protection", "Assert / apply branch protection"),
    "secret-age": ("agenticqa_core.governance.secret_age", "List GitHub secrets + flag rotation drift"),
    "audit-app": ("agenticqa_core.scanners.app_security", "18-pattern app-security audit"),
    "audit-history": ("agenticqa_core.scanners.history_exposure", "Scan git log + source for PII / client names"),
    "sre-autofix": ("agenticqa_core.scanners.sre_autofix", "Multi-language auto-fix engine"),
    "sdet-trend": ("agenticqa_core.benchmarks.sdet_trend", "Record SDET trend record from jest JSON"),
}


def _print_help() -> int:
    print(f"agenticqa v{__version__} — Wolfpack AgenticQA core toolkit")
    print()
    print("Usage: agenticqa <command> [args...]")
    print()
    print("Commands:")
    width = max(len(c) for c in COMMANDS)
    for cmd, (_mod, desc) in COMMANDS.items():
        print(f"  {cmd:<{width}}  {desc}")
    print()
    print("Run `agenticqa <command> --help` for command-specific help.")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in {"-h", "--help"}:
        return _print_help()
    if argv[0] in {"-V", "--version"}:
        print(__version__)
        return 0

    cmd = argv[0]
    if cmd not in COMMANDS:
        print(f"error: unknown command: {cmd}", file=sys.stderr)
        _print_help()
        return 2

    mod_name, _ = COMMANDS[cmd]
    import importlib

    mod = importlib.import_module(mod_name)
    return mod.main(argv[1:])


if __name__ == "__main__":
    sys.exit(main())
