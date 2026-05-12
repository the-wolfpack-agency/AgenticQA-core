"""AgenticQA-core — Wolfpack scanner / probe / governance toolkit.

Public API surface kept intentionally thin. Consumers typically use the
console scripts (`agenticqa-probe-headers`, etc.) or the reusable GitHub
Actions workflows in `.github/workflows/`. Importing the submodules
directly is supported for in-process use.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "probes",
    "governance",
    "scanners",
    "benchmarks",
]
