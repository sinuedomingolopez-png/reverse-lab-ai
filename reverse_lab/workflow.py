"""Common engine dispatcher used by the CLI and local desktop interface.

No file is executed by this dispatcher; installed third-party analyzers parse data.
"""
from __future__ import annotations

from pathlib import Path

from .analyzer import inspect_file

BACKENDS = ("basic", "lief", "rizin", "ghidra", "angr")


def analyze(
    target: str | Path,
    *,
    backend: str = "basic",
    rizin_executable: str = "rz-bin",
    ghidra_headless: str | None = None,
    timeout: int = 180,
    export_functions: bool = False,
    export_pseudocode: bool = False,
    export_call_graph: bool = False,
) -> dict:
    """Inspect an authorized file and optionally use one external static-analysis backend."""
    if backend not in BACKENDS:
        raise ValueError(f"Unsupported backend: {backend}")
    if not 1 <= timeout <= 3600:
        raise ValueError("timeout must be between 1 and 3600 seconds")
    path = Path(target)
    if not path.is_file():
        raise ValueError("target must be a regular file")
    if backend == "ghidra" and not ghidra_headless:
        raise ValueError("ghidra_headless is required for the Ghidra backend")

    report = inspect_file(path)
    if backend == "lief":
        from .integrations.lief_adapter import inspect_with_lief
        report["analysis"] = inspect_with_lief(path)
    elif backend == "rizin":
        from .integrations.rizin_adapter import inspect_with_rizin
        report["analysis"] = inspect_with_rizin(
            path, executable=rizin_executable, timeout=timeout
        )
    elif backend == "angr":
        from .integrations.angr_adapter import inspect_with_angr
        report["analysis"] = inspect_with_angr(path, timeout=timeout)
    elif backend == "ghidra":
        from .integrations.ghidra_adapter import analyze_with_ghidra
        ghidra_options = {"timeout": timeout, "export_functions": export_functions}
        if export_pseudocode:
            ghidra_options["export_pseudocode"] = True
        if export_call_graph:
            ghidra_options["export_call_graph"] = True
        report["analysis"] = analyze_with_ghidra(
            path, ghidra_headless, **ghidra_options
        )
    return report
