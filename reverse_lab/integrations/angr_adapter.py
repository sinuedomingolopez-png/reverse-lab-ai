"""Optional angl CFGFast analyzer run as a bounded local subprocess.

The target file is parsed by angr, never executed by Reverse Lab AI.
Timeout, input-size and report-size controls are NOT a secure sandbox.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

_MAX_INPUT = 32 * 1024 * 1024
_MAX_STDOUT = 2 * 1024 * 1024


def _check_report(report: object, *, max_functions: int) -> dict:
    if not isinstance(report, dict) or report.get("backend") != "angr":
        raise RuntimeError("angr worker returned an invalid backend result")
    if report.get("analysis_type") != "CFGFast":
        raise RuntimeError("angr worker returned an unexpected analysis type")
    for name in ("function_count", "cfg_nodes", "cfg_edges"):
        if type(report.get(name)) is not int or report[name] < 0:
            raise RuntimeError(f"angr worker returned invalid {name}")
    funcs = report.get("functions")
    if not isinstance(funcs, list) or len(funcs) > max_functions:
        raise RuntimeError("angr worker returned an invalid function list")
    if not all(
        isinstance(item, dict) and isinstance(item.get("name"), str)
        and 0 < len(item["name"]) <= 180
        and isinstance(item.get("entry"), str) and len(item["entry"]) <= 128
        for item in funcs
    ):
        raise RuntimeError("angr worker returned malformed function entries")
    if type(report.get("truncated")) is not bool:
        raise RuntimeError("angr worker returned invalid truncation flag")
    graph = report.get("cfg_graph")
    if graph is not None:
        if (not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list)
                or not isinstance(graph.get("edges"), list) or len(graph["nodes"]) > 500
                or len(graph["edges"]) > 1000):
            raise RuntimeError("angr worker returned invalid CFG graph")
        if not all(isinstance(n, dict) and isinstance(n.get("entry"), str)
                   and len(n["entry"]) <= 128 for n in graph["nodes"]):
            raise RuntimeError("angr worker returned invalid CFG node")
        if not all(isinstance(e, dict) and all(isinstance(e.get(k), str) and len(e[k]) <= 128
                                             for k in ("source", "target")) for e in graph["edges"]):
            raise RuntimeError("angr worker returned invalid CFG edge")
    return report


def worker_command(target: str | Path, *, max_functions: int = 300) -> list[str]:
    """Choose a real Python interpreter, even when the UI is a frozen EXE.

    A frozen GUI executable is NOT a Python interpreter and must never receive
    '-m'. The bundled worker source is invoked by an external Python whose angr
    dependency the user installed separately.
    """
    path = str(target)
    if not getattr(sys, "frozen", False):
        configured = os.environ.get("REVERSE_LAB_PYTHON", "").strip()
        if configured:
            interpreter = Path(configured).expanduser().resolve(strict=True)
            if not interpreter.is_file():
                raise RuntimeError("REVERSE_LAB_PYTHON must point to an installed Python")
            # Direct worker source avoids depending on an editable project install
            # in a separate Python 3.12+ environment used by current angr.
            return [str(interpreter), str(Path(__file__).with_name("angr_worker.py").resolve()),
                    "--input", path, "--max-functions", str(max_functions)]
        return [
            sys.executable, "-m", "reverse_lab.integrations.angr_worker",
            "--input", path, "--max-functions", str(max_functions),
        ]

    configured = os.environ.get("REVERSE_LAB_PYTHON", "").strip()
    if configured:
        selected = Path(configured).expanduser()
        if not selected.is_file():
            raise RuntimeError(
                "REVERSE_LAB_PYTHON does not point to an installed Python "
                "interpreter. Set it to python.exe with angr installed."
            )
        interpreter = str(selected.resolve())
    else:
        interpreter = shutil.which("python") or shutil.which("python3")
        if not interpreter or not Path(interpreter).is_file():
            raise RuntimeError(
                "The portable app needs a separate Python installation for angr. "
                "Install Python and angr, then set REVERSE_LAB_PYTHON to python.exe."
            )

    bundle = getattr(sys, "_MEIPASS", None)
    worker = (
        Path(bundle) / "reverse_lab" / "integrations" / "angr_worker.py"
        if bundle else None
    )
    if worker is None or not worker.is_file():
        raise RuntimeError(
            "Portable bundle is missing angr_worker.py; reinstall the complete folder."
        )
    return [
        interpreter, str(worker),
        "--input", path, "--max-functions", str(max_functions),
    ]


def inspect_with_angr(
    target: str | Path, *, timeout: int = 60, max_functions: int = 300,
) -> dict:
    """Run CFGFast with a hard process timeout, no shell and no target execution."""
    if type(timeout) is not int or not 5 <= timeout <= 600:
        raise ValueError("angr timeout must be between 5 and 600 seconds")
    if type(max_functions) is not int or not 1 <= max_functions <= 500:
        raise ValueError("max_functions must be between 1 and 500")
    path = Path(target).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError("angr target must be a regular file")
    if path.stat().st_size > _MAX_INPUT:
        raise ValueError("angr input exceeds the 32 MiB size limit")
    command = worker_command(path, max_functions=max_functions)
    try:
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, capture_output=True,
            text=True, encoding="utf-8", errors="replace",
            check=False, timeout=timeout, shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("angr CFGFast analysis timed out; try a smaller binary") from exc
    except OSError as exc:
        raise RuntimeError("Could not start the isolated angr worker process") from exc
    if result.returncode != 0:
        raise RuntimeError(
            "angr worker failed (install locally with: python -m pip install angr). "
            + result.stderr[-300:]
        )
    if len(result.stdout.encode("utf-8")) > _MAX_STDOUT:
        raise RuntimeError("angr worker output exceeds 2 MiB")
    try:
        report = json.loads(result.stdout)
    except ValueError as exc:
        raise RuntimeError("angr worker did not return JSON") from exc
    return _check_report(report, max_functions=max_functions)
