"""Real installed-engine smoke test using an inert, generated ELF64 fixture.

This module is intentionally NOT a test of arbitrarily supplied user binaries.
It invokes optional LIEF or angr only when requested and records safe status
fields, never local paths, raw code, stderr, symbols or input filenames.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import tempfile
import os
import subprocess
from pathlib import Path

from .ghidra_probe import build_synthetic_elf

ENGINES = ("lief", "angr")
_EXPECTED_ENTRY = 0x401000


def _is_installed(name: str) -> bool:
    external = os.environ.get("REVERSE_LAB_PYTHON", "").strip()
    if name == "angr" and external:
        try:
            result = subprocess.run(
                [str(Path(external).resolve(strict=True)), "-c",
                 "import importlib.util; raise SystemExit(0 if importlib.util.find_spec('angr') else 1)"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5, shell=False)
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError, AttributeError):
        return False


def probe_engine(engine: str, *, timeout: int = 90) -> dict:
    """Perform an authentic parse / CFGFast analysis on generated ELF bytes.

    'passed' means the required real output was observed. It does not mean the
    engine can correctly analyze all binaries, or that the engine is sandboxed.
    """
    if engine not in ENGINES:
        raise ValueError("engine must be lief or angr")
    if type(timeout) is not int or not 5 <= timeout <= 600:
        raise ValueError("timeout must be between 5 and 600 seconds")

    available = _is_installed(engine)
    checks = {"dependency_installed": available}
    outcome = {
        "schema": "reverse-lab-engine-smoke-v1",
        "engine": engine,
        "status": "missing" if not available else "failed",
        "checks": checks,
        "metrics": {},
    }
    if not available:
        return outcome

    fixture = build_synthetic_elf()
    checks["synthetic_elf"] = (fixture[:6] == b"\x7fELF\x02\x01"
                               and len(fixture) > 4096)
    if not checks["synthetic_elf"]:
        outcome["failure_type"] = "fixture_invalid"
        return outcome

    from .workflow import analyze

    with tempfile.TemporaryDirectory(prefix="reverse-lab-engine-smoke-") as work:
        target = Path(work) / "synthetic_engine_test.elf"
        target.write_bytes(fixture)
        try:
            report = analyze(target, backend=engine, timeout=timeout)
        except Exception as exc:
            # Do not export exception text. It might include full paths, secrets
            # or parser output from untrusted sources.
            outcome["failure_type"] = type(exc).__name__
            return outcome

    if not isinstance(report, dict):
        outcome["failure_type"] = "invalid_report"
        return outcome
    checks["elf_recognized"] = report.get("format") == "ELF"
    analysis = report.get("analysis")
    if not isinstance(analysis, dict):
        outcome["failure_type"] = "missing_analysis"
        return outcome

    checks["backend_matches"] = analysis.get("backend") == engine
    if engine == "lief":
        entry = analysis.get("entrypoint")
        valid_entry = type(entry) is int and entry == _EXPECTED_ENTRY
        checks["binary_recognized"] = analysis.get("recognized") is True
        checks["expected_entrypoint"] = valid_entry
        if type(entry) is int and 0 <= entry < 2**64:
            outcome["metrics"]["entrypoint"] = hex(entry)
    else:
        checks["static_cfg"] = analysis.get("analysis_type") == "CFGFast"
        function_count = analysis.get("function_count")
        nodes = analysis.get("cfg_nodes")
        edges = analysis.get("cfg_edges")
        checks["functions_discovered"] = type(function_count) is int and function_count >= 1
        checks["cfg_nodes_discovered"] = type(nodes) is int and nodes >= 1
        checks["cfg_edges_valid"] = type(edges) is int and edges >= 0
        for key, value in (("function_count", function_count),
                           ("cfg_nodes", nodes), ("cfg_edges", edges)):
            if type(value) is int and 0 <= value < 1_000_000:
                outcome["metrics"][key] = value
        # Guard against a worker that gives counts but no actual function list.
        functions = analysis.get("functions")
        checks["functions_returned"] = isinstance(functions, list) and len(functions) >= 1

    outcome["status"] = "passed" if all(checks.values()) else "failed"
    return outcome


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Probar LIEF o angr reales con un ELF sintético no ejecutado")
    parser.add_argument("--engine", required=True, choices=ENGINES)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--output", type=Path, help="Guardar informe JSON optativamente")
    args = parser.parse_args(argv)
    result = probe_engine(args.engine, timeout=args.timeout)
    encoded = json.dumps(result, ensure_ascii=False, indent=2)
    print(encoded)
    if args.output is not None:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    if result["status"] != "passed":
        raise SystemExit(2 if result["status"] == "missing" else 1)


if __name__ == "__main__":
    main()
