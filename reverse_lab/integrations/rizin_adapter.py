"""Read binary metadata with the optional rz-bin tool; never run the target."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path


def inspect_with_rizin(
    target: str | Path, *, executable: str = "rz-bin", timeout: int = 30,
) -> dict:
    if not 1 <= timeout <= 3600:
        raise ValueError("timeout must be between 1 and 3600 seconds")
    path = Path(target).resolve(strict=True)
    if not path.is_file():
        raise ValueError("target must be a regular file")
    try:
        process = subprocess.run(
            [executable, "-Ij", str(path)], capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=timeout,
            check=False, shell=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"rz-bin executable not found: {executable}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("rz-bin analysis timed out") from exc
    if process.returncode != 0:
        raise RuntimeError(f"rz-bin analysis failed (exit {process.returncode}): {process.stderr[-500:]}")
    try:
        metadata = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("rz-bin did not return valid JSON") from exc
    if not isinstance(metadata, dict):
        raise RuntimeError("rz-bin JSON must be an object")
    return {"backend": "rizin", "recognized": bool(metadata), "metadata": metadata}


def inspect_functions_with_rizin(target: str | Path, *, executable: str = "rizin",
                                  timeout: int = 60) -> dict:
    """Run static discovery with fixed commands, never debug or execute the input.

    The MCP job supervisor bounds the process tree, memory and output files.
    Direct CLI calls retain subprocess timeout, as with the original adapter.
    """
    if type(timeout) is not int or not 1 <= timeout <= 600:
        raise ValueError("timeout must be 1..600 seconds")
    path = Path(target).resolve(strict=True)
    if not path.is_file():
        raise ValueError("target must be a regular file")
    try:
        result = subprocess.run(
            [executable, "-2", "-q", "-c", "aaa;aflj", str(path)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("rizin static function discovery unavailable or timed out") from exc
    if result.returncode != 0 or len(result.stdout) > 2 * 1024 * 1024:
        raise RuntimeError("rizin function discovery failed or exceeded output limit")
    try:
        entries = json.loads(result.stdout)
    except ValueError as exc:
        raise RuntimeError("rizin did not return function JSON") from exc
    if not isinstance(entries, list):
        raise RuntimeError("rizin function JSON must be a list")
    functions = []
    for item in entries[:500]:
        if not isinstance(item, dict) or type(item.get("offset")) is not int:
            raise RuntimeError("invalid rizin function entry")
        functions.append({"name": str(item.get("name", "unnamed"))[:180],
                          "entry": hex(item["offset"])})
    return {"backend": "rizin", "analysis_type": "static", "functions": functions,
            "function_count": len(entries), "truncated": len(entries) > 500}
