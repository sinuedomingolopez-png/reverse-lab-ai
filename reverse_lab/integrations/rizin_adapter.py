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
