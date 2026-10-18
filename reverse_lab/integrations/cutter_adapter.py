"""Open an authorized sample in a separately installed Cutter GUI.

Launching is user initiated; Cutter is never downloaded or embedded here.
The binary is opened for examination, not executed by Reverse Lab AI.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def find_cutter(executable: str | Path | None = None) -> Path | None:
    """Locate Cutter from an explicit path, CUTTER_PATH or PATH."""
    if executable is not None:
        direct = Path(executable).expanduser()
        if direct.is_file():
            return direct.resolve()
        found = shutil.which(str(executable))
        return Path(found).resolve() if found else None

    from_env = os.environ.get("CUTTER_PATH")
    if from_env:
        path = Path(from_env).expanduser()
        if path.is_file():
            return path.resolve()
    for command in ("cutter", "Cutter.exe", "cutter-re", "rz-cutter"):
        found = shutil.which(command)
        if found:
            return Path(found).resolve()
    return None


def launch_cutter(
    target: str | Path, *, executable: str | Path | None = None,
) -> dict:
    """Start Cutter with a locally present sample, without a shell."""
    binary = Path(target).expanduser().resolve(strict=True)
    if not binary.is_file():
        raise ValueError("Cutter target must be a regular file")
    program = find_cutter(executable)
    if program is None:
        raise RuntimeError(
            "Cutter not found. Install Cutter from https://github.com/rizinorg/cutter/releases "
            "and set CUTTER_PATH or browse to its executable."
        )
    try:
        process = subprocess.Popen(
            [str(program), str(binary)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True, shell=False,
        )
    except OSError as exc:
        raise RuntimeError("Could not launch Cutter. Verify its installation and permissions.") from exc
    return {
        "tool": "cutter", "status": "started",
        "pid": process.pid, "filename": binary.name,
    }
