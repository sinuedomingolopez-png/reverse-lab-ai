"""Optional local Ghidra headless runner. Never executes the target binary."""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


def analyze_with_ghidra(
    target: str | Path,
    analyze_headless: str | Path,
    *,
    timeout: int = 180,
) -> dict:
    target_path = Path(target).resolve(strict=True)
    runner = Path(analyze_headless).resolve(strict=True)
    if not target_path.is_file() or not runner.is_file():
        raise ValueError("Target and Ghidra launcher must be files")
    if timeout < 1 or timeout > 3600:
        raise ValueError("timeout must be between 1 and 3600 seconds")
    with tempfile.TemporaryDirectory(prefix="reverse-lab-ghidra-") as project_dir:
        command = [
            str(runner), project_dir, "ReverseLab",
            "-import", str(target_path), "-deleteProject",
        ]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True,
                timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Ghidra analysis timed out") from exc
        return {
            "backend": "ghidra",
            "exit_code": result.returncode,
            "success": result.returncode == 0,
            "stdout_tail": result.stdout[-4000:],
            "stderr_tail": result.stderr[-4000:],
        }
