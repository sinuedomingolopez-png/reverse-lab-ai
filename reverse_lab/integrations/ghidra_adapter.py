"""Optional Ghidra headless runner for local, authorized static analyses."""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


def analyze_with_ghidra(
    target: str | Path,
    analyze_headless: str | Path,
    *,
    timeout: int = 180,
    export_functions: bool = False,
    max_functions: int = 10000,
) -> dict:
    if timeout < 1 or timeout > 3600:
        raise ValueError("timeout must be between 1 and 3600 seconds")
    if max_functions < 1 or max_functions > 100000:
        raise ValueError("max_functions must be between 1 and 100000")
    target_path = Path(target).resolve(strict=True)
    runner = Path(analyze_headless).resolve(strict=True)
    if not target_path.is_file() or not runner.is_file():
        raise ValueError("Target and Ghidra launcher must be files")
    with tempfile.TemporaryDirectory(prefix="reverse-lab-ghidra-") as project_dir:
        command = [
            str(runner), project_dir, "ReverseLab",
            "-import", str(target_path), "-deleteProject",
        ]
        function_output = Path(project_dir) / "functions.json"
        if export_functions:
            script_dir = Path(__file__).resolve().parents[1] / "ghidra_scripts"
            script = script_dir / "ExportFunctions.java"
            if not script.is_file():
                raise RuntimeError("Missing bundled Ghidra function export script")
            command += [
                "-scriptPath", str(script_dir),
                "-postScript", "ExportFunctions.java", str(function_output), str(max_functions),
            ]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, errors="replace",
                timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Ghidra analysis timed out") from exc
        report = {
            "backend": "ghidra",
            "exit_code": result.returncode,
            "success": result.returncode == 0,
            "stdout_tail": result.stdout[-4000:],
            "stderr_tail": result.stderr[-4000:],
        }
        if export_functions and result.returncode == 0:
            if not function_output.exists():
                report.update(success=False, error="Ghidra function export was not created")
            elif function_output.stat().st_size > 10 * 1024 * 1024:
                report.update(success=False, error="Ghidra function export exceeds 10 MB limit")
            else:
                try:
                    functions = json.loads(function_output.read_text(encoding="utf-8"))
                    if not isinstance(functions, list) or not all(
                        isinstance(item, dict) and isinstance(item.get("name"), str)
                        and isinstance(item.get("entry"), str) for item in functions
                    ):
                        raise ValueError("Unexpected function export format")
                    report.update(functions=functions, function_count=len(functions))
                except (OSError, ValueError) as exc:
                    report.update(success=False, error=f"Invalid function export: {exc}")
        return report
