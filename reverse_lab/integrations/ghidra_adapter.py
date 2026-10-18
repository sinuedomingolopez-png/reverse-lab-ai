"""Optional Ghidra headless analysis and bounded, explicit JSON exports.

This calls an installed Ghidra analyzer; it does not execute the target binary.
Ghidra itself should run inside an isolated environment for untrusted inputs.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def _read_json_export(path: Path, *, max_bytes: int, validator) -> list[dict]:
    if not path.is_file():
        raise ValueError(f"Ghidra export was not created: {path.name}")
    with path.open("rb") as stream:
        content = stream.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise ValueError(f"Ghidra export exceeds {max_bytes} bytes")
    try:
        items = json.loads(content.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Ghidra export is not valid UTF-8 JSON") from exc
    if not isinstance(items, list) or not all(validator(item) for item in items):
        raise ValueError("Ghidra export contains invalid entries")
    return items


def _function_entry(item: object) -> bool:
    return (isinstance(item, dict) and isinstance(item.get("name"), str)
            and isinstance(item.get("entry"), str))


def _pseudocode_entry(item: object) -> bool:
    return (_function_entry(item) and
            ((isinstance(item.get("pseudocode"), str) and type(item.get("truncated")) is bool)
             or isinstance(item.get("error"), str)))


def _call_edge(item: object) -> bool:
    """Require source and destination nodes with untrusted display-only text."""
    return (isinstance(item, dict) and
            _function_entry(item.get("caller")) and
            _function_entry(item.get("callee")))


def _windows_batch_args_safe(command: list[str]) -> bool:
    """Refuse shell-sensitive characters in paths passed to Windows batch launchers."""
    forbidden = '&|<>^%!\r\n'
    return all(not any(char in value for char in forbidden) for value in command)


def analyze_with_ghidra(
    target: str | Path,
    analyze_headless: str | Path,
    *,
    timeout: int = 180,
    export_functions: bool = False,
    max_functions: int = 10000,
    export_pseudocode: bool = False,
    pseudocode_max_functions: int = 20,
    pseudocode_max_chars: int = 8000,
    pseudocode_timeout: int = 10,
    export_call_graph: bool = False,
    call_graph_max_callers: int = 200,
    call_graph_max_edges: int = 2000,
) -> dict:
    if not 1 <= timeout <= 3600:
        raise ValueError("timeout must be between 1 and 3600 seconds")
    if not 1 <= max_functions <= 100000:
        raise ValueError("max_functions must be between 1 and 100000")
    if not 1 <= pseudocode_max_functions <= 50:
        raise ValueError("pseudocode_max_functions must be between 1 and 50")
    if not 256 <= pseudocode_max_chars <= 16000:
        raise ValueError("pseudocode_max_chars must be between 256 and 16000")
    if not 1 <= pseudocode_timeout <= 30:
        raise ValueError("pseudocode_timeout must be between 1 and 30 seconds")

    if not 1 <= call_graph_max_callers <= 500:
        raise ValueError("call_graph_max_callers must be between 1 and 500")
    if not 1 <= call_graph_max_edges <= 5000:
        raise ValueError("call_graph_max_edges must be between 1 and 5000")

    target_path = Path(target).resolve(strict=True)
    runner = Path(analyze_headless).resolve(strict=True)
    if not target_path.is_file() or not runner.is_file():
        raise ValueError("Target and Ghidra launcher must be regular files")

    with tempfile.TemporaryDirectory(prefix="reverse-lab-ghidra-") as project_dir:
        command = [str(runner), project_dir, "ReverseLab", "-import", str(target_path)]
        script_dir = Path(__file__).resolve().parents[1] / "ghidra_scripts"
        if export_functions or export_pseudocode or export_call_graph:
            command += ["-scriptPath", str(script_dir)]

        outputs: list[tuple[str, Path, int, object]] = []
        if export_functions:
            if not (script_dir / "ExportFunctions.java").is_file():
                raise RuntimeError("Missing Ghidra ExportFunctions.java script")
            out = Path(project_dir) / "functions.json"
            command += ["-postScript", "ExportFunctions.java", str(out), str(max_functions)]
            outputs.append(("functions", out, 10 * 1024 * 1024, _function_entry))
        if export_pseudocode:
            if not (script_dir / "ExportPseudocode.java").is_file():
                raise RuntimeError("Missing Ghidra ExportPseudocode.java script")
            out = Path(project_dir) / "pseudocode.json"
            command += ["-postScript", "ExportPseudocode.java", str(out),
                        str(pseudocode_max_functions), str(pseudocode_max_chars),
                        str(pseudocode_timeout)]
            outputs.append(("pseudocode", out, 2 * 1024 * 1024, _pseudocode_entry))
        if export_call_graph:
            if not (script_dir / "ExportCallGraph.java").is_file():
                raise RuntimeError("Missing Ghidra ExportCallGraph.java script")
            out = Path(project_dir) / "call_graph.json"
            command += ["-postScript", "ExportCallGraph.java", str(out),
                        str(call_graph_max_callers), str(call_graph_max_edges)]
            outputs.append(("call_graph", out, 2 * 1024 * 1024, _call_edge))
        command += ["-analysisTimeoutPerFile", str(min(timeout, 1800)), "-deleteProject"]

        # Windows .bat/.cmd scripts are processed by cmd.exe. Validate all
        # arguments and use Python's shell quoting for these launchers only.
        batch_on_windows = sys.platform == "win32" and runner.suffix.lower() in (".bat", ".cmd")
        kwargs = {}
        if batch_on_windows:
            if not _windows_batch_args_safe(command):
                raise ValueError("Windows batch launcher path contains unsafe shell characters")
            kwargs["shell"] = True
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, errors="replace",
                timeout=timeout, check=False, **kwargs,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Ghidra analysis timed out") from exc
        except OSError as exc:
            raise RuntimeError("Unable to launch Ghidra; check installation and launcher path") from exc

        report = {
            "backend": "ghidra", "exit_code": result.returncode,
            "success": result.returncode == 0,
            "stdout_tail": result.stdout[-4000:], "stderr_tail": result.stderr[-4000:],
        }
        if result.returncode != 0:
            return report
        for name, output_path, byte_limit, validator in outputs:
            try:
                items = _read_json_export(output_path, max_bytes=byte_limit, validator=validator)
                if name == "pseudocode" and len(items) > pseudocode_max_functions:
                    raise ValueError("Ghidra pseudocode export exceeds function limit")
                if name == "pseudocode" and any(
                    len(item.get("pseudocode", "")) > pseudocode_max_chars for item in items
                ):
                    raise ValueError("Ghidra pseudocode export exceeds character limit")
                if name == "call_graph" and len(items) > call_graph_max_edges:
                    raise ValueError("Ghidra call graph exceeds edge limit")
                report[name] = items
                key = {"functions": "function_count", "pseudocode": "pseudocode_count",
                       "call_graph": "call_graph_count"}[name]
                report[key] = len(items)
            except (OSError, ValueError) as exc:
                report["success"] = False
                report["error"] = f"Invalid {name} export: {exc}"
                break
        return report
