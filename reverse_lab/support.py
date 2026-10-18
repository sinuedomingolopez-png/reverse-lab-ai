"""Privacy-preserving, offline diagnostics for Reverse Lab AI.

No paths, filenames, system usernames, environment values, logs, binaries,
pseudocode, or exception messages are included in the exported JSON.
Nothing is saved unless the user explicitly selects a destination.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SCHEMA = "reverse-lab-support-v1"
_TOOLS = ("ghidra", "rizin", "cutter", "angr", "lief")
_RELEASE = "0.11.0"


def collect_diagnostics(
    *, environment: dict | None = None, bundle_status: dict | None = None,
) -> dict:
    """Collect only allowlisted local tool presence and package integrity."""
    status = "ok"
    if environment is None:
        try:
            from .doctor import check_environment
            environment = check_environment()
        except Exception:
            # Exception messages can reveal usernames, paths or environment keys.
            status = "error"
            environment = {}
    if bundle_status is None:
        try:
            from .portable import collect_portable_status
            bundle_status = collect_portable_status()
        except Exception:
            bundle_status = {}

    raw_tools = environment.get("tools", {}) if isinstance(environment, dict) else {}
    if not isinstance(raw_tools, dict):
        raw_tools = {}
    tools = {}
    for name in _TOOLS:
        info = raw_tools.get(name)
        if not isinstance(info, dict) or type(info.get("available")) is not bool:
            tools[name] = "unknown"
        else:
            tools[name] = "detected" if info["available"] else "missing"

    if not isinstance(bundle_status, dict):
        bundle_status = {}
    raw_bundle_state = bundle_status.get("status")
    safe_state = raw_bundle_state if raw_bundle_state in ("ready", "incomplete") else "unknown"
    scripts = bundle_status.get("ghidra_script_count")
    scripts = scripts if type(scripts) is int and 0 <= scripts <= 3 else 0

    return {
        "schema": _SCHEMA,
        "release": _RELEASE,
        "platform": "windows" if sys.platform == "win32" else
                    "macos" if sys.platform == "darwin" else "linux-or-other",
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "portable": bool(getattr(sys, "frozen", False)),
        "tools_status": status,
        "tools": tools,
        "bundle": {"status": safe_state, "ghidra_script_count": scripts},
        "privacy": "Only allowlisted local capability statuses; no private data",
    }


def write_diagnostics(
    destination: str | Path, *,
    environment: dict | None = None, bundle_status: dict | None = None,
) -> dict:
    """Write sanitized JSON only after a caller requested this action."""
    report = collect_diagnostics(
        environment=environment, bundle_status=bundle_status,
    )
    path = Path(destination).expanduser()
    if not path.parent.is_dir():
        raise ValueError("La carpeta elegida para el diagnóstico no existe")
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Diagnóstico local, sin datos privados ni red")
    parser.add_argument("--output", type=Path,
                        help="Guardar JSON solo en la ruta elegida; por defecto imprimirlo")
    args = parser.parse_args(argv)
    if args.output is None:
        print(json.dumps(collect_diagnostics(), indent=2, ensure_ascii=False))
    else:
        write_diagnostics(args.output)


if __name__ == "__main__":
    main()
