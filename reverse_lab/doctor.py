"""Check optional local tools without launching or installing software."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
from pathlib import Path

from .ghidra_probe import discover_ghidra
from .integrations.cutter_adapter import find_cutter


def check_environment() -> dict:
    detected = discover_ghidra()
    launcher = str(detected) if detected else None
    rizin = shutil.which("rz-bin")
    cutter_path = find_cutter()
    cutter = str(cutter_path) if cutter_path else None
    return {
        "tools": {
            "lief": {"available": importlib.util.find_spec("lief") is not None, "install": "pip install lief"},
            "rizin": {"available": rizin is not None, "path": rizin},
            "ghidra": {"available": launcher is not None, "path": launcher, "hint": "Set GHIDRA_HOME or run python -m reverse_lab.ghidra_probe"},
            "cutter": {"available": cutter is not None, "path": cutter},
            "angr": {"available": importlib.util.find_spec("angr") is not None, "install": "pip install angr", "hint": "CFGFast backend; parses files using an optional subprocess, not a security sandbox"},
        }
    }


def main() -> None:
    print(json.dumps(check_environment(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
