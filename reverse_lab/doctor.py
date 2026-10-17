"""Check optional local tools without launching or installing software."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
from pathlib import Path


def check_environment() -> dict:
    home = os.environ.get("GHIDRA_HOME")
    launcher = None
    if home:
        candidate = Path(home) / "support" / (
            "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        )
        if candidate.is_file():
            launcher = str(candidate)
    rizin = shutil.which("rz-bin")
    cutter = shutil.which("cutter")
    return {
        "tools": {
            "lief": {"available": importlib.util.find_spec("lief") is not None, "install": "pip install lief"},
            "rizin": {"available": rizin is not None, "path": rizin},
            "ghidra": {"available": launcher is not None, "path": launcher, "hint": "Set GHIDRA_HOME to the Ghidra installation directory"},
            "cutter": {"available": cutter is not None, "path": cutter},
            "angr": {"available": importlib.util.find_spec("angr") is not None, "install": "pip install angr"},
        }
    }


def main() -> None:
    print(json.dumps(check_environment(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
