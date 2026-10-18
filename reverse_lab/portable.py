"""Frozen Windows desktop launcher and bundle integrity smoke check.

No external binary or optional analyzer is run by --self-test-output.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REQUIRED_SCRIPTS = ("ExportFunctions.java", "ExportPseudocode.java", "ExportCallGraph.java")


def collect_portable_status(*, package_dir: Path | None = None) -> dict:
    """Return verifiable local bundle status for Windows release CI."""
    if package_dir is None:
        import reverse_lab
        # In a frozen build __main__.__file__ is at the bundle root, not
        # necessarily inside reverse_lab. Package __file__ stays accurate.
        root = Path(reverse_lab.__file__).resolve().parent
    else:
        root = package_dir
    scripts = root / "ghidra_scripts"
    missing = [name for name in _REQUIRED_SCRIPTS if not (scripts / name).is_file()]
    return {
        "status": "ready" if not missing else "incomplete",
        "frozen": bool(getattr(sys, "frozen", False)),
        "ghidra_script_count": len(_REQUIRED_SCRIPTS) - len(missing),
        "missing_scripts": missing,
        "optional_engines_included": False,
        "message": (
            "Portable local GUI ready; Ghidra, Cutter, Rizin, LIEF and angr "
            "are NOT bundled. Extra analyzers must be installed separately."
        ),
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Reverse Lab AI portable launcher")
    parser.add_argument(
        "--self-test-output", type=Path,
        help="Write JSON bundle verification (no GUI, no sample analysis)",
    )
    args = parser.parse_args(argv)
    if args.self_test_output is not None:
        report = collect_portable_status()
        args.self_test_output.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
        )
        if report["status"] != "ready":
            raise SystemExit(2)
        return
    from reverse_lab.gui import main as gui_main
    gui_main()


if __name__ == "__main__":
    main()
