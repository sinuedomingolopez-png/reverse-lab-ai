"""Command-line interface for local static binary inspection."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from collections.abc import Sequence

from .analyzer import inspect_file


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Inspect binary files without executing them")
    parser.add_argument("file", type=Path, help="File to inspect")
    parser.add_argument("--backend", choices=("basic", "lief", "rizin", "ghidra"), default="basic")
    parser.add_argument("--output", type=Path, help="Optional JSON report destination")
    parser.add_argument("--rizin-executable", default="rz-bin", help="Path to rz-bin (Rizin backend)")
    parser.add_argument("--ghidra-headless", help="Path to analyzeHeadless launcher (Ghidra backend)")
    parser.add_argument("--timeout", type=int, default=180, help="Backend timeout in seconds")
    args = parser.parse_args(argv)

    if args.backend == "ghidra" and not args.ghidra_headless:
        parser.error("--ghidra-headless is required for Ghidra")
    report = inspect_file(args.file)
    if args.backend == "lief":
        from .integrations.lief_adapter import inspect_with_lief
        report["analysis"] = inspect_with_lief(args.file)
    elif args.backend == "rizin":
        from .integrations.rizin_adapter import inspect_with_rizin
        report["analysis"] = inspect_with_rizin(
            args.file, executable=args.rizin_executable, timeout=args.timeout
        )
    elif args.backend == "ghidra":
        from .integrations.ghidra_adapter import analyze_with_ghidra
        report["analysis"] = analyze_with_ghidra(
            args.file, args.ghidra_headless, timeout=args.timeout
        )
    document = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.write_text(document + "\n", encoding="utf-8")
    else:
        print(document)


if __name__ == "__main__":
    main()
