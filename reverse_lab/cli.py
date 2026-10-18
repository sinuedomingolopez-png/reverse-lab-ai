"""Command-line interface for local static binary inspection."""
from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from .workflow import BACKENDS, analyze


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Inspect binary files without executing them")
    parser.add_argument("file", type=Path, help="File to inspect")
    parser.add_argument("--backend", choices=BACKENDS, default="basic")
    parser.add_argument("--output", type=Path, help="Optional JSON report destination")
    parser.add_argument("--rizin-executable", default="rz-bin", help="Path to rz-bin (Rizin backend)")
    parser.add_argument("--ghidra-headless", help="Path to analyzeHeadless launcher (Ghidra backend)")
    parser.add_argument("--timeout", type=int, default=180, help="Backend timeout in seconds")
    parser.add_argument("--export-functions", action="store_true", help="Ghidra: export names and entry addresses")
    parser.add_argument("--export-pseudocode", action="store_true", help="Ghidra: export bounded C-like pseudocode")
    parser.add_argument("--export-call-graph", action="store_true", help="Ghidra: export bounded static function calls")
    args = parser.parse_args(argv)
    if args.export_call_graph and args.backend != "ghidra":
        parser.error("--export-call-graph requires --backend ghidra")
    if args.export_pseudocode and args.backend != "ghidra":
        parser.error("--export-pseudocode requires --backend ghidra")

    if args.backend == "ghidra" and not args.ghidra_headless:
        parser.error("--ghidra-headless is required for Ghidra")
    report = analyze(
        args.file, backend=args.backend,
        rizin_executable=args.rizin_executable,
        ghidra_headless=args.ghidra_headless,
        timeout=args.timeout,
        export_functions=args.export_functions,
        export_pseudocode=args.export_pseudocode,
        export_call_graph=args.export_call_graph,
    )
    document = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.write_text(document + "\n", encoding="utf-8")
    else:
        print(document)


if __name__ == "__main__":
    main()
