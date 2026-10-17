"""Command-line entrypoint for static analysis."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import inspect_file


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect a file without executing it")
    parser.add_argument("file", type=Path, help="File to inspect")
    parser.add_argument("--output", type=Path, help="Optional JSON report file")
    args = parser.parse_args()
    report = json.dumps(inspect_file(args.file), indent=2, ensure_ascii=False)
    if args.output:
        args.output.write_text(report + "\n", encoding="utf-8")
    else:
        print(report)


if __name__ == "__main__":
    main()
