"""Optional static CFGFast analysis, executed in a separate Python process.

This module is the worker. It imports angr only when explicitly launched.
It does not simulate the target program or load its shared dependencies.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def analyze_cfg(target: str | Path, *, max_functions: int = 300) -> dict:
    """Recover bounded function metadata and CFG summary using angr CFGFast."""
    if type(max_functions) is not int or not 1 <= max_functions <= 500:
        raise ValueError("max_functions must be between 1 and 500")
    path = Path(target).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError("angr target must be a regular file")

    import angr  # Optional dependency; intentionally deferred.

    project = angr.Project(str(path), auto_load_libs=False)
    cfg = project.analyses.CFGFast()
    manager = cfg.kb.functions
    functions = []
    for func in manager.values():
        if len(functions) >= max_functions:
            break
        entry = getattr(func, "addr", None)
        if not isinstance(entry, int):
            continue
        name = str(getattr(func, "name", "unnamed"))[:180]
        functions.append({"name": name, "entry": hex(entry)})
    functions.sort(key=lambda f: int(f["entry"], 16))
    graph = cfg.model.graph
    return {
        "backend": "angr",
        "analysis_type": "CFGFast",
        "function_count": len(manager),
        "cfg_nodes": len(graph.nodes()),
        "cfg_edges": len(graph.edges()),
        "functions": functions,
        "truncated": len(manager) > max_functions,
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="angr CFGFast subprocess worker")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--max-functions", type=int, default=300)
    args = parser.parse_args(argv)
    try:
        result = analyze_cfg(args.input, max_functions=args.max_functions)
    except ImportError:
        parser.exit(2, "angr is not installed. Run: python -m pip install angr\n")
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
