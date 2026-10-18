"""Private static-analysis worker; no remote command or executable parameters."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main():
    # Parent attaches Windows Job Object before releasing this gate.
    if sys.stdin.buffer.read(1) != b"1":
        raise SystemExit(2)
    request = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    if sys.platform != "win32":
        import resource
        cap = request["memory_bytes"]
        resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
        resource.setrlimit(resource.RLIMIT_CPU, (request["timeout"], request["timeout"] + 1))
        resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
    from .workflow import analyze
    from .authorizations import digest_file
    path = Path(request["input"])
    if digest_file(path) != request["sha256"]:
        raise SystemExit(3)
    report = analyze(path, **request["options"])
    report["filename"] = "authorized-sample"
    analysis = report.get("analysis", {})
    # Do not write raw engine logs to report storage or return them via MCP.
    for key in ("stdout_tail", "stderr_tail", "error"):
        analysis.pop(key, None)
    encoded = json.dumps(report, ensure_ascii=True).encode("utf-8")
    if len(encoded) > 16 * 1024 * 1024:
        raise SystemExit(4)
    Path(request["output"]).write_bytes(encoded)


if __name__ == "__main__":
    main()
