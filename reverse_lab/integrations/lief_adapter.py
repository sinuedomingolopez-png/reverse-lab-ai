"""Optional LIEF binary metadata adapter."""
from __future__ import annotations

from pathlib import Path


def inspect_with_lief(path: str | Path) -> dict:
    try:
        import lief
    except ImportError as exc:
        raise RuntimeError("LIEF not installed. Run: pip install lief") from exc
    binary = lief.parse(str(Path(path)))
    if binary is None:
        return {"backend": "lief", "recognized": False}
    return {
        "backend": "lief",
        "recognized": True,
        "format": type(binary).__name__,
        "entrypoint": int(getattr(binary, "entrypoint", 0)),
    }
