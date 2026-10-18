"""Optional LIEF binary metadata adapter."""
from __future__ import annotations

from pathlib import Path
from itertools import islice


def _names(values, limit=500):
    return [str(getattr(value, "name", value))[:180] for value in islice(values, limit)]


def inspect_with_lief(path: str | Path) -> dict:
    try:
        import lief
    except ImportError as exc:
        raise RuntimeError("LIEF not installed. Run: pip install lief") from exc
    binary = lief.parse(str(Path(path)))
    if binary is None:
        return {"backend": "lief", "recognized": False}
    sections = [
        {"name": str(section.name)[:180],
         "address": int(section.virtual_address), "size": int(section.size),
         "offset": int(section.offset)}
        for section in islice(getattr(binary, "sections", ()), 500)
    ]
    header = getattr(binary, "header", None)
    fields = ("machine_type", "file_type", "entrypoint", "imagebase",
              "numberof_sections", "cpu_type", "cpu_subtype")
    return {
        "backend": "lief",
        "recognized": True,
        "format": type(binary).__name__,
        "entrypoint": int(getattr(binary, "entrypoint", 0)),
        "binary_format": str(getattr(binary, "format", "unknown")),
        "header": {key: str(getattr(header, key))[:180]
                   for key in fields if hasattr(header, key)},
        "sections": sections,
        "imports": _names(getattr(binary, "imported_functions", ())),
        "exports": _names(getattr(binary, "exported_functions", ())),
        "libraries": _names(getattr(binary, "libraries", ())),
        "limits": {"sections": 500, "symbols": 500,
                   "note": "Lists are capped; absence is not proof of no dependency."},
    }
