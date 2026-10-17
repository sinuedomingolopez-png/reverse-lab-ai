"""Validate and compare saved Reverse Lab AI reports without executing samples."""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path

_SHA = re.compile(r"^[0-9a-fA-F]{64}$")
MAX_REPORT_BYTES = 16 * 1024 * 1024


def validate_report(report: Mapping) -> dict:
    """Validate minimum fields and function-list types before using untrusted JSON."""
    if not isinstance(report, dict):
        raise ValueError("Report JSON root must be an object")
    if not isinstance(report.get("filename"), str) or not report["filename"]:
        raise ValueError("Report filename must be a nonempty string")
    if not isinstance(report.get("sha256"), str) or not _SHA.fullmatch(report["sha256"]):
        raise ValueError("Report sha256 must be a 64-character hexadecimal digest")
    size = report.get("size_bytes")
    if type(size) is not int or size < 0:
        raise ValueError("Report size_bytes must be a nonnegative integer")
    if not isinstance(report.get("format"), str):
        raise ValueError("Report format must be a string")
    analysis = report.get("analysis", {})
    if not isinstance(analysis, dict):
        raise ValueError("Report analysis must be an object")
    functions = analysis.get("functions")
    if functions is not None:
        if not isinstance(functions, list):
            raise ValueError("Report functions must be a list")
        if len(functions) > 100000:
            raise ValueError("Too many functions in the report")
        for function in functions:
            if not isinstance(function, dict) or not all(
                isinstance(function.get(k), str) for k in ("name", "entry")
            ):
                raise ValueError("Function entries need string name and entry values")
    return report


def load_report(path: str | Path, *, max_bytes: int = MAX_REPORT_BYTES) -> dict:
    """Read a bounded UTF-8 JSON report; never unpickle or evaluate input."""
    path = Path(path)
    if not path.is_file():
        raise ValueError("Report must be a regular file")
    if max_bytes < 1 or path.stat().st_size > max_bytes:
        raise ValueError("Report file is too large")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid UTF-8 JSON report") from exc
    return validate_report(data)


def _identity(entry: dict) -> tuple[str, str]:
    return (entry["name"], entry["entry"])


def _description(report: dict) -> dict:
    analysis = report.get("analysis", {})
    return {
        "filename": report["filename"],
        "sha256": report["sha256"],
        "size_bytes": report["size_bytes"],
        "format": report["format"],
        "backend": analysis.get("backend", "basic") if isinstance(analysis.get("backend", "basic"), str) else "unknown",
    }


def compare_reports(left: Mapping, right: Mapping, *, max_changes: int = 200) -> dict:
    """Compare metadata and optional function lists from two saved reports.

    Function identities use name+entry; relocation can therefore look like change.
    """
    if not 1 <= max_changes <= 10000:
        raise ValueError("max_changes must be between 1 and 10000")
    left = validate_report(left)
    right = validate_report(right)
    a = _description(left)
    b = _description(right)
    result = {
        "schema": "reverse-lab-comparison-v1",
        "left": a,
        "right": b,
        "same_binary": a["sha256"].lower() == b["sha256"].lower(),
        "changes": {field: a[field] != b[field] for field in ("sha256", "size_bytes", "format", "backend")},
    }
    left_funcs = left.get("analysis", {}).get("functions")
    right_funcs = right.get("analysis", {}).get("functions")
    if left_funcs is None or right_funcs is None:
        result["functions"] = {
            "comparable": False,
            "reason": "Function list missing on one or both reports",
        }
        return result

    left_keys = {_identity(entry) for entry in left_funcs}
    right_keys = {_identity(entry) for entry in right_funcs}
    added = sorted(right_keys - left_keys)
    removed = sorted(left_keys - right_keys)
    result["functions"] = {
        "comparable": True,
        "left_count": len(left_keys),
        "right_count": len(right_keys),
        "common_count": len(left_keys & right_keys),
        "added_count": len(added),
        "removed_count": len(removed),
        "added": [{"name": name, "entry": entry} for name, entry in added[:max_changes]],
        "removed": [{"name": name, "entry": entry} for name, entry in removed[:max_changes]],
        "truncated": len(added) > max_changes or len(removed) > max_changes,
    }
    return result


def explain_report(report: Mapping) -> str:
    """Deterministic Spanish interpretation; no AI and no malware verdict."""
    validated = validate_report(report)
    meta = _description(validated)
    analysis = validated.get("analysis", {})
    lines = [
        f"Archivo: {meta['filename']}",
        f"Formato detectado: {meta['format']} (la firma por sí sola no confirma el tipo exacto).",
        f"Tamaño: {meta['size_bytes']} bytes.",
        f"SHA-256: {meta['sha256']}.",
        f"Motor: {meta['backend']}.",
    ]
    functions = analysis.get("functions")
    if functions is None:
        lines.append("No hay una lista de funciones exportada en este informe.")
    else:
        count = len(functions)
        lines.append(f"Se han registrado {count} función{'es' if count != 1 else ''} (nombres y direcciones, no código fuente).")
    if analysis.get("success") is False:
        lines.append("El análisis externo notificó una incidencia; revisa el informe completo.")
    lines.append("Este resumen no demuestra que el archivo sea seguro, malicioso ni cómo se comporta al ejecutarse.")
    return "\n".join(lines)


def explain_comparison(comparison: Mapping) -> str:
    """Short comparison text for CLI and GUI; does not infer semantic equivalence."""
    lines = [
        "Comparación de informes de Reverse Lab AI",
        f"Izquierda: {comparison['left']['filename']} ({comparison['left']['backend']})",
        f"Derecha: {comparison['right']['filename']} ({comparison['right']['backend']})",
        "Mismo SHA-256: " + ("sí" if comparison["same_binary"] else "no"),
    ]
    functions = comparison["functions"]
    if functions["comparable"]:
        lines.append(f"Funciones comunes: {functions['common_count']}; añadidas: {functions['added_count']}; eliminadas: {functions['removed_count']}.")
        if functions["truncated"]:
            lines.append("La lista visual está truncada; consulta los recuentos del JSON.")
        lines.append("Nota: nombres o direcciones distintas no prueban por sí solos un cambio de comportamiento.")
    else:
        lines.append("Funciones no comparables: falta una lista exportada en uno o ambos informes.")
    return "\n".join(lines)
