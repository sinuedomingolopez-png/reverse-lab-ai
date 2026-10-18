"""Read-only function browser joining three optional Ghidra report exports.

All names, addresses and pseudocode are untrusted display data. No execution,
evaluation, network access, import of target code or automatic AI submission.
"""
from __future__ import annotations

from collections.abc import Mapping


def _safe_label(value: object, max_len: int = 180) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return "".join(" " if ord(char) < 32 else char for char in value[:max_len])


def _node(item: object) -> tuple[str, str] | None:
    if not isinstance(item, Mapping):
        return None
    entry = _safe_label(item.get("entry"), 128)
    name = _safe_label(item.get("name"), 180)
    return (name, entry) if name and entry else None


def _report_analysis(report: Mapping) -> Mapping:
    if not isinstance(report, Mapping):
        return {}
    analysis = report.get("analysis", {})
    return analysis if isinstance(analysis, Mapping) else {}


def build_function_index(
    report: Mapping, *, max_nodes: int = 10000, max_edges: int = 5000,
) -> dict[str, dict]:
    """Join functions, decompiled fragments and call edges by entry address.

    Return a new index on each call; original report is not modified. The caps
    bound the number of nodes/edges inspected and the amount of copied text.
    """
    if not 1 <= max_nodes <= 100000 or not 1 <= max_edges <= 5000:
        raise ValueError("max_nodes must be 1..100000 and max_edges must be 1..5000")
    analysis = _report_analysis(report)
    nodes: dict[str, dict] = {}

    def ensure(item: object) -> dict | None:
        pair = _node(item)
        if pair is None:
            return None
        name, entry = pair
        if entry not in nodes:
            if len(nodes) >= max_nodes:
                return None
            nodes[entry] = {"name": name, "entry": entry, "pseudocode": None,
                            "error": None, "calls_out": {}, "calls_in": {}}
        return nodes[entry]

    exported = analysis.get("functions")
    if isinstance(exported, list):
        for item in exported[:max_nodes]:
            ensure(item)

    fragments = analysis.get("pseudocode")
    if isinstance(fragments, list):
        for item in fragments[:max_nodes]:
            if not isinstance(item, Mapping):
                continue
            code = item.get("pseudocode")
            error = item.get("error")
            if not isinstance(code, str) and not isinstance(error, str):
                continue
            node = ensure(item)
            if node is not None:
                if isinstance(code, str):
                    node["pseudocode"] = code[:8000]
                if isinstance(error, str):
                    node["error"] = _safe_label(error, 250)

    edges = analysis.get("call_graph")
    if isinstance(edges, list):
        for edge in edges[:max_edges]:
            if not isinstance(edge, Mapping):
                continue
            caller = ensure(edge.get("caller"))
            callee = ensure(edge.get("callee"))
            if caller is None or callee is None:
                continue
            if callee["entry"] not in caller["calls_out"]:
                caller["calls_out"][callee["entry"]] = {"name": callee["name"],
                                                         "entry": callee["entry"]}
            if caller["entry"] not in callee["calls_in"]:
                callee["calls_in"][caller["entry"]] = {"name": caller["name"],
                                                       "entry": caller["entry"]}
    return nodes


def search_functions(
    index: Mapping[str, dict], query: str = "", *, limit: int = 500,
) -> list[tuple[str, str]]:
    """Return matching (name, entry) pairs in stable address order."""
    if not 1 <= limit <= 10000:
        raise ValueError("limit must be between 1 and 10000")
    term = str(query or "").casefold()[:180]
    result = []
    for entry, node in sorted(index.items()):
        name = node["name"]
        if term in name.casefold() or term in entry.casefold():
            result.append((name, entry))
            if len(result) >= limit:
                break
    return result


def describe_function(
    index: Mapping[str, dict], entry: str, *, max_calls: int = 30,
) -> dict | None:
    if not 1 <= max_calls <= 2000:
        raise ValueError("max_calls must be between 1 and 2000")
    node = index.get(entry)
    if node is None:
        return None
    return {
        "name": node["name"], "entry": node["entry"],
        "pseudocode": node["pseudocode"], "error": node["error"],
        "calls_out": list(node["calls_out"].values())[:max_calls],
        "calls_in": list(node["calls_in"].values())[:max_calls],
        "outgoing_count": len(node["calls_out"]),
        "incoming_count": len(node["calls_in"]),
    }


def format_function_details(details: Mapping | None) -> str:
    """Plain text for a read-only GUI widget; does not run recovered code."""
    if details is None:
        return "Selecciona una función para consultar su ficha técnica."
    lines = [
        f"FUNCIÓN: {details['name']}", f"DIRECCIÓN: {details['entry']}", "",
        f"LLAMADAS SALIENTES ({details['outgoing_count']} detectadas)",
    ]
    lines.extend(f"  → {x['name']} ({x['entry']})" for x in details["calls_out"])
    if not details["calls_out"]:
        lines.append("  Ninguna detectada (podrían existir llamadas indirectas).")
    lines.extend(["", f"LLAMADAS ENTRANTES ({details['incoming_count']} detectadas)"])
    lines.extend(f"  ← {x['name']} ({x['entry']})" for x in details["calls_in"])
    if not details["calls_in"]:
        lines.append("  Ninguna detectada.")
    lines.extend(["", "PSEUDOCÓDIGO C (aproximado; no es el código fuente original)"])
    if details["pseudocode"] is not None:
        lines.append(details["pseudocode"])
    elif details["error"]:
        lines.append("No disponible: " + details["error"])
    else:
        lines.append("No disponible en el informe: activa su exportación en Ghidra.")
    lines.extend(["", "Aviso: los nombres, direcciones y fragmentos proceden de datos no confiables."])
    return "\n".join(lines)
