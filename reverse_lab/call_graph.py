"""Safe read-only representation of statically resolved Ghidra call edges.

Functions called dynamically through pointers/reflection may be absent. Addresses
are used for graph identity; names remain untrusted, display-only labels.
"""
from __future__ import annotations

from collections.abc import Mapping


def _node(item: object) -> bool:
    return (isinstance(item, Mapping) and
            isinstance(item.get('name'), str) and
            isinstance(item.get('entry'), str))


def _edge(item: object) -> bool:
    return (isinstance(item, Mapping) and
            _node(item.get('caller')) and _node(item.get('callee')))


def extract_call_edges(report: Mapping, *, limit: int = 250) -> list[dict]:
    """Extract bounded valid edges without mutating input or interpreting labels."""
    if limit < 1 or limit > 5000:
        raise ValueError('limit must be between 1 and 5000')
    analysis = report.get('analysis', {}) if isinstance(report, Mapping) else {}
    if not isinstance(analysis, Mapping):
        return []
    entries = analysis.get('call_graph', [])
    if not isinstance(entries, list):
        return []
    valid = []
    for item in entries:
        if _edge(item):
            valid.append(item)
            if len(valid) >= limit:
                break
    return valid


def outgoing_calls(edges: list[dict], caller_entry: str, *, limit: int = 12) -> list[tuple[str, str]]:
    """Return unique direct callees of one function, bounded for GUI rendering."""
    if limit < 1 or limit > 5000:
        raise ValueError('limit must be between 1 and 5000')
    result, seen = [], set()
    for edge in edges:
        if _edge(edge) and edge['caller']['entry'] == caller_entry:
            callee = edge['callee']
            entry = callee['entry']
            if entry not in seen:
                result.append((callee['name'], entry))
                seen.add(entry)
            if len(result) == limit:
                break
    return result


def _dot_quote(value: str) -> str:
    """Quote one Graphviz identifier/label to prevent DOT syntax injection."""
    normalized = ''.join(' ' if ord(char) < 32 else char for char in value[:250])
    return '"' + normalized.replace('\\', '\\\\').replace('"', '\\"') + '"'


def build_dot(report: Mapping, *, limit: int = 300) -> str:
    """Make a DOT graph suitable for rendering locally with optional Graphviz."""
    edges = extract_call_edges(report, limit=limit)
    lines = [
        'digraph ReverseLabCalls {',
        '  graph [rankdir=LR, bgcolor="#101826"];',
        '  node [shape=box, style=rounded, color="#31d3c6", fontcolor=white];',
        '  edge [color="#688caa"];',
    ]
    nodes = {}
    for edge in edges:
        for side in ('caller', 'callee'):
            node = edge[side]
            nodes.setdefault(node['entry'], node['name'])
    for address, name in sorted(nodes.items()):
        label = name + ' @ ' + address
        lines.append(f'  {_dot_quote(address)} [label={_dot_quote(label)}];')
    for edge in edges:
        lines.append('  ' + _dot_quote(edge['caller']['entry']) + ' -> ' +
                     _dot_quote(edge['callee']['entry']) + ';')
    lines.append('}')
    return '\n'.join(lines) + '\n'
