"""Bounded visual rendering of actual static CFG blocks; never executes nodes."""
from __future__ import annotations


def open_cfg(parent, report):
    import tkinter as tk
    from tkinter import messagebox, ttk
    graph = (report or {}).get("analysis", {}).get("cfg_graph")
    if not isinstance(graph, dict) or not graph.get("nodes"):
        messagebox.showinfo("CFG estático", "Analiza con angr para recuperar bloques y conexiones del CFG.", parent=parent)
        return None
    window = tk.Toplevel(parent)
    window.title("Reverse Lab AI · CFGFast estático")
    window.geometry("1040x620")
    frame = ttk.Frame(window, padding=16)
    frame.pack(fill="both", expand=True)
    nodes = graph["nodes"][:40]
    entries = {node["entry"]: node for node in nodes}
    edges = [edge for edge in graph.get("edges", [])
             if edge.get("source") in entries and edge.get("target") in entries][:120]
    ttk.Label(frame, text=f"CFG estático · {len(nodes)} de {len(graph['nodes'])} bloques exportados · "
              f"{len(edges)} conexiones visibles. Puede omitir relaciones indirectas.",
              wraplength=980).pack(anchor="w", pady=(0, 12))
    canvas = tk.Canvas(frame, background="#1e2c40", highlightthickness=0)
    scroll = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
    scroll.pack(side="right", fill="y")
    canvas.pack(fill="both", expand=True)
    canvas.configure(yscrollcommand=scroll.set, scrollregion=(0, 0, 980, max(500, ((len(nodes) + 4) // 5) * 110)))
    positions = {node["entry"]: (100 + i % 5 * 190, 55 + i // 5 * 110)
                 for i, node in enumerate(nodes)}
    for edge in edges:
        x1, y1 = positions[edge["source"]]
        x2, y2 = positions[edge["target"]]
        canvas.create_line(x1, y1 + 26, x2, y2 - 26, arrow="last", fill="#99aabd", width=2)
    for node in nodes:
        x, y = positions[node["entry"]]
        canvas.create_rectangle(x - 78, y - 25, x + 78, y + 25, fill="#151e2e", outline="#4ce0d2")
        canvas.create_text(x, y, text=node["entry"][:32], fill="#eef6ff", font=("Consolas", 10))
    return window
