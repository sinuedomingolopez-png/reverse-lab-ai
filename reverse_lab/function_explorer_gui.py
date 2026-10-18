"""Tkinter function explorer for local Ghidra reports.

This widget only displays bounded, untrusted report data. It does not execute
pseudocode, make network requests, or send any data to an AI service.
"""
from __future__ import annotations

from .function_browser import (
    build_function_index, search_functions, describe_function, format_function_details,
)


class FunctionExplorerWindow:
    """Searchable function list with in/out references and read-only pseudocode."""

    def __init__(self, parent, report: dict, *, initial_entry: str | None = None):
        import tkinter as tk
        from tkinter import scrolledtext, ttk

        self.index = build_function_index(report)
        self.current_entry = None
        self.back_stack: list[str] = []
        self.window = tk.Toplevel(parent)
        self.window.title("REVERSE LAB AI | Explorador de funciones")
        self.window.geometry("1140x750")
        self.window.minsize(780, 550)
        self.window.configure(bg="#0a101b")
        self.search_var = tk.StringVar()
        self.count_var = tk.StringVar()
        self.title_var = tk.StringVar(value="Selecciona una función")

        body = ttk.Frame(self.window, padding=16)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="EXPLORADOR DE FUNCIONES", font=("Segoe UI", 15, "bold")).pack(
            anchor="w", pady=(0, 12))
        panes = ttk.PanedWindow(body, orient="horizontal")
        panes.pack(fill="both", expand=True)
        left = ttk.Frame(panes, padding=8)
        right = ttk.Frame(panes, padding=8)
        panes.add(left, weight=2)
        panes.add(right, weight=3)

        ttk.Label(left, text="Buscar por nombre o dirección").pack(anchor="w")
        query = ttk.Entry(left, textvariable=self.search_var)
        query.pack(fill="x", pady=(5, 6))
        ttk.Label(left, textvariable=self.count_var).pack(anchor="w")
        self.functions = ttk.Treeview(left, columns=("name", "entry"), show="headings")
        self.functions.heading("name", text="Función")
        self.functions.heading("entry", text="Dirección")
        self.functions.column("name", width=200)
        self.functions.column("entry", width=105)
        self.functions.pack(fill="both", expand=True, pady=(8, 0))
        self.functions.bind("<<TreeviewSelect>>", self._select_function)

        header = ttk.Frame(right)
        header.pack(fill="x")
        ttk.Label(header, textvariable=self.title_var, font=("Segoe UI", 12, "bold")).pack(side="left")
        self.back_button = ttk.Button(header, text="← Anterior", command=self.go_back, state="disabled")
        self.back_button.pack(side="right")

        tabs = ttk.Notebook(right)
        tabs.pack(fill="both", expand=True, pady=(12, 0))
        code_tab, out_tab, in_tab = (ttk.Frame(tabs, padding=6), ttk.Frame(tabs, padding=6), ttk.Frame(tabs, padding=6))
        tabs.add(code_tab, text="Ficha y pseudocódigo")
        tabs.add(out_tab, text="Llama a")
        tabs.add(in_tab, text="Llamada por")
        self.details = scrolledtext.ScrolledText(code_tab, wrap="word", relief="flat", bg="#1e2c40",
                    fg="#eef6ff", insertbackground="#eef6ff", font=("Consolas", 10), padx=10, pady=10)
        self.details.pack(fill="both", expand=True)
        self.details.insert("1.0", format_function_details(None))
        self.details.configure(state="disabled")
        self.out_tree = self._relation_tree(out_tab, ttk)
        self.in_tree = self._relation_tree(in_tab, ttk)
        self.out_tree.bind("<Double-1>", lambda _event: self._follow_relation(self.out_tree))
        self.in_tree.bind("<Double-1>", lambda _event: self._follow_relation(self.in_tree))
        self.search_var.trace_add("write", lambda *_: self.filter_functions())
        self.filter_functions()
        if initial_entry and initial_entry in self.index:
            self.open_entry(initial_entry)
        elif self.index:
            self.open_entry(next(iter(sorted(self.index))))
        query.focus_set()

    @staticmethod
    def _relation_tree(parent, ttk):
        tree = ttk.Treeview(parent, columns=("name", "entry"), show="headings")
        tree.heading("name", text="Función relacionada")
        tree.heading("entry", text="Dirección")
        tree.column("name", width=280)
        tree.column("entry", width=140)
        tree.pack(fill="both", expand=True)
        ttk.Label(parent, text="Doble clic para abrir la función relacionada.").pack(anchor="w", pady=6)
        return tree

    @staticmethod
    def _set_text(widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def filter_functions(self):
        query = self.search_var.get()
        results = search_functions(self.index, query, limit=500)
        self.functions.delete(*self.functions.get_children())
        for name, entry in results:
            self.functions.insert("", "end", iid=entry, values=(name, entry))
        self.count_var.set(f"{len(results)} mostradas / {len(self.index)} en el índice (máximo 500)")
        if self.current_entry in self.functions.get_children():
            self.functions.selection_set(self.current_entry)
            self.functions.see(self.current_entry)

    def _select_function(self, _event=None):
        selected = self.functions.selection()
        if selected and selected[0] != self.current_entry:
            self.open_entry(selected[0])

    def open_entry(self, entry: str, *, remember: bool = True):
        details = describe_function(self.index, entry, max_calls=200)
        if details is None:
            return
        if remember and self.current_entry and self.current_entry != entry:
            self.back_stack.append(self.current_entry)
            self.back_stack = self.back_stack[-50:]
        self.current_entry = entry
        self.title_var.set(f"{details['name']}  ·  {details['entry']}")
        self._set_text(self.details, format_function_details(details))
        for tree, key in ((self.out_tree, "calls_out"), (self.in_tree, "calls_in")):
            tree.delete(*tree.get_children())
            for relation in details[key]:
                tree.insert("", "end", iid=relation["entry"],
                            values=(relation["name"], relation["entry"]))
        self.back_button.configure(state="normal" if self.back_stack else "disabled")
        if entry in self.functions.get_children():
            self.functions.selection_set(entry)
            self.functions.see(entry)

    def _follow_relation(self, tree):
        selection = tree.selection()
        if selection:
            self.open_entry(selection[0])

    def go_back(self):
        if self.back_stack:
            self.open_entry(self.back_stack.pop(), remember=False)
            self.back_button.configure(state="normal" if self.back_stack else "disabled")


def open_function_explorer(parent, report: dict | None, *, initial_entry: str | None = None):
    """Create a local explorer window for an existing analysis report."""
    from tkinter import messagebox
    if not report:
        messagebox.showinfo("Explorador", "Analiza un archivo con Ghidra antes de explorar funciones.", parent=parent)
        return None
    explorer = FunctionExplorerWindow(parent, report, initial_entry=initial_entry)
    if not explorer.index:
        messagebox.showinfo("Explorador", "El informe no contiene funciones. Exporta funciones o mapa de llamadas.",
                            parent=explorer.window)
    return explorer
