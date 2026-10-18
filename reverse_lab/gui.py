"""Local desktop dashboard for authorized binary inspection.

Uses Tkinter from Python's standard library. No server, external API, telemetry
or file upload is involved. Heavy analyses are run on a worker thread.
"""
from __future__ import annotations

import json
from collections.abc import Mapping

from .workflow import analyze, BACKENDS
from .call_graph import extract_call_edges, outgoing_calls, build_dot
from . import report_gui, function_explorer_gui


def extract_function_rows(report: Mapping, *, limit: int = 500) -> list[tuple[str, str]]:
    """Return validated Ghidra function entries for display in a tree."""
    analysis = report.get("analysis", {})
    if not isinstance(analysis, Mapping):
        return []
    functions = analysis.get("functions", [])
    if not isinstance(functions, list) or limit <= 0:
        return []
    results = []
    for item in functions:
        if not isinstance(item, Mapping):
            continue
        if isinstance(item.get("name"), str) and isinstance(item.get("entry"), str):
            results.append((item["name"], item["entry"]))
        if len(results) >= limit:
            break
    return results


def format_report_preview(report: Mapping, *, limit: int = 180_000) -> str:
    """Shorten only the UI preview; saving always uses the complete JSON."""
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if len(text) > limit:
        return text[:max(0, limit)] + "\n\n[Contenido truncado. Exporta el informe para obtener el JSON completo.]"
    return text


def main() -> None:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, scrolledtext, ttk
    except ImportError as exc:
        raise RuntimeError("Tkinter is unavailable. Install the OS Python Tk package.") from exc
    import queue
    import threading
    from pathlib import Path

    BG, PANEL, FIELD, TEXT, MUTED, ACCENT = (
        "#0a101b", "#151e2e", "#1e2c40", "#eef6ff", "#99aabd", "#4ce0d2"
    )

    class ReverseLabApp:
        def __init__(self, root):
            self.root = root
            self.report = None
            self.messages = queue.Queue()
            self.busy = False
            self.root.title("REVERSE LAB AI  |  LOCAL ANALYSIS")
            self.root.geometry("1050x760")
            self.root.minsize(780, 560)
            self.root.configure(bg=BG)
            self.file_var = tk.StringVar()
            self.backend_var = tk.StringVar(value="basic")
            self.ghidra_var = tk.StringVar()
            self.rizin_var = tk.StringVar(value="rz-bin")
            self.timeout_var = tk.StringVar(value="180")
            self.export_var = tk.BooleanVar(value=True)
            self.pseudocode_var = tk.BooleanVar(value=False)
            self.call_graph_var = tk.BooleanVar(value=False)
            self.call_edges = []
            self.status_var = tk.StringVar(value="Preparado · análisis local, sin subir archivos")
            style = ttk.Style(root)
            style.theme_use("clam")
            style.configure("TFrame", background=BG)
            style.configure("Panel.TFrame", background=PANEL)
            style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
            style.configure("Sub.TLabel", background=BG, foreground=MUTED)
            style.configure("Panel.TLabel", background=PANEL, foreground=MUTED)
            style.configure("TButton", padding=(15, 9), font=("Segoe UI", 10))
            style.configure("Accent.TButton", background=ACCENT, foreground=BG)
            style.map("Accent.TButton", background=[("active", "#8df4e8")])
            style.configure("TEntry", fieldbackground=FIELD, foreground=TEXT, insertcolor=TEXT)
            style.configure("TCombobox", fieldbackground=FIELD, foreground=BG)
            style.configure("TCheckbutton", background=BG, foreground=TEXT)
            style.configure("TNotebook", background=BG, borderwidth=0)
            style.configure("TNotebook.Tab", padding=(18, 10), background=PANEL, foreground=MUTED)
            style.map("TNotebook.Tab", background=[("selected", FIELD)], foreground=[("selected", TEXT)])
            style.configure("Treeview", background=FIELD, fieldbackground=FIELD, foreground=TEXT,
                            rowheight=29, borderwidth=0)
            style.configure("Treeview.Heading", background=PANEL, foreground=ACCENT, font=("Segoe UI", 10, "bold"))

            container = ttk.Frame(root, padding=24)
            container.pack(fill="both", expand=True)
            tk.Label(container, text="REVERSE / LAB AI", font=("Segoe UI", 22, "bold"),
                     bg=BG, fg=ACCENT).pack(anchor="w")
            ttk.Label(container, text="Ingeniería inversa · laboratorio local · versión inicial",
                      style="Sub.TLabel").pack(anchor="w", pady=(0, 18))

            source = ttk.Frame(container)
            source.pack(fill="x", pady=(0, 10))
            ttk.Label(source, text="ARCHIVO QUE QUIERES ANALIZAR").pack(anchor="w", pady=(0, 5))
            entry_row = ttk.Frame(source)
            entry_row.pack(fill="x")
            ttk.Entry(entry_row, textvariable=self.file_var).pack(side="left", fill="x", expand=True)
            ttk.Button(entry_row, text="Examinar…", command=self.choose_file).pack(side="left", padx=(10, 0))

            settings = ttk.Frame(container)
            settings.pack(fill="x", pady=(4, 10))
            ttk.Label(settings, text="Motor").grid(row=0, column=0, sticky="w")
            ttk.Label(settings, text="Tiempo límite (seg.)").grid(row=0, column=1, sticky="w", padx=16)
            ttk.Label(settings, text="Ruta de Ghidra analyzeHeadless").grid(row=0, column=2, sticky="w")
            combo = ttk.Combobox(settings, textvariable=self.backend_var,
                                 values=BACKENDS, width=16, state="readonly")
            combo.grid(row=1, column=0, sticky="ew", pady=(4, 0))
            ttk.Entry(settings, textvariable=self.timeout_var, width=12).grid(
                row=1, column=1, sticky="ew", padx=16, pady=(4, 0))
            ttk.Entry(settings, textvariable=self.ghidra_var).grid(row=1, column=2, sticky="ew", pady=(4, 0))
            settings.columnconfigure(2, weight=1)

            options = ttk.Frame(container)
            options.pack(fill="x", pady=(0, 14))
            ttk.Checkbutton(options, text="Exportar funciones de Ghidra", variable=self.export_var).pack(side="left")
            ttk.Checkbutton(options, text="Pseudocódigo (experimental)", variable=self.pseudocode_var).pack(side="left", padx=(12, 0))
            ttk.Checkbutton(options, text="Mapa de llamadas", variable=self.call_graph_var).pack(side="left", padx=(12, 0))
            ttk.Label(options, text="rz-bin:").pack(side="left", padx=(20, 6))
            ttk.Entry(options, textvariable=self.rizin_var, width=26).pack(side="left")

            actions = ttk.Frame(container)
            actions.pack(fill="x", pady=(0, 10))
            self.run_button = ttk.Button(actions, text="Analizar archivo", style="Accent.TButton", command=self.run_analysis)
            self.run_button.pack(side="left")
            self.save_button = ttk.Button(actions, text="Guardar JSON", command=self.save_report, state="disabled")
            self.save_button.pack(side="left", padx=10)
            ttk.Button(actions, text="Comprobar herramientas", command=self.check_tools).pack(side="left")
            ttk.Button(actions, text="Comparar JSON", command=lambda: report_gui.compare_saved_reports(self.root)).pack(side="left", padx=(6, 0))
            ttk.Button(actions, text="Explicar", command=lambda: report_gui.explain_current_report(self.root, self.report)).pack(side="left", padx=(6, 0))
            self.progress = ttk.Progressbar(actions, mode="indeterminate", length=145)
            self.progress.pack(side="right", padx=(10, 0))
            ttk.Label(container, textvariable=self.status_var, style="Sub.TLabel").pack(anchor="w", pady=(1, 10))

            tabs = ttk.Notebook(container)
            tabs.pack(fill="both", expand=True)
            summary_page = ttk.Frame(tabs, padding=12, style="Panel.TFrame")
            functions_page = ttk.Frame(tabs, padding=12, style="Panel.TFrame")
            pseudocode_page = ttk.Frame(tabs, padding=12, style="Panel.TFrame")
            call_graph_page = ttk.Frame(tabs, padding=12, style="Panel.TFrame")
            json_page = ttk.Frame(tabs, padding=12, style="Panel.TFrame")
            tabs.add(summary_page, text="Resumen")
            tabs.add(functions_page, text="Funciones")
            tabs.add(pseudocode_page, text="Pseudocódigo")
            tabs.add(call_graph_page, text="Mapa de llamadas")
            tabs.add(json_page, text="JSON")

            self.summary = scrolledtext.ScrolledText(summary_page, bg=FIELD, fg=TEXT, insertbackground=TEXT,
                      wrap="word", relief="flat", font=("Consolas", 11), padx=14, pady=14)
            self.summary.pack(fill="both", expand=True)
            self.summary.insert("1.0", "Selecciona un archivo para comenzar.\n\nLos análisis no salen de tu ordenador.")
            self.summary.configure(state="disabled")
            function_header = ttk.Frame(functions_page, style="Panel.TFrame")
            function_header.pack(fill="x", pady=(0, 8))
            ttk.Label(function_header, text="Selecciona una función o abre el explorador unificado.",
                      style="Panel.TLabel").pack(side="left")
            ttk.Button(function_header, text="Explorar funciones",
                       command=self.open_function_explorer).pack(side="right")
            self.functions = ttk.Treeview(functions_page, columns=("name", "entry"), show="headings")
            self.functions.heading("name", text="FUNCIÓN")
            self.functions.heading("entry", text="DIRECCIÓN DE ENTRADA")
            self.functions.column("name", width=530)
            self.functions.column("entry", width=270)
            self.functions.pack(fill="both", expand=True)
            self.functions.bind("<Double-1>", self.open_function_from_list)
            self.pseudocode_view = scrolledtext.ScrolledText(
                pseudocode_page, bg=FIELD, fg=TEXT, insertbackground=TEXT,
                wrap="none", relief="flat", font=("Consolas", 10), padx=14, pady=14)
            self.pseudocode_view.pack(fill="both", expand=True)
            self.pseudocode_view.configure(state="disabled")
            call_header = ttk.Frame(call_graph_page, style="Panel.TFrame")
            call_header.pack(fill="x", pady=(0, 8))
            ttk.Label(call_header, text="Conexiones de llamadas estáticas detectadas", style="Panel.TLabel").pack(side="left")
            self.dot_button = ttk.Button(call_header, text="Guardar .DOT", command=self.save_call_dot,
                                         state="disabled")
            self.dot_button.pack(side="right")
            self.call_tree = ttk.Treeview(call_graph_page, columns=("caller", "callee", "entry"),
                                          show="headings", height=7)
            self.call_tree.heading("caller", text="FUNCIÓN ORIGEN")
            self.call_tree.heading("callee", text="FUNCIÓN DESTINO")
            self.call_tree.heading("entry", text="DIRECCIÓN DESTINO")
            self.call_tree.column("caller", width=270)
            self.call_tree.column("callee", width=290)
            self.call_tree.column("entry", width=160)
            self.call_tree.pack(fill="both", expand=True)
            self.call_tree.bind("<<TreeviewSelect>>", self.show_selected_calls)
            self.call_tree.bind("<Double-1>", self.open_function_from_call)
            self.call_canvas = tk.Canvas(call_graph_page, bg=FIELD, highlightthickness=0, height=215)
            self.call_canvas.pack(fill="x", pady=(10, 0))
            self.call_canvas.bind("<Configure>", self.show_selected_calls)
            self.draw_calls(None)
            self.json_view = scrolledtext.ScrolledText(json_page, bg=FIELD, fg=TEXT,
                    insertbackground=TEXT, wrap="none", relief="flat", font=("Consolas", 10), padx=14, pady=14)
            self.json_view.pack(fill="both", expand=True)
            self.json_view.configure(state="disabled")
            self.root.after(125, self.poll_results)

        @staticmethod
        def set_text(widget, text):
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.insert("1.0", text)
            widget.configure(state="disabled")

        def choose_file(self):
            path = filedialog.askopenfilename(title="Selecciona un archivo autorizado")
            if path:
                self.file_var.set(path)

        def check_tools(self):
            from .doctor import check_environment
            try:
                info = check_environment()["tools"]
                lines = [f"{key}: {'Disponible' if value['available'] else 'No instalado / no detectado'}"
                         for key, value in info.items()]
                messagebox.showinfo("Herramientas locales", "\n".join(lines))
            except Exception as exc:
                messagebox.showerror("Error", str(exc))

        def run_analysis(self):
            if self.busy:
                return
            path = self.file_var.get().strip()
            if not path or not Path(path).is_file():
                messagebox.showwarning("Archivo", "Selecciona un archivo existente.")
                return
            try:
                timeout = int(self.timeout_var.get().strip())
                if not 1 <= timeout <= 3600:
                    raise ValueError
            except ValueError:
                messagebox.showwarning("Tiempo límite", "Introduce entre 1 y 3600 segundos.")
                return
            backend = self.backend_var.get()
            launcher = self.ghidra_var.get().strip() or None
            if backend == "ghidra" and not launcher:
                messagebox.showwarning("Ghidra", "Selecciona analyzeHeadless para usar Ghidra.")
                return
            if self.call_graph_var.get() and backend != "ghidra":
                messagebox.showwarning("Mapa de llamadas", "Selecciona Ghidra para exportar conexiones.")
                return
            if self.pseudocode_var.get() and backend != "ghidra":
                messagebox.showwarning("Pseudocódigo", "Esta función necesita el motor Ghidra.")
                return
            params = dict(backend=backend, timeout=timeout,
                          ghidra_headless=launcher,
                          rizin_executable=self.rizin_var.get().strip() or "rz-bin",
                          export_functions=self.export_var.get(),
                          export_pseudocode=self.pseudocode_var.get(),
                          export_call_graph=self.call_graph_var.get())
            self.busy = True
            self.run_button.configure(state="disabled")
            self.status_var.set(f"Analizando {Path(path).name} con {backend}…")
            self.progress.start(12)
            threading.Thread(target=self.worker, args=(path, params), daemon=True).start()

        def worker(self, path, params):
            try:
                report = analyze(path, **params)
            except Exception as exc:
                self.messages.put((False, f"{type(exc).__name__}: {exc}"))
            else:
                self.messages.put((True, report))

        def poll_results(self):
            try:
                while True:
                    success, result = self.messages.get_nowait()
                    self.busy = False
                    self.run_button.configure(state="normal")
                    self.progress.stop()
                    if success:
                        self.report = result
                        self.save_button.configure(state="normal")
                        details = result.get("analysis", {})
                        ok = details.get("success", True) if isinstance(details, Mapping) else True
                        status = "Completado" if ok else "Análisis con incidencias"
                        self.status_var.set(f"{status} · {result['filename']}")
                        self.display(result)
                    else:
                        self.status_var.set("Error durante el análisis")
                        messagebox.showerror("Análisis fallido", result)
            except queue.Empty:
                pass
            self.root.after(125, self.poll_results)

        def display(self, report):
            summary = [
                f"ARCHIVO     {report.get('filename', '-')}",
                f"FORMATO     {report.get('format', '-')}",
                f"TAMAÑO      {report.get('size_bytes', 0):,} bytes",
                f"SHA-256     {report.get('sha256', '-')}",
                f"MOTOR       {report.get('analysis', {}).get('backend', 'basic')}",
            ]
            result = report.get("analysis")
            if isinstance(result, dict):
                if "success" in result:
                    summary.append(f"ÉXITO       {result['success']}")
                if "error" in result:
                    summary.append(f"AVISO       {result['error']}")
                if "function_count" in result:
                    summary.append(f"FUNCIONES   {result['function_count']}")
                if "call_graph_count" in result:
                    summary.append(f"LLAMADAS    {result['call_graph_count']} relaciones detectadas")
            self.set_text(self.summary, "\n".join(summary))
            for item in self.functions.get_children():
                self.functions.delete(item)
            for name, entry in extract_function_rows(report):
                self.functions.insert("", "end", values=(name, entry))
            snippets = result.get("pseudocode", []) if isinstance(result, dict) else []
            blocks = []
            if isinstance(snippets, list):
                for item in snippets[:20]:
                    if isinstance(item, dict):
                        code = item.get("pseudocode")
                        text = code[:8000] if isinstance(code, str) else "Error: " + str(item.get("error", "No disponible"))[:250]
                        blocks.append(f"// {item.get('name', 'función')} @ {item.get('entry', '?')}\n{text}")
            self.set_text(self.pseudocode_view, "\n\n".join(blocks) if blocks else
                          "Sin pseudocódigo. Marca Pseudocódigo y elige el motor Ghidra.\n"
                          "El resultado es aproximado y puede contener datos confidenciales.")
            self.call_edges = extract_call_edges(report, limit=500)
            self.call_tree.delete(*self.call_tree.get_children())
            for i, edge in enumerate(self.call_edges):
                caller, callee = edge["caller"], edge["callee"]
                self.call_tree.insert("", "end", iid=str(i),
                                      values=(caller["name"], callee["name"], callee["entry"]))
            self.dot_button.configure(state="normal" if self.call_edges else "disabled")
            if self.call_edges:
                self.call_tree.selection_set("0")
            self.show_selected_calls()
            self.set_text(self.json_view, format_report_preview(report))

        def show_selected_calls(self, _event=None):
            selections = self.call_tree.selection()
            if not selections:
                self.draw_calls(None)
                return
            try:
                edge = self.call_edges[int(selections[0])]
            except (IndexError, ValueError):
                self.draw_calls(None)
                return
            self.draw_calls(edge["caller"])

        def draw_calls(self, caller):
            canvas = self.call_canvas
            canvas.delete("all")
            width = max(470, canvas.winfo_width())
            if not caller:
                canvas.create_text(width / 2, 105, text="Sin llamadas exportadas. Selecciona Ghidra y marca Mapa de llamadas.",
                                   fill=MUTED, font=("Segoe UI", 10))
                return
            entry = caller["entry"]
            callees = outgoing_calls(self.call_edges, entry, limit=8)
            center_x = width / 2
            canvas.create_oval(center_x - 84, 16, center_x + 84, 65,
                               fill="#133b4b", outline=ACCENT, width=2)
            canvas.create_text(center_x, 41, text=caller["name"][:23],
                               fill=TEXT, font=("Segoe UI", 10, "bold"))
            if not callees:
                canvas.create_text(center_x, 145, text="No se han detectado llamadas directas.", fill=MUTED)
                return
            span = width - 100
            gap = span / max(len(callees), 1)
            for i, (name, address) in enumerate(callees):
                x = 50 + (i + .5) * gap
                canvas.create_line(center_x, 65, x, 145, fill="#6c9fb5", width=2,
                                   arrow="last", arrowshape=(10, 12, 4))
                canvas.create_rectangle(x - min(72, gap * .4), 146,
                                        x + min(72, gap * .4), 201,
                                        fill="#192d3b", outline="#4ce0d2")
                canvas.create_text(x, 163, text=name[:max(6, int(gap // 8))],
                                   fill=TEXT, font=("Segoe UI", 9))
                canvas.create_text(x, 186, text=address[:16], fill=MUTED,
                                   font=("Consolas", 8))

        def save_call_dot(self):
            if not self.call_edges or self.report is None:
                return
            path = filedialog.asksaveasfilename(title="Guardar mapa de llamadas", defaultextension=".dot",
                   filetypes=[("Graphviz DOT", "*.dot")])
            if not path:
                return
            try:
                Path(path).write_text(build_dot(self.report, limit=5000), encoding="utf-8")
            except (OSError, ValueError) as exc:
                messagebox.showerror("Error al exportar mapa", str(exc))
                return
            self.status_var.set("Mapa DOT guardado en " + path)

        def open_function_explorer(self, initial_entry=None):
            function_explorer_gui.open_function_explorer(
                self.root, self.report, initial_entry=initial_entry
            )

        def open_function_from_list(self, _event=None):
            selected = self.functions.selection()
            if not selected:
                return
            values = self.functions.item(selected[0], "values")
            if len(values) >= 2:
                self.open_function_explorer(initial_entry=values[1])

        def open_function_from_call(self, _event=None):
            selected = self.call_tree.selection()
            if not selected:
                return
            try:
                edge = self.call_edges[int(selected[0])]
            except (ValueError, IndexError):
                return
            self.open_function_explorer(initial_entry=edge["callee"]["entry"])

        def save_report(self):
            if self.report is None:
                return
            path = filedialog.asksaveasfilename(title="Guardar informe", defaultextension=".json",
                   filetypes=[("Archivo JSON", "*.json")])
            if not path:
                return
            try:
                Path(path).write_text(json.dumps(self.report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            except OSError as exc:
                messagebox.showerror("Error al guardar", str(exc))
                return
            self.status_var.set("Informe guardado en " + path)

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        raise RuntimeError("No graphical desktop is available for Tkinter.") from exc
    ReverseLabApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
