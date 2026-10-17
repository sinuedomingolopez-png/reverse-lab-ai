"""Local report-comparison and interpretation dialogs for the desktop UI."""
from __future__ import annotations

import json
from .reports import compare_reports, explain_comparison, explain_report, load_report


def render_comparison_text(result: dict) -> str:
    return (explain_comparison(result) + "\n\n" +
            "DATOS DEL INFORME (JSON)\n" + json.dumps(result, indent=2, ensure_ascii=False))


def _text_window(parent, title: str, content: str):
    import tkinter as tk
    from tkinter import filedialog, scrolledtext, messagebox
    window = tk.Toplevel(parent)
    window.title("REVERSE LAB AI  |  " + title)
    window.geometry("800x650")
    window.configure(bg="#0a101b")
    text = scrolledtext.ScrolledText(
        window, bg="#1e2c40", fg="#eef6ff", insertbackground="#eef6ff",
        font=("Consolas", 10), wrap="word", padx=15, pady=15,
    )
    text.pack(fill="both", expand=True, padx=14, pady=(14, 8))
    text.insert("1.0", content)
    text.configure(state="disabled")

    def save():
        filename = filedialog.asksaveasfilename(parent=window, title="Guardar texto", defaultextension=".txt")
        if filename:
            try:
                from pathlib import Path
                Path(filename).write_text(content + "\n", encoding="utf-8")
            except OSError as exc:
                messagebox.showerror("Error al guardar", str(exc), parent=window)

    tk.Button(window, text="Guardar texto", command=save, bg="#4ce0d2", fg="#0a101b").pack(pady=(0, 12))
    return window


def compare_saved_reports(parent) -> None:
    from tkinter import filedialog, messagebox
    first = filedialog.askopenfilename(parent=parent, title="Selecciona el primer informe JSON",
                                       filetypes=[("Informes JSON","*.json")])
    if not first:
        return
    second = filedialog.askopenfilename(parent=parent, title="Selecciona el segundo informe JSON",
                                        filetypes=[("Informes JSON","*.json")])
    if not second:
        return
    try:
        comparison = compare_reports(load_report(first), load_report(second))
    except (ValueError, OSError) as exc:
        messagebox.showerror("No se pudieron comparar los informes", str(exc), parent=parent)
        return
    _text_window(parent, "Comparar informes", render_comparison_text(comparison))


def explain_current_report(parent, report: dict | None) -> None:
    import tkinter as tk
    from tkinter import messagebox
    if report is None:
        messagebox.showinfo("Informe", "Analiza un archivo antes de pedir una explicación.", parent=parent)
        return
    try:
        content = explain_report(report)
    except ValueError as exc:
        messagebox.showerror("Informe inválido", str(exc), parent=parent)
        return
    window = _text_window(parent, "Resumen técnico sin IA", content)
    tk.Button(window, text="Explicar mediante IA local (Ollama)",
              command=lambda: explain_with_local_ai(parent, report),
              bg="#29394f", fg="#eef6ff").pack(pady=(0, 12))


def explain_with_local_ai(parent, report: dict) -> None:
    """Only contacts the local model after deliberate confirmation."""
    import queue
    import threading
    from tkinter import messagebox
    if not messagebox.askyesno(
        "IA local", "¿Consultar Ollama en este ordenador? Solo se compartirán "
        "metadatos resumidos con el modelo local qwen2.5:3b; no se enviará el binario.",
        parent=parent,
    ):
        return
    messages: queue.Queue = queue.Queue()

    def worker():
        try:
            from .ollama_adapter import explain_with_ollama
            messages.put((True, explain_with_ollama(report)))
        except Exception as exc:
            messages.put((False, str(exc)))

    def poll():
        try:
            success, response = messages.get_nowait()
        except queue.Empty:
            parent.after(200, poll)
            return
        if success:
            _text_window(parent, "Explicación con Ollama local", response)
        else:
            messagebox.showerror("Ollama local", response, parent=parent)

    threading.Thread(target=worker, daemon=True).start()
    parent.after(200, poll)
