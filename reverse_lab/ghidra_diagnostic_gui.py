"""Tkinter Ghidra diagnostic window. All processing remains on the local machine."""
from __future__ import annotations

import queue
import threading

from .ghidra_probe import ghidra_selftest


def format_diagnostic(result: dict) -> str:
    """Spanish status text that distinguishes detection from a successful run."""
    labels = {
        "missing": "NO DISPONIBLE",
        "available": "DETECTADO, SIN ANALIZAR",
        "passed": "VALIDACIÓN CORRECTA",
        "failed": "AUTOPRUEBA FALLIDA",
    }
    lines = [
        "REVERSE LAB AI — GHIDRA DIAGNÓSTICO",
        "ESTADO: " + labels.get(result.get("status"), "DESCONOCIDO"),
        "LANZADOR: " + str(result.get("launcher") or "No localizado"),
        "",
    ]
    for name, passed in result.get("checks", {}).items():
        lines.append(("✓ " if passed else "✗ ") + str(name))
    if result.get("counts"):
        lines.append("\nEXPORTACIONES:")
        lines.extend(f"  {name}: {value}" for name, value in result["counts"].items())
    if result.get("warnings"):
        lines.append("\nADVERTENCIAS:")
        lines.extend("  - " + str(item) for item in result["warnings"])
    if result.get("error"):
        lines.append("\nERROR: " + str(result["error"]))
    lines.extend([
        "", "Esta prueba analiza solo un ejecutable sintético; no lo ejecuta.",
        "Un resultado correcto no garantiza la seguridad de otros ejecutables.",
    ])
    return "\n".join(lines)


class GhidraDiagnosticWindow:
    def __init__(self, parent, initial_launcher: str = ""):
        import tkinter as tk
        from tkinter import filedialog, scrolledtext, ttk

        self.messages: queue.Queue = queue.Queue()
        self.running = False
        self.window = tk.Toplevel(parent)
        self.window.title("REVERSE LAB AI | Autoprueba Ghidra")
        self.window.geometry("800x610")
        self.window.configure(bg="#0a101b")
        self.launcher = tk.StringVar(value=initial_launcher)
        self.state = tk.StringVar(value="Sin ejecutar. Selecciona Ghidra o utiliza GHIDRA_HOME.")
        panel = ttk.Frame(self.window, padding=18)
        panel.pack(fill="both", expand=True)
        ttk.Label(panel, text="DIAGNÓSTICO LOCAL DE GHIDRA",
                  font=("Segoe UI", 14, "bold")).pack(anchor="w", pady=(0, 12))
        ttk.Label(panel, text="Ruta de analyzeHeadless (vacía para detección automática)").pack(anchor="w")
        path_row = ttk.Frame(panel)
        path_row.pack(fill="x", pady=(6, 12))
        ttk.Entry(path_row, textvariable=self.launcher).pack(side="left", fill="x", expand=True)

        def browse():
            path = filedialog.askopenfilename(parent=self.window, title="Selecciona analyzeHeadless")
            if path:
                self.launcher.set(path)

        ttk.Button(path_row, text="Examinar…", command=browse).pack(side="left", padx=(10, 0))
        actions = ttk.Frame(panel)
        actions.pack(fill="x")
        self.detect_button = ttk.Button(actions, text="Solo detectar", command=lambda: self.start(True))
        self.detect_button.pack(side="left")
        self.run_button = ttk.Button(
            actions, text="Ejecutar autoprueba completa", command=lambda: self.start(False)
        )
        self.run_button.pack(side="left", padx=8)
        self.progress = ttk.Progressbar(actions, mode="indeterminate", length=155)
        self.progress.pack(side="right")
        ttk.Label(panel, textvariable=self.state).pack(anchor="w", pady=(10, 8))
        self.details = scrolledtext.ScrolledText(
            panel, bg="#1e2c40", fg="#eef6ff", insertbackground="#eef6ff",
            wrap="word", font=("Consolas", 10), padx=14, pady=14,
        )
        self.details.pack(fill="both", expand=True)
        self.details.insert("1.0", "La comprobación utiliza una muestra ELF sintética y no instala software.")
        self.details.configure(state="disabled")

    def start(self, check_only: bool):
        if self.running or not self.window.winfo_exists():
            return
        self.running = True
        self.detect_button.configure(state="disabled")
        self.run_button.configure(state="disabled")
        self.progress.start(12)
        self.state.set("Comprobando instalación local…" if check_only else
                       "Analizando muestra sintética con Ghidra…")
        launcher = self.launcher.get().strip() or None

        def worker():
            try:
                report = ghidra_selftest(launcher=launcher, timeout=360, check_only=check_only)
            except Exception as exc:
                report = {"status": "failed", "launcher": launcher, "checks": {},
                          "counts": {}, "warnings": [],
                          "error": f"{type(exc).__name__}: {exc}"}
            self.messages.put(report)

        threading.Thread(target=worker, daemon=True).start()
        self.window.after(120, self.poll)

    def poll(self):
        if not self.window.winfo_exists():
            return
        try:
            result = self.messages.get_nowait()
        except queue.Empty:
            self.window.after(120, self.poll)
            return
        self.running = False
        self.progress.stop()
        self.detect_button.configure(state="normal")
        self.run_button.configure(state="normal")
        summary = format_diagnostic(result)
        self.state.set(summary.splitlines()[1])
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", summary)
        self.details.configure(state="disabled")


def open_ghidra_diagnostic(parent, launcher: str | None = None) -> GhidraDiagnosticWindow:
    return GhidraDiagnosticWindow(parent, initial_launcher=launcher or "")
