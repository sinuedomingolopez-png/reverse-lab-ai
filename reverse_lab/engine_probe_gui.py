"""Local desktop smoke checks for optional LIEF and angr installations.

The user must explicitly click Run; no local files are uploaded or executed.
"""
from __future__ import annotations

import queue
import threading

from .engine_probe import probe_engine


def format_engine_probe(result: dict) -> str:
    """Human-readable output using only validated, non-sensitive status keys."""
    engine = result.get("engine")
    label = {"lief": "LIEF", "angr": "angr"}.get(engine, "Motor desconocido")
    status = {
        "passed": "VALIDACIÓN CORRECTA",
        "missing": "NO INSTALADO",
        "failed": "FALLÓ LA AUTOPRUEBA",
    }.get(result.get("status"), "ESTADO DESCONOCIDO")
    lines = ["REVERSE LAB AI — PRUEBA LOCAL", f"MOTOR: {label}",
             f"ESTADO: {status}", "",
             "Se usa exclusivamente un ELF sintético generado por el laboratorio."]
    known_checks = ("dependency_installed", "synthetic_elf",
                    "elf_recognized", "backend_matches", "binary_recognized",
                    "expected_entrypoint", "static_cfg", "functions_discovered",
                    "cfg_nodes_discovered", "cfg_edges_valid", "functions_returned")
    checks = result.get("checks", {})
    if isinstance(checks, dict):
        lines.append("")
        lines.append("COMPROBACIONES:")
        for name in known_checks:
            value = checks.get(name)
            if type(value) is bool:
                lines.append(("  OK   " if value else "  ERROR ") + name)
    metrics = result.get("metrics", {})
    if isinstance(metrics, dict):
        allowed = ("entrypoint", "function_count", "cfg_nodes", "cfg_edges")
        lines.append("")
        lines.append("RESULTADOS:")
        for name in allowed:
            value = metrics.get(name)
            if type(value) is int and 0 <= value < 1_000_000:
                lines.append(f"  {name}: {value}")
            elif name == "entrypoint" and isinstance(value, str) and value.startswith("0x"):
                lines.append(f"  {name}: {value[:20]}")
    lines.extend(["", "La prueba no ejecuta el archivo sintético.",
                  "Un resultado correcto no garantiza seguridad con binarios desconocidos.",
                  "LIEF y angr son instalaciones opcionales; no vienen en el ZIP portable."])
    return "\n".join(lines)


class EngineProbeDialog:
    def __init__(self, parent):
        import tkinter as tk
        from tkinter import scrolledtext, ttk

        self.queue: queue.Queue = queue.Queue()
        self.running = False
        self.window = tk.Toplevel(parent)
        self.window.title("REVERSE LAB AI | Probar LIEF y angr")
        self.window.geometry("770x550")
        self.window.minsize(580, 380)
        self.engine = tk.StringVar(value="lief")
        self.status = tk.StringVar(value="Selecciona un motor y pulsa Probar motor real.")
        panel = ttk.Frame(self.window, padding=18)
        panel.pack(fill="both", expand=True)
        ttk.Label(panel, text="AUTOPRUEBAS DE MOTORES REALES",
                  font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(panel, text="No uses archivos propios: la muestra se genera automáticamente.",
                  wraplength=670).pack(anchor="w", pady=(8, 14))
        buttons = ttk.Frame(panel)
        buttons.pack(fill="x")
        self.engine_combo = ttk.Combobox(buttons, values=("lief", "angr"),
                                         textvariable=self.engine,
                                         state="readonly", width=12)
        self.engine_combo.pack(side="left")
        self.start_button = ttk.Button(buttons, text="Probar motor real",
                                       command=self.start)
        self.start_button.pack(side="left", padx=10)
        self.progress = ttk.Progressbar(buttons, mode="indeterminate", length=150)
        self.progress.pack(side="right")
        ttk.Label(panel, textvariable=self.status).pack(anchor="w", pady=(12, 10))
        self.details = scrolledtext.ScrolledText(
            panel, wrap="word", font=("Consolas", 10), bg="#1e2c40",
            fg="#eef6ff", padx=12, pady=12, relief="flat")
        self.details.pack(fill="both", expand=True)
        self._set_text("Sin ejecutar. La comprobación solamente usa un ELF de ejemplo.")

    def _set_text(self, text: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def start(self) -> None:
        if self.running or not self.window.winfo_exists():
            return
        engine = self.engine.get()
        if engine not in ("lief", "angr"):
            return
        self.running = True
        self.start_button.configure(state="disabled")
        self.engine_combo.configure(state="disabled")
        self.progress.start(12)
        self.status.set("Probando " + engine + " sobre un ELF sintético…")

        def worker():
            try:
                report = probe_engine(engine, timeout=120)
            except Exception:
                report = {"engine": engine, "status": "failed", "checks": {}, "metrics": {}}
            self.queue.put(report)

        threading.Thread(target=worker, daemon=True).start()
        self.window.after(120, self.poll)

    def poll(self) -> None:
        if not self.window.winfo_exists():
            return
        try:
            report = self.queue.get_nowait()
        except queue.Empty:
            self.window.after(120, self.poll)
            return
        self.running = False
        self.start_button.configure(state="normal")
        self.engine_combo.configure(state="readonly")
        self.progress.stop()
        self.status.set("Resultado de " + report["engine"] + ": " + report["status"])
        self._set_text(format_engine_probe(report))


def open_engine_probe(parent):
    return EngineProbeDialog(parent)
