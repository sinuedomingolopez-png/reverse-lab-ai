"""Owner-only local permissions and explicit agent lifecycle controls."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from .authorizations import Authorizations
from .history import default_history_directory


class AgentPanel:
    def __init__(self, parent, selected_file=lambda: "", *, manifest=None):
        import tkinter as tk
        from tkinter import ttk
        self.selected_file = selected_file
        self.process = None
        self.control = None
        self.grants = Authorizations(manifest or default_history_directory().parent / "agent" / "grants.json")
        self.window = tk.Toplevel(parent)
        self.window.title("Reverse Lab AI · Permisos y agente MCP")
        self.window.geometry("850x490")
        self.window.minsize(720, 420)
        frame = ttk.Frame(self.window, padding=20)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Control local de acceso", font=("Segoe UI", 17, "bold")).pack(anchor="w")
        ttk.Label(frame, text="ChatGPT: comprueba la conexión desde el complemento de tu cuenta.\n"
                  "Solo se comparten los archivos autorizados por ID y hash. Los permisos caducan en una hora.",
                  wraplength=760).pack(anchor="w", pady=12)
        self.share_content = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Permitir compartir símbolos, referencias y pseudocódigo con el cliente MCP",
                        variable=self.share_content).pack(anchor="w", pady=8)
        controls = ttk.Frame(frame)
        controls.pack(fill="x")
        ttk.Button(controls, text="Autorizar archivo", command=self.authorize).pack(side="left")
        ttk.Button(controls, text="Revocar selección", command=self.revoke).pack(side="left", padx=8)
        ttk.Button(controls, text="Actualizar permisos", command=self.refresh).pack(side="left")
        self.files = ttk.Treeview(frame, columns=("id", "hash", "content"), show="headings", height=7)
        for column, label, width in (("id", "ID AUTORIZADO", 250), ("hash", "SHA-256", 330),
                                     ("content", "CONTENIDO", 100)):
            self.files.heading(column, text=label)
            self.files.column(column, width=width)
        self.files.pack(fill="both", expand=True, pady=16)
        lifecycle = ttk.Frame(frame)
        lifecycle.pack(fill="x")
        ttk.Button(lifecycle, text="Iniciar HTTP con configuración…", command=self.start).pack(side="left")
        ttk.Button(lifecycle, text="Detener HTTP del panel", command=self.stop).pack(side="left", padx=8)
        self.state = tk.StringVar(value="Agente local: sin iniciar desde este panel")
        ttk.Label(frame, textvariable=self.state, wraplength=760).pack(anchor="w", pady=8)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.refresh()
        self.window.after(500, self.poll)

    def refresh(self):
        from tkinter import messagebox
        self.files.delete(*self.files.get_children())
        try:
            for item in self.grants.list_files():
                self.files.insert("", "end", iid=item["id"],
                                  values=(item["id"], item["sha256"], "Sí" if item["content"] else "No"))
        except (OSError, ValueError):
            messagebox.showerror("Permisos MCP", "No se puede leer el manifiesto local.", parent=self.window)

    def authorize(self):
        from tkinter import filedialog, messagebox
        selected = self.selected_file()
        path = Path(selected) if selected else None
        if path is None or not path.is_file():
            selected = filedialog.askopenfilename(parent=self.window, title="Archivo autorizado para MCP")
            if not selected:
                return
            path = Path(selected)
        root = filedialog.askdirectory(parent=self.window, initialdir=path.parent,
                                       title="Directorio permitido para este archivo")
        if not root:
            return
        notice = ("¿Autorizar el análisis de este archivo durante una hora?\n\n"
                  "El cliente MCP podrá recibir su hash y metadatos. Si conectas ChatGPT, "
                  "esos resultados se enviarán a OpenAI. El binario no se sube.\n\n")
        if self.share_content.get():
            notice += "También autorizas compartir símbolos, referencias y pseudocódigo aproximado."
        if not messagebox.askyesno("Confirmar acceso MCP", notice, parent=self.window):
            return
        try:
            self.grants.grant(path, root=root, content=self.share_content.get())
        except (OSError, ValueError):
            messagebox.showerror("Permisos MCP", "Archivo fuera de la raíz, demasiado grande o no disponible.", parent=self.window)
        self.refresh()

    def revoke(self):
        for item_id in self.files.selection():
            self.grants.revoke(item_id)
        self.refresh()

    def start(self):
        from tkinter import filedialog, messagebox
        if self.process and self.process.poll() is None:
            return
        if getattr(sys, "frozen", False):
            messagebox.showinfo("Agente Python", "El portable utiliza un agente Python externo. "
                                "Consulta docs/MCP_CHATGPT.md del repositorio.", parent=self.window)
            return
        selected = filedialog.askopenfilename(parent=self.window, title="Configuración OAuth del agente",
                                              filetypes=[("Configuración JSON", "*.json")])
        if not selected:
            return
        try:
            path = Path(selected)
            if path.stat().st_size > 16384:
                raise ValueError
            config = json.loads(path.read_text(encoding="utf-8"))
            from .mcp_auth import LocalJWKVerifier
            LocalJWKVerifier(config["jwks"], issuer=config["issuer"],
                             resource=config["resource_url"], subject=config["owner_subject"])
            command = [sys.executable, "-m", "reverse_lab.agent", "--manifest", str(self.grants.manifest),
                       "serve", "--transport", "http", "--issuer", config["issuer"],
                       "--resource-url", config["resource_url"], "--jwks", config["jwks"],
                       "--owner-subject", config["owner_subject"], "--port", str(int(config.get("port", 8765)))]
            if self.control is not None:
                self.control.cleanup()
            self.control = tempfile.TemporaryDirectory(prefix="reverse-lab-control-")
            command += ["--stop-file", str(Path(self.control.name) / "stop")]
            self.process = subprocess.Popen(command, shell=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
            self.state.set("Agente local: iniciando proceso; OAuth y ChatGPT aún sin verificar")
        except (OSError, ValueError, KeyError, ImportError, TypeError):
            messagebox.showerror("Agente MCP", "Revisa el JSON OAuth y la instalación del extra MCP.", parent=self.window)

    def stop(self):
        if self.process and self.process.poll() is None:
            # TerminateProcess on Windows bypasses jobs.close and can strand
            # private snapshots. Ask uvicorn to exit and let finally clean them.
            if self.control is None:
                return False
            (Path(self.control.name) / "stop").write_text("stop", encoding="ascii")
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.state.set("El agente no ha terminado; conserva este panel abierto y revisa el proceso local.")
                return False
        self.process = None
        if self.control is not None:
            self.control.cleanup()
            self.control = None
        self.state.set("Agente local: detenido")
        return True

    def poll(self):
        if not self.window.winfo_exists():
            return
        if self.process is not None:
            self.state.set("Agente local: proceso activo; conexión ChatGPT sin verificar"
                           if self.process.poll() is None else "Agente local: proceso detenido o error de configuración")
        self.window.after(500, self.poll)

    def close(self):
        if self.stop():
            self.window.destroy()
