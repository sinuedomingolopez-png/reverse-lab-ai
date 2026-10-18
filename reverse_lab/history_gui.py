"""Local-only GUI for explicitly saved reports.

History is disabled by default: saving requires a click AND confirmation.
The stored JSON may contain secrets or recovered proprietary code.
"""
from __future__ import annotations

from .history import HistoryStore


def save_current_report(parent, report: dict | None) -> dict | None:
    from tkinter import messagebox
    if report is None:
        messagebox.showinfo("Historial local", "Primero analiza o abre un informe JSON.", parent=parent)
        return None
    if not messagebox.askyesno(
        "Guardar en historial local",
        "¿Guardar una copia COMPLETA del informe en este ordenador?\n\n"
        "Puede contener pseudocódigo, nombres y otros datos confidenciales. "
        "No se guarda nada automáticamente ni se envía a internet. "
        "Puedes eliminarla después desde Historial local.",
        parent=parent,
    ):
        return None
    try:
        saved = HistoryStore().save(report)
    except (OSError, ValueError) as exc:
        messagebox.showerror("No se pudo guardar", str(exc), parent=parent)
        return None
    messagebox.showinfo(
        "Guardado localmente",
        f"Informe guardado: {saved['filename']}\n"
        "Usa Historial local para abrirlo o eliminarlo.",
        parent=parent,
    )
    return saved


class HistoryDialog:
    def __init__(self, parent, on_open):
        import tkinter as tk
        from tkinter import ttk
        self.store = HistoryStore()
        self.on_open = on_open
        self.window = tk.Toplevel(parent)
        self.window.title("REVERSE LAB AI | Historial local")
        self.window.geometry("940x530")
        self.window.minsize(720, 420)
        self.window.configure(bg="#0a101b")
        frame = ttk.Frame(self.window, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(
            frame, text="HISTORIAL LOCAL DE INFORMES",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            frame,
            text="Solo informes guardados por ti. Nunca se guarda un análisis automáticamente.",
        ).pack(anchor="w", pady=(4, 12))

        columns = ("saved", "filename", "backend", "format")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for key, label, size in [
            ("saved", "FECHA UTC", 200),
            ("filename", "ARCHIVO", 300),
            ("backend", "MOTOR", 120),
            ("format", "FORMATO", 170),
        ]:
            self.tree.heading(key, text=label)
            self.tree.column(key, width=size, minwidth=80, stretch=True)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", lambda _event: self.open_selected())
        self.tree.bind("<Return>", lambda _event: self.open_selected())

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(12, 0))
        ttk.Button(buttons, text="Abrir informe", command=self.open_selected).pack(side="left")
        ttk.Button(buttons, text="Eliminar seleccionado", command=self.delete_selected).pack(side="left", padx=8)
        ttk.Button(buttons, text="Actualizar", command=self.refresh).pack(side="left")
        ttk.Button(buttons, text="Cerrar", command=self.window.destroy).pack(side="right")
        self.status = tk.StringVar()
        ttk.Label(frame, textvariable=self.status).pack(anchor="w", pady=(12, 0))
        self.refresh()

    def refresh(self):
        from tkinter import messagebox
        try:
            entries = self.store.list_entries()
        except (ValueError, OSError) as exc:
            messagebox.showerror("Historial", str(exc), parent=self.window)
            return
        self.tree.delete(*self.tree.get_children())
        for item in entries:
            self.tree.insert(
                "", "end", iid=item["id"],
                values=(item["saved_at"], item["filename"], item["backend"], item["format"]),
            )
        self.status.set(f"{len(entries)} informes en este ordenador · máximo {self.store.max_records}")

    def _selected_id(self) -> str | None:
        selected = self.tree.selection()
        return selected[0] if selected else None

    def open_selected(self):
        from tkinter import messagebox
        identifier = self._selected_id()
        if identifier is None:
            return
        try:
            report = self.store.load(identifier)
        except (ValueError, OSError) as exc:
            messagebox.showerror("Historial", str(exc), parent=self.window)
            self.refresh()
            return
        self.on_open(report)
        self.window.destroy()

    def delete_selected(self):
        from tkinter import messagebox
        identifier = self._selected_id()
        if identifier is None:
            return
        filename = self.tree.item(identifier, "values")[1]
        if not messagebox.askyesno(
            "Eliminar copia del historial",
            f"¿Eliminar definitivamente la copia local de {filename}?\n"
            "No elimina el archivo binario original ni otros informes.",
            parent=self.window,
        ):
            return
        try:
            self.store.delete(identifier)
        except (ValueError, OSError) as exc:
            messagebox.showerror("Historial", str(exc), parent=self.window)
            return
        self.refresh()


def open_history(parent, on_open) -> HistoryDialog:
    return HistoryDialog(parent, on_open)
