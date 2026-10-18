"""Real Tkinter window smoke test for source and frozen Windows builds.

Creates the desktop, checks visible controls, and destroys it without opening
any user files, launching analysis engines, or entering the event loop.
"""
from __future__ import annotations


_REQUIRED_CONTROLS = (
    "Analizar archivo",
    "Historial local",
    "Guardar en historial",
    "Autoprueba Ghidra",
)


def _start_and_collect() -> dict:
    import tkinter as tk
    from unittest.mock import patch
    from . import gui

    def descendants(widget):
        for child in widget.winfo_children():
            yield child
            yield from descendants(child)

    # The GUI should construct and return without waiting in the event loop.
    # Only this temporary process is affected; no installed GUI code is changed.
    with patch.object(tk.Tk, "mainloop", lambda self: None):
        gui.main()
    root = tk._default_root
    if root is None:
        return {"window_created": False, "controls": [], "backend_angr": False,
                "window_title": ""}
    try:
        texts = set()
        backend_angr = False
        for widget in descendants(root):
            try:
                label = widget.cget("text")
            except (tk.TclError, AttributeError):
                label = None
            if label:
                texts.add(str(label))
            if widget.winfo_class() == "TCombobox":
                try:
                    backend_angr = backend_angr or "angr" in widget.cget("values")
                except (tk.TclError, AttributeError):
                    pass
        return {
            "window_created": bool(root.winfo_exists()),
            "window_title": root.title(),
            "controls": sorted(texts),
            "backend_angr": backend_angr,
        }
    finally:
        root.destroy()


def run_desktop_smoke() -> dict:
    """Report actual Tkinter GUI creation, not only Python import success."""
    try:
        result = _start_and_collect()
    except Exception as exc:
        return {
            "status": "failed", "window_created": False,
            "missing_controls": list(_REQUIRED_CONTROLS),
            "backend_angr": False, "error": f"{type(exc).__name__}: {exc}"[:400],
        }
    controls = result.get("controls", ())
    missing = [name for name in _REQUIRED_CONTROLS if name not in controls]
    result["missing_controls"] = missing
    valid = (result.get("window_created") is True
             and "REVERSE LAB AI" in result.get("window_title", "")
             and result.get("backend_angr") is True and not missing)
    result["status"] = "passed" if valid else "failed"
    return result
