"""Open the actual desktop under the CI virtual display; no external tools run."""
import tkinter as tk
import unittest
from unittest.mock import patch

from reverse_lab import gui


def walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from walk(child)


class AngrCutterDesktopSmokeTests(unittest.TestCase):
    def test_main_window_exposes_angr_and_cutter_without_launching_anything(self):
        with patch.object(tk.Tk, "mainloop", lambda self: None):
            gui.main()
        root = tk._default_root
        self.assertIsNotNone(root)
        try:
            widgets = list(walk(root))
            labels = []
            options = []
            for widget in widgets:
                try:
                    labels.append(widget.cget("text"))
                except tk.TclError:
                    pass
                if widget.winfo_class() == "TCombobox":
                    options.extend(widget.cget("values"))
            self.assertIn("Abrir archivo en Cutter", labels)
            self.assertIn("angr", options)
            self.assertIn("Autoprueba Ghidra", labels)
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
