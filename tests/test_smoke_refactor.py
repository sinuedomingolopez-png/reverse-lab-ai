"""GUI smoke must inspect a deliberately created window, not monkeypatch mainloop."""
import sys
import types
import unittest
from unittest.mock import patch

from reverse_lab.gui_smoke import _start_and_collect


class FakeRoot:
    def __init__(self):
        self.destroyed = False
        self.children = [
            FakeWidget("TButton", "Analizar archivo"),
            FakeWidget("TButton", "Historial local"),
            FakeWidget("TButton", "Guardar en historial"),
            FakeWidget("TButton", "Autoprueba Ghidra"),
            FakeWidget("TButton", "Guardar diagnóstico"),
            FakeWidget("TButton", "Probar LIEF/angr"),
            FakeWidget("TCombobox", None),
        ]

    def winfo_children(self): return self.children
    def winfo_exists(self): return 1
    def title(self): return "REVERSE LAB AI | LOCAL ANALYSIS"
    def destroy(self): self.destroyed = True


class FakeWidget:
    def __init__(self, klass, value):
        self.klass, self.value = klass, value

    def winfo_children(self): return []
    def winfo_class(self): return self.klass
    def cget(self, key):
        if key == "text":
            return self.value
        if key == "values":
            return ("basic", "ghidra", "angr")
        raise KeyError(key)


class SmokeRefactorTests(unittest.TestCase):
    def test_smoke_calls_explicit_window_build_without_entering_mainloop(self):
        root = FakeRoot()
        fake_tk = types.SimpleNamespace(TclError=KeyError)
        with patch.dict(sys.modules, {"tkinter": fake_tk}):
            with patch("reverse_lab.gui.main", return_value=root) as gui:
                status = _start_and_collect()
        gui.assert_called_once_with(run_loop=False)
        self.assertTrue(root.destroyed)
        self.assertTrue(status["window_created"])
        self.assertIn("Historial local", status["controls"])
        self.assertTrue(status["backend_angr"])


if __name__ == "__main__":
    unittest.main()
