"""Desktop smoke-check contract for the PyInstaller Windows portable build."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab import portable
from reverse_lab.gui_smoke import run_desktop_smoke


class DesktopSmokeTests(unittest.TestCase):
    def test_smoke_collects_window_and_required_controls(self):
        class FakeRoot:
            def winfo_exists(self): return 1
            def title(self): return "REVERSE LAB AI  |  LOCAL ANALYSIS"
            def destroy(self): pass
        class FakeTk:
            _default_root = FakeRoot()
        class FakeGUI:
            @staticmethod
            def main(): pass
        with patch("reverse_lab.gui_smoke._start_and_collect", return_value={
            "window_created": True,
            "window_title": FakeRoot().title(),
            "controls": ["Analizar archivo", "Historial local",
                         "Guardar en historial", "Autoprueba Ghidra",
                         "Guardar diagnóstico"],
            "backend_angr": True,
        }):
            result = run_desktop_smoke()
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["backend_angr"])

    def test_missing_required_control_fails(self):
        with patch("reverse_lab.gui_smoke._start_and_collect", return_value={
            "window_created": True, "window_title": "REVERSE LAB AI",
            "controls": ["Analizar archivo"], "backend_angr": True,
        }):
            result = run_desktop_smoke()
        self.assertEqual(result["status"], "failed")
        self.assertIn("Historial local", result["missing_controls"])

    def test_smoke_errors_fail_closed(self):
        with patch("reverse_lab.gui_smoke._start_and_collect",
                   side_effect=RuntimeError("No display")):
            result = run_desktop_smoke()
        self.assertEqual(result["status"], "failed")
        self.assertIn("No display", result["error"])

    def test_portable_writes_gui_smoke_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "gui.json"
            with patch("reverse_lab.gui_smoke.run_desktop_smoke",
                       return_value={"status": "passed", "window_created": True}):
                portable.main(["--gui-smoke-output", str(output)])
            self.assertEqual(json.loads(output.read_text())["status"], "passed")

    def test_portable_gui_smoke_fails_on_missing_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "gui.json"
            with patch("reverse_lab.gui_smoke.run_desktop_smoke",
                       return_value={"status": "failed", "window_created": False}):
                with self.assertRaises(SystemExit) as raised:
                    portable.main(["--gui-smoke-output", str(output)])
            self.assertEqual(raised.exception.code, 3)
            self.assertEqual(json.loads(output.read_text())["status"], "failed")


if __name__ == "__main__":
    unittest.main()
