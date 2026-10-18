"""Real Tkinter diagnostic window smoke test; run in Xvfb on Linux."""
import time
import tkinter as tk
import unittest
from unittest.mock import patch

from reverse_lab.ghidra_diagnostic_gui import GhidraDiagnosticWindow


class GhidraDiagnosticWindowTests(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.addCleanup(self.root.destroy)

    def test_shows_results_from_background_worker(self):
        window = GhidraDiagnosticWindow(self.root)
        self.assertIn("Autoprueba Ghidra", window.window.title())
        report = {"status": "missing", "launcher": None,
                  "checks": {"ghidra_available": False},
                  "counts": {}, "warnings": [], "error": "No se encuentra Ghidra"}
        with patch("reverse_lab.ghidra_diagnostic_gui.ghidra_selftest", return_value=report):
            window.start(check_only=True)
            deadline = time.monotonic() + 4
            while window.running and time.monotonic() < deadline:
                self.root.update()
                time.sleep(0.03)
        self.assertFalse(window.running)
        self.assertIn("NO DISPONIBLE", window.details.get("1.0", "end"))
        self.assertEqual(str(window.run_button["state"]), "normal")
        self.root.update()


if __name__ == "__main__":
    unittest.main()
