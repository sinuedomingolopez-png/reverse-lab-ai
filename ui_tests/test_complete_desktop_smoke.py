"""Standalone complete-desktop smoke check under a virtual display."""
import unittest
from reverse_lab.gui_smoke import run_desktop_smoke

class CompleteDesktopSmokeTests(unittest.TestCase):
    def test_opens_real_gui_with_history_controls(self):
        result = run_desktop_smoke()
        self.assertEqual(result["status"], "passed", result)
        self.assertIn("Guardar en historial", result["controls"])
        self.assertIn("Historial local", result["controls"])

if __name__ == "__main__":
    unittest.main()
