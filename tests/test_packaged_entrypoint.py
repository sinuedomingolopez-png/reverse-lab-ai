"""Reproduce PyInstaller entrypoint semantics (__main__, no package context).

PyInstaller runs reverse_lab/portable.py as the script entrypoint. Relative
imports in that file may fail even though package-level unittest mocks pass.
"""
import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "reverse_lab" / "portable.py"


class PackagedEntrypointTests(unittest.TestCase):
    def test_diagnostics_work_when_portable_is_run_as_a_standalone_script(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "support.json"
            process = subprocess.run(
                [sys.executable, str(SCRIPT), "--diagnostics-output", str(output)],
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(process.returncode, 0, process.stderr[-700:])
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["schema"], "reverse-lab-support-v1")

    def test_gui_smoke_imports_work_with_main_context_without_display(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "gui.json"
            fake_result = {
                "status": "passed", "window_created": True,
                "backend_angr": True, "controls": [],
            }
            with patch("reverse_lab.gui_smoke.run_desktop_smoke",
                       return_value=fake_result):
                with patch.object(sys, "argv", [str(SCRIPT),
                                               "--gui-smoke-output", str(output)]):
                    runpy.run_path(str(SCRIPT), run_name="__main__")
            self.assertEqual(json.loads(output.read_text())["status"], "passed")


if __name__ == "__main__":
    unittest.main()
