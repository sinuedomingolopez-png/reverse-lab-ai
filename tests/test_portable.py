"""Portable build and runtime contracts, independent of PyInstaller installation."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab import portable
from reverse_lab.integrations import angr_adapter


class PortableEntrypointTests(unittest.TestCase):
    def test_status_fails_if_any_bundled_ghidra_script_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            script_dir = Path(directory) / "ghidra_scripts"
            script_dir.mkdir()
            (script_dir / "ExportFunctions.java").write_text("// stub")
            status = portable.collect_portable_status(package_dir=Path(directory))
        self.assertEqual(status["status"], "incomplete")
        self.assertIn("ExportCallGraph.java", status["missing_scripts"])

    def test_status_passes_if_all_three_scripts_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            script_dir = Path(directory) / "ghidra_scripts"
            script_dir.mkdir()
            for filename in ("ExportFunctions.java", "ExportPseudocode.java", "ExportCallGraph.java"):
                (script_dir / filename).write_text("// stub")
            status = portable.collect_portable_status(package_dir=Path(directory))
        self.assertEqual(status["status"], "ready")
        self.assertEqual(status["ghidra_script_count"], 3)

    def test_selftest_writes_json_without_starting_gui(self):
        with tempfile.TemporaryDirectory() as directory:
            outfile = Path(directory) / "smoke.json"
            with patch("reverse_lab.portable.collect_portable_status",
                       return_value={"status": "ready", "frozen": True, "ghidra_script_count": 3}):
                with patch("reverse_lab.gui.main") as gui:
                    portable.main(["--self-test-output", str(outfile)])
                gui.assert_not_called()
            self.assertEqual(json.loads(outfile.read_text(encoding="utf-8"))["status"], "ready")

    def test_incomplete_selftest_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            outfile = Path(directory) / "smoke.json"
            with patch("reverse_lab.portable.collect_portable_status",
                       return_value={"status": "incomplete", "missing_scripts": ["ExportFunctions.java"]}):
                with self.assertRaises(SystemExit) as raised:
                    portable.main(["--self-test-output", str(outfile)])
            self.assertEqual(raised.exception.code, 2)

    def test_normal_entry_starts_gui(self):
        with patch("reverse_lab.gui.main") as main:
            portable.main([])
        main.assert_called_once_with()


class FrozenAngrWorkerTests(unittest.TestCase):
    def setUp(self):
        self.target = Path("C:/test target.exe")

    def test_source_launch_preserves_python_module_workflow(self):
        with patch.object(sys, "frozen", False, create=True):
            command = angr_adapter.worker_command(self.target, max_functions=15)
        self.assertEqual(command[:3], [sys.executable, "-m", "reverse_lab.integrations.angr_worker"])
        self.assertEqual(command[-1], "15")

    def test_frozen_uses_external_python_and_embedded_worker_script(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = Path(directory) / "reverse_lab" / "integrations" / "angr_worker.py"
            worker.parent.mkdir(parents=True)
            worker.write_text("# worker", encoding="utf-8")
            external_python = Path(directory) / "python.exe"
            external_python.touch()
            with patch.object(sys, "frozen", True, create=True), \
                 patch.object(sys, "_MEIPASS", directory, create=True), \
                 patch.dict(os.environ, {"REVERSE_LAB_PYTHON": str(external_python)}):
                command = angr_adapter.worker_command(self.target, max_functions=100)
        self.assertEqual(command[0], str(external_python.resolve()))
        self.assertEqual(command[1], str(worker))
        self.assertEqual(command[-2:], ["--max-functions", "100"])
        self.assertNotIn("-m", command)

    def test_frozen_without_external_python_explains_what_to_install(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(sys, "frozen", True, create=True), \
                 patch.object(sys, "_MEIPASS", directory, create=True), \
                 patch.dict(os.environ, {"REVERSE_LAB_PYTHON": "/does/not/exist"}):
                with self.assertRaisesRegex(RuntimeError, "REVERSE_LAB_PYTHON"):
                    angr_adapter.worker_command(self.target, max_functions=1)

    def test_frozen_missing_worker_source_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            python = Path(directory) / "python.exe"
            python.touch()
            with patch.object(sys, "frozen", True, create=True), \
                 patch.object(sys, "_MEIPASS", directory, create=True), \
                 patch.dict(os.environ, {"REVERSE_LAB_PYTHON": str(python)}):
                with self.assertRaisesRegex(RuntimeError, "angr_worker.py"):
                    angr_adapter.worker_command(self.target, max_functions=2)


if __name__ == "__main__":
    unittest.main()
