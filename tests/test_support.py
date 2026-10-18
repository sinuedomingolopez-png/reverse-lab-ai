"""Support diagnostics must not leak private paths, samples or environment values."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.support import collect_diagnostics, write_diagnostics
from reverse_lab.portable import main as portable_main


class SupportDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.tools = {
            "tools": {
                "ghidra": {"available": True, "path": r"C:\Users\PRIVATE_NAME\Ghidra", "hint": "token=SECRET"},
                "angr": {"available": False, "install": "pip install angr"},
                "rizin": {"available": True, "path": "/home/PRIVATE_NAME/rz-bin"},
                "cutter": {"available": False, "path": None},
                "lief": {"available": False, "install": "pip install lief"},
            },
        }
        self.bundle = {
            "status": "ready", "frozen": True,
            "ghidra_script_count": 3, "missing_scripts": [],
            "message": "anything -- token=SECRET",
        }

    def test_diagnostics_are_safe_allowlisted_public_metadata(self):
        with patch("reverse_lab.support.sys.frozen", True, create=True):
            report = collect_diagnostics(environment=self.tools, bundle_status=self.bundle)
        data = json.dumps(report)
        self.assertEqual(report["schema"], "reverse-lab-support-v1")
        self.assertTrue(report["portable"])
        self.assertEqual(report["tools"]["ghidra"], "detected")
        self.assertEqual(report["tools"]["angr"], "missing")
        self.assertEqual(report["bundle"]["ghidra_script_count"], 3)
        for secret in ("PRIVATE_NAME", "SECRET", "token=", "C:\\", "/home/", "path"):
            self.assertNotIn(secret, data)
        self.assertNotIn("filename", data)
        self.assertNotIn("sha256", data)

    def test_diagnostics_fail_closed_when_tool_detection_errors(self):
        with patch("reverse_lab.doctor.check_environment", side_effect=RuntimeError("PRIVATE_NAME has key SECRET")):
            result = collect_diagnostics(bundle_status=self.bundle)
        self.assertEqual(result["tools_status"], "error")
        self.assertNotIn("PRIVATE_NAME", json.dumps(result))
        self.assertNotIn("SECRET", json.dumps(result))

    def test_diagnostics_do_not_create_file_until_explicit_export(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "diagnostico.json"
            collect_diagnostics(environment=self.tools, bundle_status=self.bundle)
            self.assertFalse(output.exists())
            write_diagnostics(output, environment=self.tools, bundle_status=self.bundle)
            self.assertTrue(output.exists())
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["schema"],
                             "reverse-lab-support-v1")

    def test_portable_diagnostics_flag_does_not_open_gui(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "diagnostico.json"
            with patch("reverse_lab.gui.main") as gui:
                portable_main(["--diagnostics-output", str(output)])
                gui.assert_not_called()
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["schema"], "reverse-lab-support-v1")
            self.assertIn(result["bundle"]["status"], ("ready", "incomplete"))

    def test_diagnostics_flags_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("sys.stderr"):
                with self.assertRaises(SystemExit) as error:
                    portable_main(["--diagnostics-output", str(Path(directory) / "a.json"),
                                   "--self-test-output", str(Path(directory) / "b.json")])
            self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
