import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.integrations.ghidra_adapter import analyze_with_ghidra


class GhidraAdapterTests(unittest.TestCase):
    def test_runs_headless_without_shell_and_deletes_project(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "test binary.exe"
            launcher = Path(directory) / "analyzeHeadless"
            target.write_bytes(b"MZ")
            launcher.write_text("placeholder")
            completed = subprocess.CompletedProcess([], 0, "ok", "")
            with patch("reverse_lab.integrations.ghidra_adapter.subprocess.run", return_value=completed) as run:
                report = analyze_with_ghidra(target, launcher)
            self.assertTrue(report["success"])
            args = run.call_args.args[0]
            self.assertEqual(args[3:5], ["-import", str(target.resolve())])
            self.assertIn("-deleteProject", args)
            self.assertNotIn("shell", run.call_args.kwargs)

    def test_rejects_invalid_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            launcher = Path(directory) / "launcher"
            target.touch()
            launcher.touch()
            with self.assertRaisesRegex(ValueError, "timeout"):
                analyze_with_ghidra(target, launcher, timeout=0)


if __name__ == "__main__":
    unittest.main()
