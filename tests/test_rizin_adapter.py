import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.integrations.rizin_adapter import inspect_with_rizin


class RizinAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.target = Path(self.temp.name) / "program with spaces.bin"
        self.target.write_bytes(b"MZ" + bytes(128))

    def test_reads_json_without_shell_or_debug_execution(self):
        output = json.dumps({"bin": {"arch": "x86", "bits": 64}})
        with patch("reverse_lab.integrations.rizin_adapter.subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, "")) as run:
            result = inspect_with_rizin(self.target, executable="rz-bin")
        self.assertEqual(result["metadata"]["bin"]["bits"], 64)
        args = run.call_args.args[0]
        self.assertEqual(args, ["rz-bin", "-Ij", str(self.target.resolve())])
        self.assertFalse(run.call_args.kwargs.get("shell", False))

    def test_raises_for_invalid_json(self):
        with patch("reverse_lab.integrations.rizin_adapter.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "invalid", "")):
            with self.assertRaisesRegex(RuntimeError, "JSON"):
                inspect_with_rizin(self.target)

    def test_raises_when_executable_missing(self):
        with patch("reverse_lab.integrations.rizin_adapter.subprocess.run", side_effect=FileNotFoundError):
            with self.assertRaisesRegex(RuntimeError, "rz-bin"):
                inspect_with_rizin(self.target)

    def test_raises_for_nonzero_exit(self):
        with patch("reverse_lab.integrations.rizin_adapter.subprocess.run", return_value=subprocess.CompletedProcess([], 2, "", "bad")):
            with self.assertRaisesRegex(RuntimeError, "failed"):
                inspect_with_rizin(self.target)

    def test_rejects_bad_timeout(self):
        with self.assertRaises(ValueError):
            inspect_with_rizin(self.target, timeout=0)

    def test_rejects_directory(self):
        with self.assertRaises(ValueError):
            inspect_with_rizin(Path(self.temp.name))
