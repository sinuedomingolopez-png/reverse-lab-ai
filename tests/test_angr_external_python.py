import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.integrations.angr_adapter import worker_command


class ExternalPythonTests(unittest.TestCase):
    def test_source_application_can_use_separate_supported_angr_python(self):
        with tempfile.TemporaryDirectory() as directory:
            interpreter = Path(directory) / "python.exe"
            interpreter.touch()
            with patch.dict(os.environ, {"REVERSE_LAB_PYTHON": str(interpreter)}):
                command = worker_command("authorized.elf")
            self.assertEqual(Path(command[0]), interpreter.resolve())
            self.assertTrue(Path(command[1]).is_file())
            self.assertEqual(Path(command[1]).name, "angr_worker.py")
