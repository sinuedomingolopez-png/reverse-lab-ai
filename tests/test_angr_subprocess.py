"""Real subprocess smoke test with a temporary fake angr API (no dependency install)."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.integrations.angr_adapter import inspect_with_angr


class AngrSubprocessTests(unittest.TestCase):
    def test_worker_can_return_valid_json_from_separate_interpreter(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "angr.py"
            fake.write_text('''
from types import SimpleNamespace
class Project:
    def __init__(self, filename, auto_load_libs):
        assert auto_load_libs is False
        self.analyses = SimpleNamespace(CFGFast=self.cfgfast)
    def cfgfast(self):
        functions = {0x401000: SimpleNamespace(name="entry", addr=0x401000)}
        graph = SimpleNamespace(nodes=lambda: [1, 2], edges=lambda: [(1, 2)])
        return SimpleNamespace(
            kb=SimpleNamespace(functions=functions),
            model=SimpleNamespace(graph=graph))
''', encoding="utf-8")
            target = Path(directory) / "sample with spaces.elf"
            target.write_bytes(bytes.fromhex("7f454c46") + bytes(20))
            pythonpath = directory + os.pathsep + os.environ.get("PYTHONPATH", "")
            with patch.dict(os.environ, {"PYTHONPATH": pythonpath}):
                result = inspect_with_angr(target, timeout=20, max_functions=2)
        self.assertEqual(result["backend"], "angr")
        self.assertEqual(result["function_count"], 1)
        self.assertEqual(result["functions"], [{"name": "entry", "entry": "0x401000"}])
        self.assertEqual(result["cfg_nodes"], 2)


if __name__ == "__main__":
    unittest.main()
