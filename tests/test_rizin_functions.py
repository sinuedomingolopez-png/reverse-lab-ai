import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.integrations.rizin_adapter import inspect_functions_with_rizin


class RizinFunctionsTests(unittest.TestCase):
    def test_fixed_static_commands_and_function_normalization(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.bin"
            target.write_bytes(b"synthetic")
            output = json.dumps([{"name": "helper", "offset": 4198410}])
            with patch("reverse_lab.integrations.rizin_adapter.subprocess.run",
                       return_value=subprocess.CompletedProcess([], 0, output, "")) as run:
                result = inspect_functions_with_rizin(target)
            self.assertEqual(result["functions"][0]["entry"], "0x40100a")
            self.assertEqual(run.call_args.args[0][1:5], ["-2", "-q", "-c", "aaa;aflj"])
            self.assertFalse(run.call_args.kwargs["shell"])
