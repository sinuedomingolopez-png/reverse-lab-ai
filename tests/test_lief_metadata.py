"""Contract tests; real-format validation lives in integration_tests."""
import types
import unittest
from unittest.mock import patch

from reverse_lab.integrations.lief_adapter import inspect_with_lief


class LiefMetadataTests(unittest.TestCase):
    def test_sections_symbols_headers_and_counts_are_bounded(self):
        binary = types.SimpleNamespace(
            entrypoint=0x401000, format="ELF", header=types.SimpleNamespace(machine_type="X86_64"),
            sections=[types.SimpleNamespace(name=".text", virtual_address=0x401000,
                                           size=16, offset=4096)],
            imported_functions=["puts"], exported_functions=["helper"],
            libraries=["libc.so"],
        )
        with patch.dict("sys.modules", {"lief": types.SimpleNamespace(parse=lambda _: binary)}):
            report = inspect_with_lief("synthetic.elf")
        self.assertEqual(report["sections"][0]["name"], ".text")
        self.assertEqual(report["imports"], ["puts"])
        self.assertEqual(report["exports"], ["helper"])
        self.assertEqual(report["libraries"], ["libc.so"])
        self.assertIn("machine_type", report["header"])
