import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.cli import main


class CliTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.target = Path(self.folder.name) / 'example.bin'
        self.target.write_bytes(bytes.fromhex('7f454c46') + bytes(20))

    def test_basic_report_remains_backward_compatible(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            main([str(self.target)])
        data = json.loads(output.getvalue())
        self.assertEqual(data['format'], 'ELF')
        self.assertNotIn('analysis', data)

    def test_rizin_backend_writes_combined_report(self):
        report_path = Path(self.folder.name) / 'report.json'
        with patch('reverse_lab.integrations.rizin_adapter.inspect_with_rizin', return_value={'backend': 'rizin', 'recognized': True}) as analyze:
            main([str(self.target), '--backend', 'rizin', '--output', str(report_path)])
        self.assertEqual(json.loads(report_path.read_text())['analysis']['backend'], 'rizin')
        analyze.assert_called_once()

    def test_ghidra_requires_launcher(self):
        with self.assertRaises(SystemExit) as caught:
            main([str(self.target), '--backend', 'ghidra'])
        self.assertEqual(caught.exception.code, 2)

    def test_ghidra_backend_passes_configured_launcher(self):
        with patch('reverse_lab.integrations.ghidra_adapter.analyze_with_ghidra', return_value={'backend': 'ghidra', 'success': True}) as analyze:
            with contextlib.redirect_stdout(io.StringIO()):
                main([str(self.target), '--backend', 'ghidra', '--ghidra-headless', 'any-launcher'])
        self.assertEqual(str(analyze.call_args.args[0]), str(self.target))
        self.assertEqual(analyze.call_args.args[1], 'any-launcher')

    def test_lief_backend_is_selectable(self):
        with patch('reverse_lab.integrations.lief_adapter.inspect_with_lief', return_value={'backend': 'lief'}) as analyze:
            with contextlib.redirect_stdout(io.StringIO()):
                main([str(self.target), '--backend', 'lief'])
        analyze.assert_called_once()
