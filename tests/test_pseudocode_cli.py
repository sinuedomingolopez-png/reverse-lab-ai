import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.workflow import analyze
from reverse_lab.cli import main


class PseudocodeCLI(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / 'program.exe'
        self.path.write_bytes(b'MZ' + bytes(20))

    def test_workflow_propagates_opt_in(self):
        with patch('reverse_lab.integrations.ghidra_adapter.analyze_with_ghidra',
                   return_value={'success': True}) as ghidra:
            report = analyze(self.path, backend='ghidra', ghidra_headless='fake',
                             export_pseudocode=True)
        self.assertTrue(report['analysis']['success'])
        self.assertTrue(ghidra.call_args.kwargs['export_pseudocode'])

    def test_cli_ghidra_pseudocode_json(self):
        with patch('reverse_lab.integrations.ghidra_adapter.analyze_with_ghidra',
                   return_value={'backend': 'ghidra', 'success': True, 'pseudocode': []}) as ghidra:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                main([str(self.path), '--backend', 'ghidra',
                      '--ghidra-headless', 'fake', '--export-pseudocode'])
        self.assertEqual(json.loads(output.getvalue())['analysis']['pseudocode'], [])
        self.assertTrue(ghidra.call_args.kwargs['export_pseudocode'])

    def test_disallow_pseudocode_on_basic_backend(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                main([str(self.path), '--export-pseudocode'])
        self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
