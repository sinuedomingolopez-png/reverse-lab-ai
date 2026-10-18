import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.integrations.ghidra_adapter import analyze_with_ghidra


class PseudocodeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.binary = Path(self.temp.name) / 'test binary.exe'
        self.launcher = Path(self.temp.name) / 'analyzeHeadless'
        self.binary.write_bytes(b'MZ' + bytes(15))
        self.launcher.write_text('# fake runner')

    def test_explicit_pseudocode_export_and_limits(self):
        def fake_run(args, **kwargs):
            index = args.index('-postScript')
            self.assertEqual(args[index + 1], 'ExportPseudocode.java')
            self.assertEqual(args[index + 3:index + 6], ['5', '512', '7'])
            self.assertIn('-analysisTimeoutPerFile', args)
            Path(args[index + 2]).write_text(json.dumps([
                {'name': 'main', 'entry': '00401000',
                 'pseudocode': 'int main(void) { return 0; }', 'truncated': False}
            ]))
            return subprocess.CompletedProcess(args, 0, 'ok', '')
        with patch('reverse_lab.integrations.ghidra_adapter.subprocess.run', side_effect=fake_run):
            report = analyze_with_ghidra(self.binary, self.launcher, export_pseudocode=True,
                                         pseudocode_max_functions=5,
                                         pseudocode_max_chars=512, pseudocode_timeout=7)
        self.assertTrue(report['success'])
        self.assertEqual(report['pseudocode_count'], 1)
        self.assertEqual(report['pseudocode'][0]['name'], 'main')

    def test_missing_export_rejected_even_if_exit_code_zero(self):
        with patch('reverse_lab.integrations.ghidra_adapter.subprocess.run',
                   return_value=subprocess.CompletedProcess([], 0, '', '')):
            result = analyze_with_ghidra(self.binary, self.launcher, export_pseudocode=True)
        self.assertFalse(result['success'])
        self.assertIn('error', result)

    def test_invalid_schema_rejected(self):
        def fake_run(args, **kwargs):
            output = Path(args[args.index('ExportPseudocode.java') + 1])
            output.write_text('[{"name":"main","entry":"0x1","pseudocode":5}]')
            return subprocess.CompletedProcess(args, 0, '', '')
        with patch('reverse_lab.integrations.ghidra_adapter.subprocess.run', side_effect=fake_run):
            result = analyze_with_ghidra(self.binary, self.launcher, export_pseudocode=True)
        self.assertFalse(result['success'])

    def test_limits_and_requires_explicit_optin(self):
        with self.assertRaises(ValueError):
            analyze_with_ghidra(self.binary, self.launcher, export_pseudocode=True,
                                pseudocode_max_functions=0)
        with self.assertRaises(ValueError):
            analyze_with_ghidra(self.binary, self.launcher, export_pseudocode=True,
                                pseudocode_max_chars=200000)
        with patch('reverse_lab.integrations.ghidra_adapter.subprocess.run',
                   return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
            analyze_with_ghidra(self.binary, self.launcher)
        self.assertNotIn('ExportPseudocode.java', run.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
