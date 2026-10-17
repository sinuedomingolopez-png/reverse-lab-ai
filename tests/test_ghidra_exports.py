import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.integrations.ghidra_adapter import analyze_with_ghidra


class GhidraExportsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.target = Path(self.temp.name) / 'test.bin'
        self.launcher = Path(self.temp.name) / 'analyzeHeadless'
        self.target.write_bytes(b'MZ')
        self.launcher.touch()

    def test_extracts_function_list_via_post_script(self):
        def fake_run(command, **kwargs):
            index = command.index('-postScript')
            self.assertEqual(command[index + 1], 'ExportFunctions.java')
            output_path = Path(command[index + 2])
            output_path.write_text(json.dumps([
                {'name': 'main', 'entry': '401000'},
                {'name': 'init', 'entry': '401100'},
            ]))
            self.assertIn('-scriptPath', command)
            return subprocess.CompletedProcess(command, 0, 'ok', '')

        with patch('reverse_lab.integrations.ghidra_adapter.subprocess.run', side_effect=fake_run):
            report = analyze_with_ghidra(self.target, self.launcher, export_functions=True)
        self.assertTrue(report['success'])
        self.assertEqual(report['function_count'], 2)
        self.assertEqual(report['functions'][0]['name'], 'main')

    def test_failed_script_is_not_reported_as_success(self):
        with patch('reverse_lab.integrations.ghidra_adapter.subprocess.run', return_value=subprocess.CompletedProcess([], 0, '', '')):
            report = analyze_with_ghidra(self.target, self.launcher, export_functions=True)
        self.assertFalse(report['success'])
        self.assertIn('error', report)

    def test_no_script_if_export_disabled(self):
        with patch('reverse_lab.integrations.ghidra_adapter.subprocess.run', return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
            report = analyze_with_ghidra(self.target, self.launcher)
        self.assertTrue(report['success'])
        self.assertNotIn('-postScript', run.call_args.args[0])
        self.assertNotIn('functions', report)
