import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.workflow import analyze


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.target = Path(self.tempdir.name) / 'target file.bin'
        self.target.write_bytes(bytes.fromhex('7f454c46') + bytes(64))

    def test_basic_contains_hash_and_no_backend_execution(self):
        report = analyze(self.target)
        self.assertEqual(report['format'], 'ELF')
        self.assertEqual(len(report['sha256']), 64)
        self.assertNotIn('analysis', report)

    def test_rizin_merges_metadata_and_keeps_filename(self):
        with patch('reverse_lab.integrations.rizin_adapter.inspect_with_rizin', return_value={'backend':'rizin', 'metadata': {'bin': {'arch':'x86'}}}) as inspected:
            report = analyze(self.target, backend='rizin', rizin_executable='my-rz', timeout=12)
        self.assertEqual(report['analysis']['metadata']['bin']['arch'], 'x86')
        inspected.assert_called_once_with(self.target, executable='my-rz', timeout=12)
        self.assertEqual(report['filename'], 'target file.bin')

    def test_ghidra_exports_functions_when_requested(self):
        with patch('reverse_lab.integrations.ghidra_adapter.analyze_with_ghidra', return_value={'backend':'ghidra', 'functions': []}) as inspected:
            report = analyze(self.target, backend='ghidra', ghidra_headless='launcher', export_functions=True)
        self.assertEqual(report['analysis']['functions'], [])
        inspected.assert_called_once_with(self.target, 'launcher', timeout=180, export_functions=True)

    def test_unknown_backend_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'backend'):
            analyze(self.target, backend='unknown')

    def test_missing_ghidra_launcher_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'ghidra_headless'):
            analyze(self.target, backend='ghidra')

    def test_path_must_be_a_file(self):
        with self.assertRaises((IsADirectoryError, ValueError)):
            analyze(self.tempdir.name)

    def test_timeout_bounds(self):
        with self.assertRaisesRegex(ValueError, 'timeout'):
            analyze(self.target, timeout=0)


if __name__ == '__main__':
    unittest.main()
