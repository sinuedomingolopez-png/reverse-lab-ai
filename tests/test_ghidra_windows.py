import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.integrations.ghidra_adapter import analyze_with_ghidra


class WindowsBatchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.target = self.folder / 'file with spaces.exe'
        self.target.write_bytes(b'MZ')
        self.launcher = self.folder / 'analyzeHeadless.bat'
        self.launcher.write_text('@echo off')

    def test_windows_batch_uses_shell_quoting_and_spaces(self):
        with patch('reverse_lab.integrations.ghidra_adapter.sys.platform', 'win32'):
            with patch('reverse_lab.integrations.ghidra_adapter.subprocess.run',
                       return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
                report = analyze_with_ghidra(self.target, self.launcher)
        self.assertTrue(report['success'])
        self.assertTrue(run.call_args.kwargs['shell'])
        self.assertEqual(run.call_args.args[0][4], str(self.target))

    def test_windows_batch_rejects_shell_metacharacters(self):
        target = self.folder / 'untrusted & calc.exe'
        target.write_bytes(b'MZ')
        with patch('reverse_lab.integrations.ghidra_adapter.sys.platform', 'win32'):
            with patch('reverse_lab.integrations.ghidra_adapter.subprocess.run') as run:
                with self.assertRaisesRegex(ValueError, 'unsafe'):
                    analyze_with_ghidra(target, self.launcher)
                run.assert_not_called()

    def test_posix_launch_remains_shell_free(self):
        with patch('reverse_lab.integrations.ghidra_adapter.sys.platform', 'linux'):
            with patch('reverse_lab.integrations.ghidra_adapter.subprocess.run',
                       return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
                analyze_with_ghidra(self.target, self.launcher)
        self.assertNotIn('shell', run.call_args.kwargs)


if __name__ == '__main__':
    unittest.main()
