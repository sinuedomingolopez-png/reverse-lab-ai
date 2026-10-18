"""Integration test with a disposable executable simulating Ghidra headless."""
import os
import tempfile
import unittest
from pathlib import Path

from reverse_lab.integrations.ghidra_adapter import analyze_with_ghidra


@unittest.skipIf(os.name == 'nt', 'Executable Python shebang fixture runs on POSIX')
class CallGraphRunnerTests(unittest.TestCase):
    def test_executes_fake_headless_and_reads_edges(self):
        with tempfile.TemporaryDirectory(prefix='reverse lab calls ') as directory:
            folder = Path(directory)
            sample = folder / 'sample 01.bin'
            runner = folder / 'analyzeHeadless'
            sample.write_bytes(b'MZ' + bytes(20))
            runner.write_text('''#!/usr/bin/env python3
import json,sys
from pathlib import Path
args=sys.argv[1:]
assert '-import' in args
assert '-deleteProject' in args
for i,argument in enumerate(args):
    if argument=='-postScript' and args[i+1]=='ExportCallGraph.java':
        Path(args[i+2]).write_text(json.dumps([
            {'caller':{'name':'main','entry':'0x400'},
             'callee':{'name':'helper','entry':'0x500'}}]))
''')
            runner.chmod(0o755)
            report = analyze_with_ghidra(sample, runner, export_call_graph=True)
        self.assertTrue(report['success'], report)
        self.assertEqual(report['call_graph_count'], 1)
        self.assertEqual(report['call_graph'][0]['callee']['entry'], '0x500')


if __name__ == '__main__':
    unittest.main()
