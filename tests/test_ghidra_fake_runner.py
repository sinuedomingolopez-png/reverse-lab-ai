"""Execute a disposable fake Ghidra launcher; no real Ghidra dependency."""
import os
import tempfile
import unittest
from pathlib import Path

from reverse_lab.integrations.ghidra_adapter import analyze_with_ghidra


@unittest.skipIf(os.name == 'nt', 'POSIX fake launcher fixture')
class GhidraFakeRunnerTests(unittest.TestCase):
    def test_real_subprocess_fake_headless_writes_json(self):
        with tempfile.TemporaryDirectory(prefix='reverse lab smoke ') as temp:
            directory = Path(temp)
            runner = directory / 'analyzeHeadless'
            sample = directory / 'hello sample.bin'
            sample.write_bytes(b'MZ' + bytes(20))
            runner.write_text('''#!/usr/bin/env python3
import json,sys
from pathlib import Path
args=sys.argv[1:]
assert '-import' in args
assert '-deleteProject' in args
for n,value in enumerate(args):
    if value=='-postScript':
        name=args[n+1]
        output=Path(args[n+2])
        if name=='ExportFunctions.java':
            output.write_text(json.dumps([{'name':'main','entry':'0x00001000'}]))
        if name=='ExportPseudocode.java':
            output.write_text(json.dumps([{'name':'main','entry':'0x00001000',
              'pseudocode':'int main(void) { return 0; }','truncated':False}]))
''')
            runner.chmod(0o755)
            result = analyze_with_ghidra(
                sample, runner, export_functions=True, export_pseudocode=True
            )
            self.assertTrue(result['success'], result)
            self.assertEqual(result['function_count'], 1)
            self.assertEqual(result['pseudocode_count'], 1)
            self.assertIn('return 0', result['pseudocode'][0]['pseudocode'])


if __name__ == '__main__':
    unittest.main()
