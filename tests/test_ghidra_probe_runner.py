"""Exercise the real Ghidra adapter subprocess with a disposable fake headless launcher.

This does not use a Ghidra installation and cannot validate Ghidra's Java API.
"""
import os
import tempfile
import unittest
from pathlib import Path

from reverse_lab.ghidra_probe import ghidra_selftest


@unittest.skipIf(os.name == "nt", "POSIX executable shebang fixture")
class GhidraSelfTestRunnerTests(unittest.TestCase):
    def test_inert_elf_and_all_exports_through_external_process(self):
        with tempfile.TemporaryDirectory(prefix="reverse-lab-smoke-") as directory:
            runner = Path(directory) / "analyzeHeadless"
            runner.write_text('''#!/usr/bin/env python3
import json, sys
from pathlib import Path
args = sys.argv[1:]
assert '-import' in args
sample = Path(args[args.index('-import')+1])
assert sample.read_bytes().startswith(b'\\x7fELF')
assert '-deleteProject' in args
for i, arg in enumerate(args):
    if arg != '-postScript':
        continue
    name = args[i+1]
    output = Path(args[i+2])
    if name == 'ExportFunctions.java':
        value = [{'name':'entry','entry':'00401000'}]
    elif name == 'ExportPseudocode.java':
        value = [{'name':'entry','entry':'00401000','pseudocode':'return 0;',
                  'truncated':False}]
    elif name == 'ExportCallGraph.java':
        value = [{'caller':{'name':'entry','entry':'00401000'},
                  'callee':{'name':'helper','entry':'0040100a'}}]
    else:
        raise AssertionError('Unexpected script: ' + name)
    output.write_text(json.dumps(value), encoding='utf-8')
''', encoding="utf-8")
            runner.chmod(0o755)
            result = ghidra_selftest(launcher=runner, timeout=90)
        self.assertEqual(result["status"], "passed", result)
        self.assertEqual(result["counts"], {
            "functions": 1, "pseudocode": 1, "call_graph": 1,
        })


if __name__ == "__main__":
    unittest.main()
