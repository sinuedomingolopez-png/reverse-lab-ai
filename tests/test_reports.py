import json
import tempfile
import unittest
from pathlib import Path

from reverse_lab.reports import load_report, compare_reports, explain_report


def report(sha='a'*64, backend='ghidra', funcs=None, name='app.exe', size=120):
    analysis = {'backend': backend}
    if funcs is not None:
        analysis['functions'] = funcs
    return {'filename':name,'sha256':sha,'size_bytes':size,'format':'PE (possible)','analysis':analysis}


class ReportTests(unittest.TestCase):
    def test_load_validates_schema(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'result.json'
            p.write_text(json.dumps(report()),encoding='utf-8')
            self.assertEqual(load_report(p)['filename'],'app.exe')

    def test_rejects_invalid_json_and_schema(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'result.json'
            for data in ('[]', '{"filename":"foo"}', 'not json'):
                p.write_text(data,encoding='utf-8')
                with self.assertRaises(ValueError):load_report(p)

    def test_rejects_too_large_before_read(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'result.json'
            p.write_bytes(b' '*40)
            with self.assertRaisesRegex(ValueError,'large'):
                load_report(p,max_bytes=20)

    def test_same_binary_across_different_backends(self):
        left=report(backend='ghidra',funcs=[{'name':'main','entry':'0x10'}])
        right=report(backend='rizin')
        compared=compare_reports(left,right)
        self.assertTrue(compared['same_binary'])
        self.assertEqual(compared['left']['backend'],'ghidra')
        self.assertEqual(compared['right']['backend'],'rizin')
        self.assertFalse(compared['functions']['comparable'])
        self.assertEqual(compared['functions']['reason'],'Function list missing on one or both reports')

    def test_reports_function_changes_and_counts(self):
        left=report(funcs=[{'name':'main','entry':'0x10'},{'name':'init','entry':'0x20'}])
        right=report(sha='b'*64, funcs=[{'name':'main','entry':'0x10'},{'name':'added','entry':'0x30'}],size=121)
        result=compare_reports(left,right)
        self.assertFalse(result['same_binary'])
        self.assertTrue(result['changes']['sha256'])
        self.assertTrue(result['changes']['size_bytes'])
        self.assertEqual(result['functions']['common_count'],1)
        self.assertEqual(result['functions']['removed'],[{'name':'init','entry':'0x20'}])
        self.assertEqual(result['functions']['added'],[{'name':'added','entry':'0x30'}])

    def test_truncates_diff_but_preserves_totals(self):
        left=report(funcs=[])
        right=report(funcs=[{'name':f'func{i}','entry':f'{i:04x}'} for i in range(50)])
        diff=compare_reports(left,right,max_changes=3)
        self.assertEqual(diff['functions']['added_count'],50)
        self.assertEqual(len(diff['functions']['added']),3)
        self.assertTrue(diff['functions']['truncated'])

    def test_offline_explanation_does_not_invent_malware_or_function_behavior(self):
        text=explain_report(report(funcs=[{'name':'main','entry':'0x10'}]))
        self.assertIn('SHA-256',text)
        self.assertIn('1 función',text)
        self.assertIn('no demuestra',text)

    def test_rejects_malformed_functions_and_nonhex_digest(self):
        invalid=report(sha='not-sha')
        with self.assertRaises(ValueError): compare_reports(invalid, report())
        invalid=report(funcs='all')
        with self.assertRaises(ValueError): compare_reports(invalid, report())


if __name__=='__main__':unittest.main()
