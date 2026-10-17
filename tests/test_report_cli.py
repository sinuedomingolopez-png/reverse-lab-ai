import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.report_cli import main, main_compare, main_explain


def report(sha):
    return {'filename':'app.exe','sha256':sha,'size_bytes':12,'format':'PE (possible)'}


class ReportCLITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.p1=Path(self.temp.name)/'a.json'
        self.p2=Path(self.temp.name)/'b.json'
        self.p1.write_text(json.dumps(report('a'*64)))
        self.p2.write_text(json.dumps(report('b'*64)))

    def test_compare_json_stdout(self):
        out=io.StringIO()
        with contextlib.redirect_stdout(out):
            main_compare([str(self.p1),str(self.p2)])
        self.assertFalse(json.loads(out.getvalue())['same_binary'])

    def test_compare_text_saved_to_file(self):
        output=Path(self.temp.name)/'comparison.txt'
        main_compare([str(self.p1),str(self.p2),'--format','text','--output',str(output)])
        self.assertIn('Mismo SHA-256: no',output.read_text())

    def test_explain_defaults_to_offline_without_network(self):
        with patch('reverse_lab.ollama_adapter.HTTPConnection') as mocked:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                main_explain([str(self.p1)])
        self.assertIn('SHA-256:',out.getvalue())
        mocked.assert_not_called()

    def test_explain_ollama_is_opt_in(self):
        with patch('reverse_lab.ollama_adapter.explain_with_ollama',return_value='Local text') as explained:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                main_explain([str(self.p1),'--ollama','--model','custom:1'])
        self.assertEqual(out.getvalue().strip(),'Local text')
        self.assertEqual(explained.call_args.kwargs['model'],'custom:1')

    def test_module_router(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            main(['compare',str(self.p1),str(self.p2),'--format','text'])
        self.assertIn('Comparación de informes',out.getvalue())


if __name__=='__main__':unittest.main()
