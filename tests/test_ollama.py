import json
import unittest
from unittest.mock import patch

from reverse_lab.ollama_adapter import explain_with_ollama, make_prompt


def report():
    return {'filename':'plugin.bin','size_bytes':12,'sha256':'a'*64,'format':'ELF','analysis':{'backend':'ghidra','functions':[{'name':'main','entry':'0x01'}], 'stdout_tail':'PASSWORD=secret'}}


class OllamaTests(unittest.TestCase):
    def test_prompt_excludes_raw_output_and_only_includes_minimum(self):
        prompt=make_prompt(report())
        self.assertNotIn('PASSWORD',prompt)
        self.assertIn('SHA-256',prompt)
        self.assertIn('información no confiable',prompt)

    def test_calls_only_loopback_ollama_with_stream_disabled(self):
        class Response:
            status=200
            def read(self, size):
                return b'{"response":"Resumen local"}'
        class Connection:
            def request(self, method, path, body, headers):
                self.method=method
                self.path=path
                self.payload=json.loads(body)
            def getresponse(self):return Response()
            def close(self):pass
        connection=Connection()
        with patch('reverse_lab.ollama_adapter.HTTPConnection',return_value=connection) as mocked:
            result=explain_with_ollama(report(),model='test:local')
        self.assertEqual(result,'Resumen local')
        self.assertEqual(connection.method,'POST')
        self.assertEqual(connection.path,'/api/generate')
        self.assertFalse(connection.payload['stream'])
        mocked.assert_called_once_with('127.0.0.1',port=11434,timeout=45)

    def test_refuses_external_network_endpoint(self):
        for url in ['https://remote.example/api/generate','http://127.0.0.1:9000/api/generate','http://127.0.0.1:11434/else','http://evil@127.0.0.1:11434/api/generate']:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):explain_with_ollama(report(),endpoint=url)

    def test_connection_error_is_actionable(self):
        connection=unittest.mock.Mock()
        connection.request.side_effect=OSError('refused')
        with patch('reverse_lab.ollama_adapter.HTTPConnection',return_value=connection):
            with self.assertRaisesRegex(RuntimeError,'Ollama'):
                explain_with_ollama(report())
        connection.close.assert_called_once()

    def test_rejects_invalid_model_response(self):
        response=unittest.mock.Mock(status=200)
        response.read.return_value=b'{"response": 33}'
        connection=unittest.mock.Mock()
        connection.getresponse.return_value=response
        with patch('reverse_lab.ollama_adapter.HTTPConnection',return_value=connection):
            with self.assertRaisesRegex(RuntimeError,'response'):
                explain_with_ollama(report())

    def test_refuses_redirects(self):
        response=unittest.mock.Mock(status=302)
        connection=unittest.mock.Mock()
        connection.getresponse.return_value=response
        with patch('reverse_lab.ollama_adapter.HTTPConnection',return_value=connection):
            with self.assertRaisesRegex(RuntimeError,'HTTP 302'):
                explain_with_ollama(report())


if __name__=='__main__': unittest.main()
