import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.call_graph import extract_call_edges, build_dot, outgoing_calls
from reverse_lab.integrations.ghidra_adapter import analyze_with_ghidra
from reverse_lab.workflow import analyze
from reverse_lab.cli import main


SAMPLE_EDGES = [
    {'caller': {'name': 'main', 'entry': '00401000'},
     'callee': {'name': 'helper', 'entry': '00401200'}},
    {'caller': {'name': 'main', 'entry': '00401000'},
     'callee': {'name': 'draw "view"', 'entry': '00401400'}},
    {'caller': {'name': 'helper', 'entry': '00401200'},
     'callee': {'name': 'log', 'entry': '00401600'}},
]


class CallGraphHelpersTests(unittest.TestCase):
    def test_extracts_bounded_edges(self):
        report = {'analysis': {'call_graph': SAMPLE_EDGES}}
        self.assertEqual(len(extract_call_edges(report, limit=2)), 2)
        self.assertEqual(extract_call_edges({'analysis': {}}), [])

    def test_ignores_bad_records(self):
        report = {'analysis': {'call_graph': [None, {}, SAMPLE_EDGES[0], {'caller': 'main', 'callee': {}}]}}
        self.assertEqual(extract_call_edges(report), SAMPLE_EDGES[:1])

    def test_outgoing_calls_filters_by_entry_address(self):
        self.assertEqual(outgoing_calls(SAMPLE_EDGES, '00401000'), [
            ('helper', '00401200'), ('draw "view"', '00401400')])
        self.assertEqual(outgoing_calls(SAMPLE_EDGES, 'n/a'), [])

    def test_dot_escapes_untrusted_names(self):
        report = {'analysis': {'call_graph': SAMPLE_EDGES}}
        dot = build_dot(report)
        self.assertIn('digraph ReverseLabCalls {', dot)
        self.assertIn('draw \\"view\\"', dot)
        self.assertIn('"00401000" -> "00401200"', dot)

    def test_dot_rejects_invalid_limit(self):
        with self.assertRaises(ValueError):
            build_dot({'analysis': {}}, limit=0)


class CallGraphAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.target = Path(self.temp.name) / 'sample.exe'
        self.runner = Path(self.temp.name) / 'analyzeHeadless'
        self.target.write_bytes(b'MZ' + bytes(30))
        self.runner.touch()

    def test_export_is_opt_in_and_json_is_checked(self):
        def fake_run(args, **kwargs):
            i = args.index('ExportCallGraph.java')
            self.assertEqual(args[i + 2:i + 4], ['30', '80'])
            Path(args[i + 1]).write_text(json.dumps(SAMPLE_EDGES), encoding='utf-8')
            return subprocess.CompletedProcess(args, 0, '', '')
        with patch('reverse_lab.integrations.ghidra_adapter.subprocess.run', side_effect=fake_run):
            result = analyze_with_ghidra(self.target, self.runner,
                export_call_graph=True, call_graph_max_callers=30, call_graph_max_edges=80)
        self.assertTrue(result['success'], result)
        self.assertEqual(result['call_graph_count'], 3)

    def test_export_missing_is_failure(self):
        with patch('reverse_lab.integrations.ghidra_adapter.subprocess.run',
                return_value=subprocess.CompletedProcess([], 0, '', '')):
            result = analyze_with_ghidra(self.target, self.runner, export_call_graph=True)
        self.assertFalse(result['success'])
        self.assertIn('error', result)

    def test_invalid_edges_are_rejected(self):
        def fake_run(args, **kwargs):
            i = args.index('ExportCallGraph.java')
            Path(args[i + 1]).write_text('[{"caller":"not a node","callee":{}}]')
            return subprocess.CompletedProcess(args, 0, '', '')
        with patch('reverse_lab.integrations.ghidra_adapter.subprocess.run', side_effect=fake_run):
            report = analyze_with_ghidra(self.target, self.runner, export_call_graph=True)
        self.assertFalse(report['success'])

    def test_rejects_limits_before_launching(self):
        for max_callers, max_edges in [(0, 10), (2000, 10), (10, 0), (10, 90000)]:
            with self.subTest(max_callers=max_callers, max_edges=max_edges):
                with patch('reverse_lab.integrations.ghidra_adapter.subprocess.run') as run:
                    with self.assertRaises(ValueError):
                        analyze_with_ghidra(self.target, self.runner, export_call_graph=True,
                            call_graph_max_callers=max_callers, call_graph_max_edges=max_edges)
                    run.assert_not_called()

    def test_does_not_run_script_without_opt_in(self):
        with patch('reverse_lab.integrations.ghidra_adapter.subprocess.run',
                return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
            analyze_with_ghidra(self.target, self.runner)
        self.assertNotIn('ExportCallGraph.java', run.call_args.args[0])

    def test_workflow_routes_optin(self):
        with patch('reverse_lab.integrations.ghidra_adapter.analyze_with_ghidra',
                return_value={'backend': 'ghidra', 'success': True, 'call_graph': []}) as mocked:
            report = analyze(self.target, backend='ghidra', ghidra_headless='runner',
                             export_call_graph=True)
        self.assertIn('call_graph', report['analysis'])
        self.assertTrue(mocked.call_args.kwargs['export_call_graph'])

    def test_cli_argument_and_validation(self):
        from io import StringIO
        from contextlib import redirect_stdout, redirect_stderr
        with patch('reverse_lab.integrations.ghidra_adapter.analyze_with_ghidra',
                return_value={'backend': 'ghidra', 'success': True, 'call_graph': []}) as mocked:
            with redirect_stdout(StringIO()):
                main([str(self.target), '--backend', 'ghidra',
                    '--ghidra-headless', 'runner', '--export-call-graph'])
        self.assertTrue(mocked.call_args.kwargs['export_call_graph'])
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit):
                main([str(self.target), '--export-call-graph'])


if __name__ == '__main__':
    unittest.main()
