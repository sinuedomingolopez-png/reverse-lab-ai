import json
import unittest

from reverse_lab.gui import extract_function_rows, format_report_preview


class GuiHelpersTests(unittest.TestCase):
    def test_extracts_function_rows_from_ghidra_report(self):
        data = {'analysis': {'functions': [
            {'name': 'main', 'entry': '0x401000'},
            {'name': 'init', 'entry': '0x401200'},
        ]}}
        self.assertEqual(extract_function_rows(data), [
            ('main', '0x401000'), ('init', '0x401200')
        ])

    def test_ignores_unexpected_function_values(self):
        data = {'analysis': {'functions': [None, {'name': 3, 'entry': 1}, {'name': 'ok', 'entry': '0x2'}]}}
        self.assertEqual(extract_function_rows(data), [('ok', '0x2')])

    def test_limits_displayed_rows(self):
        data = {'analysis': {'functions': [{'name': str(i), 'entry': str(i)} for i in range(200)]}}
        self.assertEqual(len(extract_function_rows(data, limit=30)), 30)

    def test_preview_shows_truncation_without_mutating_report(self):
        data = {'text': 'abcdefghij'}
        preview = format_report_preview(data, limit=10)
        self.assertIn('truncado', preview)
        self.assertEqual(data['text'], 'abcdefghij')

    def test_short_report_remains_valid_json(self):
        data = {'filename': 'álbum.wav', 'size_bytes': 8}
        self.assertEqual(json.loads(format_report_preview(data)), data)


if __name__ == '__main__':
    unittest.main()
