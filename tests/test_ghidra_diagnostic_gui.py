import unittest

from reverse_lab.ghidra_diagnostic_gui import format_diagnostic


class DiagnosticFormatTests(unittest.TestCase):
    def test_missing_is_not_presented_as_passed(self):
        data = {"status": "missing", "launcher": None,
                "checks": {"ghidra_available": False},
                "counts": {}, "warnings": [], "error": "No launcher"}
        text = format_diagnostic(data)
        self.assertIn("NO DISPONIBLE", text)
        self.assertIn("No launcher", text)

    def test_passed_report_contains_counts_and_warnings(self):
        data = {"status": "passed", "launcher": "/usr/bin/ghidra",
                "checks": {"ghidra_available": True, "functions_export_valid": True},
                "counts": {"functions": 1}, "warnings": ["No calls"]}
        text = format_diagnostic(data)
        self.assertIn("VALIDACIÓN CORRECTA", text)
        self.assertIn("functions: 1", text)
        self.assertIn("No calls", text)

    def test_available_is_not_analysed(self):
        data = {"status": "available", "launcher": "somewhere",
                "checks": {}, "counts": {}, "warnings": []}
        self.assertIn("SIN ANALIZAR", format_diagnostic(data))


if __name__ == "__main__":
    unittest.main()
