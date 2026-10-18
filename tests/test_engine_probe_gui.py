"""The GUI must clearly distinguish installed, passed, and failed engine checks."""
import unittest

from reverse_lab.engine_probe_gui import format_engine_probe


class EngineProbePresentationTests(unittest.TestCase):
    def test_passed_lief_shows_checked_conditions(self):
        report = {
            "engine": "lief", "status": "passed",
            "checks": {"dependency_installed": True, "expected_entrypoint": True},
            "metrics": {"entrypoint": "0x401000"}
        }
        text = format_engine_probe(report)
        self.assertIn("VALIDACIÓN CORRECTA", text)
        self.assertIn("LIEF", text)
        self.assertIn("0x401000", text)

    def test_missing_dependency_does_not_claim_success(self):
        report = {"engine": "angr", "status": "missing",
                  "checks": {"dependency_installed": False}, "metrics": {}}
        text = format_engine_probe(report)
        self.assertIn("NO INSTALADO", text)
        self.assertNotIn("VALIDACIÓN CORRECTA", text)

    def test_failure_does_not_reveal_raw_exceptions(self):
        report = {"engine": "angr", "status": "failed",
                  "checks": {"static_cfg": False},
                  "metrics": {}, "failure_type": "ValueError",
                  "unexpected": "private path /home/user/secret.bin"}
        text = format_engine_probe(report)
        self.assertIn("FALLÓ", text)
        self.assertNotIn("/home/user", text)
        self.assertNotIn("secret.bin", text)


if __name__ == "__main__":
    unittest.main()
