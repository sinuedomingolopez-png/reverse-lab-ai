import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.ghidra_probe import (
    build_synthetic_elf, discover_ghidra, ghidra_selftest, main,
)


class FixtureTests(unittest.TestCase):
    def test_fixture_is_valid_x86_64_elf_with_two_functions(self):
        content = build_synthetic_elf()
        self.assertEqual(content[:4], b"\x7fELF")
        self.assertEqual(content[4:6], b"\x02\x01")
        self.assertEqual(struct.unpack_from("<H", content, 18)[0], 62)
        self.assertEqual(struct.unpack_from("<Q", content, 24)[0], 0x401000)
        self.assertEqual(content[0x1000:0x1005], b"\xe8\x05\x00\x00\x00")
        shoff = struct.unpack_from("<Q", content, 40)[0]
        self.assertEqual(struct.unpack_from("<H", content, 60)[0], 3)
        self.assertTrue(0 < shoff < len(content) - 3 * 64 + 1)

    def test_fixture_is_deterministic(self):
        self.assertEqual(build_synthetic_elf(), build_synthetic_elf())


class DiscoveryTests(unittest.TestCase):
    def test_explicit_launcher_overrides_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / (
                "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
            )
            launcher.touch()
            with patch.dict(os.environ, {"GHIDRA_HOME": "/missing"}):
                self.assertEqual(discover_ghidra(launcher), launcher.resolve())

    def test_ghidra_home_variable_is_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            support = Path(directory) / "support"
            support.mkdir()
            launcher = support / (
                "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
            )
            launcher.touch()
            with patch.dict(os.environ, {"GHIDRA_HOME": directory}):
                self.assertEqual(discover_ghidra(), launcher.resolve())

    def test_missing_launcher_returns_none(self):
        with patch.dict(os.environ, {"GHIDRA_HOME": "/not-installed"}):
            with patch("reverse_lab.ghidra_probe.shutil.which", return_value=None):
                self.assertIsNone(discover_ghidra())


class SmokeTests(unittest.TestCase):
    def test_missing_runner_reports_unavailable(self):
        with patch("reverse_lab.ghidra_probe.discover_ghidra", return_value=None):
            result = ghidra_selftest()
        self.assertEqual(result["status"], "missing")
        self.assertFalse(result["checks"]["ghidra_available"])

    def test_real_analysis_adapter_called_with_all_exports(self):
        def fake_adapter(target, launcher, **kwargs):
            self.assertEqual(Path(target).read_bytes()[:4], b"\x7fELF")
            self.assertTrue(kwargs["export_functions"])
            self.assertTrue(kwargs["export_pseudocode"])
            self.assertTrue(kwargs["export_call_graph"])
            return {
                "backend": "ghidra", "success": True,
                "functions": [{"name": "entry", "entry": "00401000"}],
                "function_count": 1,
                "pseudocode": [{"name": "entry", "entry": "00401000",
                                "pseudocode": "return 0;", "truncated": False}],
                "pseudocode_count": 1,
                "call_graph": [{
                    "caller": {"name": "entry", "entry": "00401000"},
                    "callee": {"name": "helper", "entry": "0040100a"},
                }],
                "call_graph_count": 1,
            }
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "analyzeHeadless"
            launcher.touch()
            with patch("reverse_lab.integrations.ghidra_adapter.analyze_with_ghidra",
                       side_effect=fake_adapter):
                result = ghidra_selftest(launcher=launcher)
        self.assertEqual(result["status"], "passed")
        self.assertTrue(all(result["checks"].values()))
        self.assertEqual(result["counts"]["functions"], 1)

    def test_failed_adapter_reports_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "analyzeHeadless"
            launcher.touch()
            with patch("reverse_lab.integrations.ghidra_adapter.analyze_with_ghidra",
                       return_value={"success": False, "error": "Java script error"}):
                result = ghidra_selftest(launcher=launcher)
        self.assertEqual(result["status"], "failed")
        self.assertIn("Java script error", result["error"])

    def test_empty_exports_report_a_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "analyzeHeadless"
            launcher.touch()
            with patch("reverse_lab.integrations.ghidra_adapter.analyze_with_ghidra",
                       return_value={
                           "success": True, "functions": [], "pseudocode": [], "call_graph": [],
                       }):
                result = ghidra_selftest(launcher=launcher)
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["warnings"])

    def test_inconsistent_counts_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "analyzeHeadless"
            launcher.touch()
            with patch("reverse_lab.integrations.ghidra_adapter.analyze_with_ghidra",
                       return_value={
                           "success": True, "functions": [], "pseudocode": [],
                           "call_graph": [], "function_count": 11,
                       }):
                result = ghidra_selftest(launcher=launcher)
        self.assertEqual(result["status"], "failed")

    def test_cli_missing_tool_exits_nonzero_and_prints_json(self):
        import io
        from contextlib import redirect_stdout
        with patch("reverse_lab.ghidra_probe.discover_ghidra", return_value=None):
            capture = io.StringIO()
            with redirect_stdout(capture):
                with self.assertRaises(SystemExit) as caught:
                    main([])
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(json.loads(capture.getvalue())["status"], "missing")

    def test_check_only_does_not_execute_ghidra(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "analyzeHeadless"
            launcher.touch()
            with patch("reverse_lab.integrations.ghidra_adapter.analyze_with_ghidra") as adapter:
                result = ghidra_selftest(launcher=launcher, check_only=True)
        self.assertEqual(result["status"], "available")
        adapter.assert_not_called()


if __name__ == "__main__":
    unittest.main()
