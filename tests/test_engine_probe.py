"""A real-engine smoke test must use an inert locally generated ELF."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from reverse_lab.engine_probe import probe_engine, main


class EngineProbeTests(unittest.TestCase):
    def test_lief_positive_checks_real_workflow_response(self):
        def fake_analysis(target, **kwargs):
            data = Path(target).read_bytes()
            self.assertEqual(data[:4], b"\x7fELF")
            self.assertGreater(len(data), 4000)
            self.assertEqual(kwargs["backend"], "lief")
            return {
                "format": "ELF",
                "analysis": {"backend": "lief", "recognized": True,
                             "entrypoint": 0x401000, "format": "Binary"},
            }
        with patch("reverse_lab.engine_probe._is_installed", return_value=True), \
             patch("reverse_lab.workflow.analyze", side_effect=fake_analysis):
            result = probe_engine("lief")
        self.assertEqual(result["status"], "passed", result)
        self.assertTrue(all(result["checks"].values()))
        self.assertEqual(result["metrics"]["entrypoint"], "0x401000")
        self.assertNotIn("filename", result)
        self.assertNotIn("path", result)

    def test_angr_positive_checks_real_workflow_response(self):
        with patch("reverse_lab.engine_probe._is_installed", return_value=True), \
             patch("reverse_lab.workflow.analyze", return_value={
                 "format": "ELF", "analysis": {
                     "backend": "angr", "analysis_type": "CFGFast",
                     "function_count": 2, "cfg_nodes": 4, "cfg_edges": 3,
                     "functions": [{"name": "sub_401000", "entry": "0x401000"}],
                     "truncated": False
                 },
             }) as analyze:
            result = probe_engine("angr", timeout=75)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["metrics"]["cfg_nodes"], 4)
        self.assertEqual(analyze.call_args.kwargs["timeout"], 75)

    def test_uninstalled_engine_has_explicit_missing_status(self):
        with patch("reverse_lab.engine_probe._is_installed", return_value=False), \
             patch("reverse_lab.workflow.analyze") as analyze:
            result = probe_engine("angr")
        analyze.assert_not_called()
        self.assertEqual(result["status"], "missing")
        self.assertFalse(result["checks"]["dependency_installed"])

    def test_incomplete_angr_cfg_is_failed_not_passed(self):
        with patch("reverse_lab.engine_probe._is_installed", return_value=True), \
             patch("reverse_lab.workflow.analyze", return_value={
                 "format": "ELF", "analysis": {
                     "backend": "angr", "analysis_type": "CFGFast",
                     "function_count": 0, "cfg_nodes": 0, "cfg_edges": 0,
                     "functions": [], "truncated": False,
                 },
             }):
            result = probe_engine("angr")
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["checks"]["functions_discovered"])

    def test_lief_wrong_entrypoint_not_counted_as_success(self):
        with patch("reverse_lab.engine_probe._is_installed", return_value=True), \
             patch("reverse_lab.workflow.analyze", return_value={
                 "format": "ELF", "analysis": {
                     "backend": "lief", "recognized": True, "entrypoint": 0,
                 },
             }):
            result = probe_engine("lief")
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["checks"]["expected_entrypoint"])

    def test_exception_text_is_not_exposed(self):
        with patch("reverse_lab.engine_probe._is_installed", return_value=True), \
             patch("reverse_lab.workflow.analyze",
                   side_effect=RuntimeError("SECRET /home/user/private.bin")):
            result = probe_engine("lief")
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("private", json.dumps(result))

    def test_probe_cleans_sample_after_processing(self):
        path_used = []
        def read_sample(target, **kwargs):
            path_used.append(Path(target))
            self.assertTrue(Path(target).is_file())
            return {"format": "ELF", "analysis": {"backend": "lief",
                    "recognized": True, "entrypoint": 0x401000}}
        with patch("reverse_lab.engine_probe._is_installed", return_value=True), \
             patch("reverse_lab.workflow.analyze", side_effect=read_sample):
            probe_engine("lief")
        self.assertFalse(path_used[0].exists())

    def test_invalid_engine_and_timeout_rejected(self):
        with self.assertRaises(ValueError):
            probe_engine("ghidra")
        for timeout in (0, 4, 601):
            with self.assertRaises(ValueError):
                probe_engine("angr", timeout=timeout)

    def test_cli_exit_code_if_missing_engine_and_writes_json(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "check.json"
            with patch("reverse_lab.engine_probe._is_installed", return_value=False):
                with redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit) as exc:
                        main(["--engine", "lief", "--output", str(output)])
            self.assertEqual(exc.exception.code, 2)
            self.assertEqual(json.loads(output.read_text())["status"], "missing")

    def test_cli_success_prints_only_status(self):
        with patch("reverse_lab.engine_probe._is_installed", return_value=True), \
             patch("reverse_lab.workflow.analyze", return_value={
                 "format": "ELF",
                 "analysis": {"backend": "lief", "recognized": True,
                              "entrypoint": 0x401000}
             }):
            captured = io.StringIO()
            with redirect_stdout(captured):
                main(["--engine", "lief"])
        self.assertEqual(json.loads(captured.getvalue())["status"], "passed")


if __name__ == "__main__":
    unittest.main()
