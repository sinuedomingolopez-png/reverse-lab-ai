import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from reverse_lab.workflow import analyze
from reverse_lab.cli import main
from reverse_lab.integrations.cutter_adapter import find_cutter, launch_cutter
from reverse_lab.integrations.angr_adapter import inspect_with_angr
from reverse_lab.integrations.angr_worker import analyze_cfg


class CutterIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.target = Path(self.temp.name) / "file with spaces.exe"
        self.target.write_bytes(b"MZ" + bytes(100))
        self.launcher = Path(self.temp.name) / "Cutter.exe"
        self.launcher.touch()

    def test_explicit_cutter_is_detected(self):
        self.assertEqual(find_cutter(self.launcher), self.launcher.resolve())

    def test_missing_cutter_is_reported(self):
        with patch.dict("os.environ", {"CUTTER_PATH": ""}):
            with patch("reverse_lab.integrations.cutter_adapter.shutil.which", return_value=None):
                self.assertIsNone(find_cutter())

    def test_opens_existing_binary_as_separate_program_without_shell(self):
        proc = SimpleNamespace(pid=1234)
        with patch("reverse_lab.integrations.cutter_adapter.subprocess.Popen", return_value=proc) as popen:
            report = launch_cutter(self.target, executable=self.launcher)
        self.assertEqual(report["status"], "started")
        self.assertEqual(report["pid"], 1234)
        args = popen.call_args.args[0]
        self.assertEqual(args, [str(self.launcher.resolve()), str(self.target.resolve())])
        self.assertIs(popen.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertFalse(popen.call_args.kwargs.get("shell", False))

    def test_cutter_must_be_installed(self):
        with self.assertRaisesRegex(RuntimeError, "Cutter"):
            launch_cutter(self.target, executable=Path(self.temp.name) / "missing.exe")

    def test_cutter_refuses_missing_target(self):
        with self.assertRaises((ValueError, FileNotFoundError)):
            launch_cutter(Path(self.temp.name) / "missing.bin", executable=self.launcher)


class AngrAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.target = Path(self.temp.name) / "sample with spaces.elf"
        self.target.write_bytes(bytes.fromhex("7f454c46") + bytes(30))

    def test_runs_separate_python_worker_and_checks_json(self):
        output = json.dumps({
            "backend": "angr", "analysis_type": "CFGFast",
            "function_count": 1, "cfg_nodes": 2, "cfg_edges": 1,
            "functions": [{"name": "main", "entry": "0x401000"}],
            "truncated": False,
        })
        completed = subprocess.CompletedProcess([], 0, output, "")
        with patch("reverse_lab.integrations.angr_adapter.subprocess.run", return_value=completed) as run:
            report = inspect_with_angr(self.target, timeout=30)
        self.assertEqual(report["cfg_edges"], 1)
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[0], sys.executable)
        self.assertEqual(cmd[1:3], ["-m", "reverse_lab.integrations.angr_worker"])
        self.assertEqual(cmd[4], str(self.target.resolve()))
        self.assertFalse(run.call_args.kwargs.get("shell", False))
        self.assertEqual(run.call_args.kwargs["timeout"], 30)

    def test_timeout_is_bounded_and_reported(self):
        with patch("reverse_lab.integrations.angr_adapter.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(["python"], 10)):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                inspect_with_angr(self.target, timeout=10)

    def test_bad_json_or_bad_schema_is_rejected(self):
        for text in ("not json", '{"backend":"angr","functions":"oops"}',
                     '{"backend":"angr","function_count":1,"cfg_nodes":2,"cfg_edges":0,"functions":[{"name":33,"entry":"0x1"}]}'):
            with self.subTest(output=text):
                with patch("reverse_lab.integrations.angr_adapter.subprocess.run",
                           return_value=subprocess.CompletedProcess([], 0, text, "")):
                    with self.assertRaisesRegex(RuntimeError, "angr"):
                        inspect_with_angr(self.target)

    def test_nonzero_status_fails_with_actionable_error(self):
        with patch("reverse_lab.integrations.angr_adapter.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 1, "", "No module named angr")):
            with self.assertRaisesRegex(RuntimeError, "pip install angr"):
                inspect_with_angr(self.target)

    def test_limits_reject_too_large_targets_without_running(self):
        self.target.write_bytes(b"X" * (32 * 1024 * 1024 + 1))
        with patch("reverse_lab.integrations.angr_adapter.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "32 MiB"):
                inspect_with_angr(self.target)
            run.assert_not_called()

    def test_limits_reject_bad_inputs(self):
        for kwargs in ({"max_functions": 0}, {"max_functions": 900},
                       {"timeout": 0}, {"timeout": 1000}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    inspect_with_angr(self.target, **kwargs)


class AngrWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.target = Path(self.temp.name) / "test.elf"
        self.target.write_bytes(bytes.fromhex("7f454c46") + bytes(10))

    def test_cfgfast_does_not_autoload_libraries_or_execute_target(self):
        funcs = {
            0x401000: SimpleNamespace(name="main", addr=0x401000),
            0x401010: SimpleNamespace(name="helper", addr=0x401010),
        }
        graph = SimpleNamespace(nodes=lambda: [1, 2, 3], edges=lambda: [(1, 2)])
        cfg = SimpleNamespace(
            model=SimpleNamespace(graph=graph),
            kb=SimpleNamespace(functions=funcs),
        )
        def fake_project(path, **opts):
            self.assertFalse(opts["auto_load_libs"])
            return SimpleNamespace(analyses=SimpleNamespace(CFGFast=lambda: cfg))
        fake_angr = SimpleNamespace(Project=fake_project)
        with patch.dict(sys.modules, {"angr": fake_angr}):
            report = analyze_cfg(self.target, max_functions=1)
        self.assertEqual(report["analysis_type"], "CFGFast")
        self.assertEqual(report["function_count"], 2)
        self.assertEqual(len(report["functions"]), 1)
        self.assertEqual(report["cfg_nodes"], 3)
        self.assertTrue(report["truncated"])

    def test_worker_validates_max_functions(self):
        with self.assertRaisesRegex(ValueError, "max_functions"):
            analyze_cfg(self.target, max_functions=0)


class AngrWorkflowAndCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.target = Path(self.temp.name) / "target.elf"
        self.target.write_bytes(bytes.fromhex("7f454c46") + bytes(30))

    def test_angr_report_merges_with_static_file_summary(self):
        with patch("reverse_lab.integrations.angr_adapter.inspect_with_angr",
                   return_value={"backend": "angr", "analysis_type": "CFGFast", "functions": []}) as mocked:
            report = analyze(self.target, backend="angr", timeout=42)
        self.assertEqual(report["format"], "ELF")
        self.assertEqual(report["analysis"]["backend"], "angr")
        mocked.assert_called_once_with(self.target, timeout=42)

    def test_cli_exposes_optional_angr_backend(self):
        with patch("reverse_lab.integrations.angr_adapter.inspect_with_angr",
                   return_value={"backend": "angr", "analysis_type": "CFGFast", "functions": []}):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                main([str(self.target), "--backend", "angr"])
        self.assertEqual(json.loads(output.getvalue())["analysis"]["backend"], "angr")


if __name__ == "__main__":
    unittest.main()
