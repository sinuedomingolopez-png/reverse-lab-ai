"""Regression checks for a reproducible, auditable Windows portable ZIP."""
import hashlib
import json
import subprocess
from unittest.mock import patch
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.build_windows import build_command, make_archive, portable_readme, attempt_gui_smoke, windows_diagnostic_launcher, release_version


class PortableBuilderTests(unittest.TestCase):
    def test_release_version_matches_python_package_and_support_report(self):
        import re
        from reverse_lab import support
        project = Path(__file__).resolve().parents[1]
        declared = re.search(r'^version = "([^"]+)"$', (project / "pyproject.toml").read_text(),
                             re.MULTILINE).group(1)
        self.assertEqual(release_version(), declared)
        self.assertEqual(support._RELEASE, declared)
        self.assertIn(f"({declared})", portable_readme())

    def test_default_archive_uses_current_package_version_not_stale_label(self):
        with tempfile.TemporaryDirectory() as td:
            app = Path(td) / "dist" / "ReverseLabAI"
            app.mkdir(parents=True)
            (app / "ReverseLabAI.exe").write_bytes(b"test")
            archive, checksum = make_archive(app)
            self.assertEqual(archive.name,
                             f"ReverseLabAI-{release_version()}-windows-x64.zip")
            self.assertTrue(checksum.is_file())

    def test_pyinstaller_command_uses_onedir_windowed_and_bundled_scripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cmd = build_command(root)
        self.assertEqual(cmd[1:3], ["-m", "PyInstaller"])
        self.assertIn("--onedir", cmd)
        self.assertIn("--windowed", cmd)
        self.assertIn("--collect-data", cmd)
        self.assertIn("reverse_lab", cmd)
        self.assertIn("--exclude-module", cmd)
        self.assertIn("angr", cmd)
        self.assertTrue(
            any("angr_worker.py" in arg for arg in cmd),
            "The portable build must ship the worker source for an external Python."
        )

    def test_pyinstaller_spec_and_data_are_resolved_from_project_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            cmd = build_command(Path(tmp))
        # PyInstaller resolves --add-data sources relative to the .spec file.
        # Keeping .spec in ./ avoids accidentally searching ./build/... .
        self.assertEqual(cmd[cmd.index("--specpath") + 1], ".")
        self.assertIn(
            "reverse_lab/integrations/angr_worker.py:reverse_lab/integrations",
            cmd,
        )

    def test_archive_preserves_app_folder_structure_and_hashes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app = root / "dist" / "ReverseLabAI"
            nested = app / "_internal" / "reverse_lab"
            nested.mkdir(parents=True)
            (app / "ReverseLabAI.exe").write_bytes(b"demo")
            (nested / "ExportFunctions.java").write_text("sample", encoding="utf-8")
            archive, checksum_path = make_archive(app, version="0.11.0")
            self.assertTrue(archive.is_file())
            self.assertTrue(checksum_path.is_file())
            with zipfile.ZipFile(archive) as package:
                names = set(package.namelist())
            self.assertIn("ReverseLabAI/ReverseLabAI.exe", names)
            self.assertIn("ReverseLabAI/_internal/reverse_lab/ExportFunctions.java", names)
            expected = hashlib.sha256(archive.read_bytes()).hexdigest()
            self.assertTrue(checksum_path.read_text().startswith(expected))

    def test_headless_windows_timeout_is_unverified_not_passed(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "gui-smoke.json"
            with patch("tools.build_windows.subprocess.run",
                       side_effect=subprocess.TimeoutExpired(["ReverseLabAI.exe"], 12)):
                status = attempt_gui_smoke(Path(td) / "ReverseLabAI.exe", path, timeout=12)
            self.assertEqual(status["status"], "not_verified")
            self.assertFalse(status.get("window_created", False))
            self.assertEqual(json.loads(path.read_text())["status"], "not_verified")

    def test_real_success_requires_window_created(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "gui-smoke.json"
            path.write_text(json.dumps({"status": "passed", "window_created": True}))
            with patch("tools.build_windows.subprocess.run",
                       return_value=subprocess.CompletedProcess([], 0)):
                status = attempt_gui_smoke(Path(td) / "ReverseLabAI.exe", path)
            self.assertEqual(status["status"], "passed")

    def test_explicit_gui_failure_still_fails_build(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "gui-smoke.json"
            path.write_text(json.dumps({"status": "failed", "window_created": False}))
            with patch("tools.build_windows.subprocess.run",
                       return_value=subprocess.CompletedProcess([], 3)):
                with self.assertRaisesRegex(RuntimeError, "GUI"):
                    attempt_gui_smoke(Path(td) / "ReverseLabAI.exe", path)

    def test_windows_support_launcher_creates_only_opt_in_safe_report(self):
        script = windows_diagnostic_launcher()
        self.assertIn('ReverseLabAI.exe', script)
        self.assertIn('--diagnostics-output', script)
        self.assertIn('%TEMP%', script)
        self.assertNotIn('powershell -enc', script.lower())

    def test_readme_explains_unsigned_status_and_optional_tools(self):
        text = portable_readme()
        for required in ("NO FIRMADO", "Ghidra", "angr", "Python", "ReverseLabAI.exe"):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
