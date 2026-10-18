"""Regression checks for a reproducible, auditable Windows portable ZIP."""
import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.build_windows import build_command, make_archive, portable_readme


class PortableBuilderTests(unittest.TestCase):
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
            archive, checksum_path = make_archive(app, version="0.9.0")
            self.assertTrue(archive.is_file())
            self.assertTrue(checksum_path.is_file())
            with zipfile.ZipFile(archive) as package:
                names = set(package.namelist())
            self.assertIn("ReverseLabAI/ReverseLabAI.exe", names)
            self.assertIn("ReverseLabAI/_internal/reverse_lab/ExportFunctions.java", names)
            expected = hashlib.sha256(archive.read_bytes()).hexdigest()
            self.assertTrue(checksum_path.read_text().startswith(expected))

    def test_readme_explains_unsigned_status_and_optional_tools(self):
        text = portable_readme()
        for required in ("NO FIRMADO", "Ghidra", "angr", "Python", "ReverseLabAI.exe"):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
