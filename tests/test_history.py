"""Local history: explicit opt-in persistence of possibly confidential reports."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.history import HistoryStore, default_history_directory

def report(sha="a" * 64, name="example.bin"):
    return {
        "filename": name,
        "sha256": sha,
        "size_bytes": 34,
        "format": "ELF",
        "analysis": {
            "backend": "ghidra",
            "functions": [{"name": "main", "entry": "0x400"}],
            "pseudocode": [{"name": "main", "entry": "0x400", "pseudocode": "int main() { return 0; }"}],
        },
    }


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.directory = Path(self.tempdir.name) / "history"
        self.store = HistoryStore(self.directory)

    def test_listing_does_not_create_history_automatically(self):
        self.assertEqual(self.store.list_entries(), [])
        self.assertFalse(self.directory.exists())

    def test_save_and_reopen_preserves_complete_report(self):
        original = report()
        item = self.store.save(original)
        self.assertRegex(item["id"], "^[a-f0-9]{32}$")
        self.assertEqual(item["filename"], "example.bin")
        self.assertEqual(item["backend"], "ghidra")
        self.assertEqual(self.store.load(item["id"]), original)
        self.assertEqual(self.store.list_entries()[0]["id"], item["id"])

    def test_separate_reports_do_not_overwrite(self):
        one = self.store.save(report(name="one"))
        two = self.store.save(report(name="two"))
        self.assertNotEqual(one["id"], two["id"])
        self.assertEqual(len(self.store.list_entries()), 2)

    def test_delete_only_named_local_history_item(self):
        one = self.store.save(report(name="one"))
        two = self.store.save(report(name="two"))
        self.assertTrue(self.store.delete(one["id"]))
        self.assertFalse(self.store.delete(one["id"]))
        self.assertEqual(self.store.load(two["id"])["filename"], "two")
        with self.assertRaises(FileNotFoundError):
            self.store.load(one["id"])

    def test_invalid_identifiers_cannot_escape_history_directory(self):
        for item in ("../secret", "/tmp/abc", "wrong.json", "", "..", "A" * 32):
            with self.subTest(item=item):
                with self.assertRaises(ValueError):
                    self.store.load(item)
                with self.assertRaises(ValueError):
                    self.store.delete(item)

    def test_reports_without_required_metadata_are_rejected(self):
        with self.assertRaises(ValueError):
            self.store.save({"filename": "incomplete"})
        self.assertFalse(self.directory.exists())

    def test_excessive_report_size_rejected_before_disk_write(self):
        oversized = report()
        oversized["analysis"]["pseudocode"][0]["pseudocode"] = "X" * (4 * 1024 * 1024 + 20)
        with self.assertRaisesRegex(ValueError, "4 MiB"):
            self.store.save(oversized)
        self.assertFalse(self.directory.exists())

    def test_history_capacity_does_not_silently_prune(self):
        self.store = HistoryStore(self.directory, max_records=2)
        self.store.save(report(name="one"))
        self.store.save(report(name="two"))
        with self.assertRaisesRegex(ValueError, "lleno"):
            self.store.save(report(name="three"))
        self.assertEqual(len(self.store.list_entries()), 2)

    def test_saved_report_is_valid_json_and_temporary_files_are_cleaned(self):
        record = self.store.save(report())
        path = self.directory / (record["id"] + ".json")
        self.assertTrue(path.exists())
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "reverse-lab-history-v1")
        self.assertEqual(payload["report"]["filename"], "example.bin")
        self.assertEqual(len(list(self.directory.iterdir())), 1)

    def test_symlinks_are_neither_listed_nor_loaded(self):
        with tempfile.TemporaryDirectory() as other:
            target = Path(other) / "elsewhere.json"
            target.write_text(json.dumps({"private": True}), encoding="utf-8")
            ident = "a" * 32
            link = self.directory / (ident + ".json")
            self.directory.mkdir()
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks unavailable on this OS")
            self.assertEqual(self.store.list_entries(), [])
            with self.assertRaises(ValueError):
                self.store.load(ident)
            self.assertTrue(target.exists())

    def test_default_location_is_per_user_not_project(self):
        with patch.dict(os.environ, {"LOCALAPPDATA": "/tmp/my-user/appdata", "XDG_DATA_HOME": "/tmp/my-user/xdg"}):
            path = default_history_directory()
        self.assertIn("ReverseLab", str(path).replace("reverse-lab", "ReverseLab"))
        self.assertIn("history", str(path))


if __name__ == "__main__":
    unittest.main()
