"""Actual Tkinter history dialog checks under Xvfb; files stay in a temp dir."""
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.history import HistoryStore
from reverse_lab.history_gui import HistoryDialog


def synthetic_report():
    return {
        "filename": "synthetic.elf", "sha256": "a" * 64,
        "size_bytes": 88, "format": "ELF",
        "analysis": {"backend": "basic"},
    }


class LocalHistoryUITests(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.addCleanup(self.root.destroy)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = HistoryStore(Path(self.temp.name) / "history")

    def test_can_reopen_explicitly_saved_report(self):
        saved = self.store.save(synthetic_report())
        opened = []
        with patch("reverse_lab.history_gui.HistoryStore", return_value=self.store):
            dlg = HistoryDialog(self.root, opened.append)
        self.assertEqual(len(dlg.tree.get_children()), 1)
        dlg.tree.selection_set(saved["id"])
        dlg.open_selected()
        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0]["filename"], "synthetic.elf")
        self.root.update()

    def test_cancel_delete_preserves_report(self):
        saved = self.store.save(synthetic_report())
        with patch("reverse_lab.history_gui.HistoryStore", return_value=self.store):
            dlg = HistoryDialog(self.root, lambda _report: None)
        dlg.tree.selection_set(saved["id"])
        with patch("tkinter.messagebox.askyesno", return_value=False):
            dlg.delete_selected()
        self.assertEqual(len(self.store.list_entries()), 1)
        dlg.window.destroy()
        self.root.update()

if __name__ == "__main__":
    unittest.main()
