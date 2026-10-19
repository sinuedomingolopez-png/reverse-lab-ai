"""Real desktop controls; no service, file grants or cloud traffic are started."""
import tempfile
import tkinter as tk
import unittest
from pathlib import Path

from reverse_lab.agent_gui import AgentPanel


class AgentPanelTests(unittest.TestCase):
    def test_empty_permissions_do_not_create_history_or_claim_connection(self):
        root = tk.Tk()
        root.withdraw()
        self.addCleanup(root.destroy)
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "grants.json"
            panel = AgentPanel(root, manifest=manifest)
            root.update()
            self.assertFalse(manifest.exists())
            self.assertEqual(panel.files.get_children(), ())
            self.assertIsNone(panel.process)
            panel.stop()
            self.assertIn("detenido", panel.state.get())
            panel.close()
