"""Interactive Tk smoke checks (run under Xvfb, not in ordinary headless unit CI)."""
import tkinter as tk
import unittest

from reverse_lab.function_explorer_gui import FunctionExplorerWindow


def sample_report():
    return {"analysis": {
        "functions": [{"name": "main", "entry": "00401000"},
                      {"name": "process_audio", "entry": "00401100"}],
        "pseudocode": [{"name": "process_audio", "entry": "00401100",
                        "pseudocode": "void process_audio(void) { return; }",
                        "truncated": False}],
        "call_graph": [
            {"caller": {"name": "main", "entry": "00401000"},
             "callee": {"name": "process_audio", "entry": "00401100"}},
        ],
    }}


class FunctionExplorerSmokeTests(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.addCleanup(self.root.destroy)

    def test_search_navigation_and_back_button(self):
        window = FunctionExplorerWindow(self.root, sample_report(), initial_entry="00401100")
        self.assertEqual(window.current_entry, "00401100")
        self.assertIn("process_audio(void)", window.details.get("1.0", "end"))
        window.search_var.set("main")
        self.assertEqual(window.functions.get_children(), ("00401000",))
        window.open_entry("00401000")
        self.assertEqual(window.current_entry, "00401000")
        window.go_back()
        self.assertEqual(window.current_entry, "00401100")
        self.root.update()

    def test_double_click_navigation_to_related_function(self):
        window = FunctionExplorerWindow(self.root, sample_report(), initial_entry="00401000")
        window.out_tree.selection_set("00401100")
        window._follow_relation(window.out_tree)
        self.assertEqual(window.current_entry, "00401100")
        self.assertEqual(window.in_tree.item("00401000", "values")[0], "main")
        self.root.update()


if __name__ == "__main__":
    unittest.main()
