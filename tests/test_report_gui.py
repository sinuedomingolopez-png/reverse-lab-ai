import unittest
from reverse_lab.report_gui import render_comparison_text


class ReportGuiTests(unittest.TestCase):
    def test_comparison_display_includes_human_summary_and_json(self):
        data={'left':{'filename':'before.exe','backend':'ghidra'},
              'right':{'filename':'after.exe','backend':'ghidra'},
              'same_binary':False,
              'functions':{'comparable':True,'common_count':10,
                 'added_count':2,'removed_count':1,'truncated':False,
                 'added':[{'name':'new','entry':'0x02'}], 'removed':[]},
              'schema':'reverse-lab-comparison-v1'}
        text=render_comparison_text(data)
        self.assertIn('Funciones comunes: 10',text)
        self.assertIn('"schema": "reverse-lab-comparison-v1"',text)


if __name__=='__main__':unittest.main()
