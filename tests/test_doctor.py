import contextlib
import io
import json
import unittest
from unittest.mock import patch

from reverse_lab.doctor import check_environment, main


class DoctorTests(unittest.TestCase):
    def test_reports_missing_optional_tools_without_running_them(self):
        with patch('reverse_lab.doctor.shutil.which', return_value=None), patch('reverse_lab.doctor.importlib.util.find_spec', return_value=None):
            report = check_environment()
        self.assertEqual(report['tools']['rizin']['available'], False)
        self.assertEqual(report['tools']['lief']['available'], False)
        self.assertIn('ghidra', report['tools'])

    def test_prints_json(self):
        with patch('reverse_lab.doctor.check_environment', return_value={'tools': {}}):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                main()
        self.assertEqual(json.loads(output.getvalue()), {'tools': {}})
