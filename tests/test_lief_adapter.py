import unittest
from unittest.mock import patch

from reverse_lab.integrations.lief_adapter import inspect_with_lief


class LiefAdapterTests(unittest.TestCase):
    def test_missing_dependency_has_clear_error(self):
        with patch.dict("sys.modules", {"lief": None}):
            with self.assertRaisesRegex(RuntimeError, "pip install lief"):
                inspect_with_lief("dummy.bin")

    def test_unknown_file_is_reported(self):
        class FakeLief:
            @staticmethod
            def parse(path):
                return None
        with patch.dict("sys.modules", {"lief": FakeLief}):
            self.assertEqual(inspect_with_lief("dummy.bin"), {
                "backend": "lief", "recognized": False,
            })


if __name__ == "__main__":
    unittest.main()
