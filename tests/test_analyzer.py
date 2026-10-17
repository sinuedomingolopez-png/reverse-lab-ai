import hashlib
import tempfile
import unittest
from pathlib import Path

from reverse_lab.analyzer import detect_format, inspect_file


class AnalyzerTests(unittest.TestCase):
    def test_recognizes_formats(self):
        self.assertEqual(detect_format(b"\\x7fELF"+b"\\x00"*12), "ELF")
        self.assertEqual(detect_format(b"\\x00asm"+b"\\x01"*12), "WebAssembly")
        self.assertEqual(detect_format(b"PK\\x03\\x04"), "ZIP")

    def test_unknown(self):
        self.assertEqual(detect_format(b"plain text"), "unknown")

    def test_streaming_hash_and_size(self):
        data = b"hello reverse lab" * 100
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample.bin"
            path.write_bytes(data)
            result = inspect_file(path)
        self.assertEqual(result["size_bytes"], len(data))
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(result["filename"], "sample.bin")


if __name__ == "__main__":
    unittest.main()
