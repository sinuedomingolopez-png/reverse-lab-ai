import tempfile
import unittest
from pathlib import Path

from reverse_lab.authorizations import Authorizations


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.target = self.root / "authorized.bin"
        self.target.write_bytes(b"synthetic")
        self.store = Authorizations(self.root / "private.json")

    def test_no_implicit_directory_authorization(self):
        self.assertEqual(self.store.list_files(), [])
        with self.assertRaises(ValueError):
            self.store.resolve("arbitrary-path")

    def test_hash_pins_explicit_grant_and_revocation(self):
        item = self.store.grant(self.target, root=self.root)
        self.assertEqual(self.store.resolve(item["id"]), self.target.resolve())
        self.target.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "changed"):
            self.store.resolve(item["id"])
        self.store.revoke(item["id"])
        self.assertEqual(self.store.list_files(), [])

    def test_root_and_size_checks(self):
        with self.assertRaises(ValueError):
            self.store.grant(self.target, root=self.root / "elsewhere")
        with self.assertRaises(ValueError):
            self.store.grant(self.target, root=self.root, max_bytes=1)

    def test_content_export_needs_local_grant(self):
        item = self.store.grant(self.target, root=self.root)
        self.assertFalse(self.store.permission(item["id"], "content"))
        self.assertTrue(self.store.permission(item["id"], "metadata"))

    def test_secret_paths_are_not_listed(self):
        item = self.store.grant(self.target, root=self.root)
        self.assertNotIn(str(self.root), str(self.store.list_files()))
        self.assertNotIn("path", item)
