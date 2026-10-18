import tempfile
import importlib.util
import time
import unittest
from pathlib import Path

from reverse_lab.authorizations import Authorizations
from reverse_lab.analysis_jobs import AnalysisJobs


class JobTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.sample = root / "synthetic.bin"
        self.sample.write_bytes(b"synthetic authorized input")
        self.grants = Authorizations(root / "grants.json")
        self.item = self.grants.grant(self.sample, root=root)
        self.jobs = AnalysisJobs(self.grants)
        self.addCleanup(self.jobs.close)

    @unittest.skipUnless(importlib.util.find_spec("psutil"), "requires MCP job extra")
    def test_real_basic_worker_and_revocation(self):
        job = self.jobs.submit(self.item["id"], "basic")
        deadline = time.monotonic() + 15
        while self.jobs.status(job["id"])["state"] in ("queued", "running"):
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.05)
        self.assertEqual(self.jobs.status(job["id"])["state"], "completed")
        report = self.jobs.report(job["id"])
        self.assertEqual(report["sha256"], self.item["sha256"])
        self.assertEqual(report["filename"], "authorized-sample")
        self.grants.revoke(self.item["id"])
        with self.assertRaises(ValueError):
            self.jobs.report(job["id"])

    def test_no_remote_paths_or_commands(self):
        with self.assertRaises(ValueError):
            self.jobs.submit(str(self.sample), "basic")
        with self.assertRaises(ValueError):
            self.jobs.submit(self.item["id"], "cmd.exe")

    def test_resource_limits_are_validated(self):
        with self.assertRaises(ValueError):
            AnalysisJobs(self.grants, timeout=0)
