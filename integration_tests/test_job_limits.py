"""Real inert worker processes verify supervisor limits, not engine accuracy."""
import importlib.util
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_lab.analysis_jobs import AnalysisJobs
from reverse_lab.authorizations import Authorizations


@unittest.skipUnless(importlib.util.find_spec("psutil"), "MCP job extra")
class LimitsTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "Windows Job Object hard memory limit")
    def test_windows_job_denies_allocation_over_memory_cap(self):
        from reverse_lab.analysis_jobs import _windows_job, _terminate
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "memory-result"
            script = f'''import sys
from pathlib import Path
sys.stdin.buffer.read(1)
chunks = []
blocked = False
try:
    for _ in range(32):
        chunks.append(bytearray(16 * 1024 * 1024))
except MemoryError:
    blocked = True
del chunks
Path({str(result)!r}).write_text("blocked" if blocked else "unbounded")
'''
            process = subprocess.Popen([sys.executable, "-c", script], stdin=subprocess.PIPE,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            handle = None
            try:
                handle = _windows_job(process, 256 * 1024 * 1024)
                process.stdin.write(b"1")
                process.stdin.close()
                self.assertEqual(process.wait(timeout=10), 0)
                self.assertEqual(result.read_text(), "blocked")
            finally:
                _terminate(process, handle)

    def test_cancel_and_timeout_terminate_real_worker_tree(self):
        import psutil
        for cancel in (True, False):
            with self.subTest(cancel=cancel), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / "fixture"
                target.write_bytes(b"inert")
                grants = Authorizations(root / "grants.json")
                item = grants.grant(target, root=root)
                jobs = AnalysisJobs(grants, timeout=5)
                started = []
                original = subprocess.Popen
                child_pid_file = root / "child.pid"
                script = ("import sys,subprocess,time; from pathlib import Path; "
                          "sys.stdin.buffer.read(1); "
                          "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']); "
                          f"Path({str(child_pid_file)!r}).write_text(str(p.pid)); time.sleep(30)")
                def fixture_process(command, **kwargs):
                    p = original([sys.executable, "-c", script], **kwargs)
                    started.append(p)
                    return p
                try:
                    with patch("reverse_lab.analysis_jobs.subprocess.Popen", side_effect=fixture_process):
                        job = jobs.submit(item["id"])
                        deadline = time.monotonic() + 12
                        while not child_pid_file.exists():
                            self.assertLess(time.monotonic(), deadline)
                            time.sleep(0.05)
                        child_pid = int(child_pid_file.read_text())
                        if cancel:
                            jobs.cancel(job["id"])
                        while jobs.status(job["id"])["state"] in ("running", "queued"):
                            self.assertLess(time.monotonic(), deadline)
                            time.sleep(0.05)
                        self.assertEqual(jobs.status(job["id"])["state"], "cancelled" if cancel else "timed_out")
                    jobs.close()
                    self.assertIsNotNone(started[0].poll())
                    # Job Object/process-group cleanup can finish just after terminal state.
                    for _ in range(40):
                        if not psutil.pid_exists(child_pid):
                            break
                        try:
                            if psutil.Process(child_pid).status() == psutil.STATUS_ZOMBIE:
                                break
                        except psutil.NoSuchProcess:
                            break
                        time.sleep(0.05)
                    else:
                        self.fail("supervisor left a child process running")
                finally:
                    jobs.close()
