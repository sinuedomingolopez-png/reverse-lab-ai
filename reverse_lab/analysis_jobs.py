"""Bounded transient local jobs, shared by MCP and optional desktop controls.

This is resource containment, not a malware sandbox or a network isolation layer.
Only trusted synthetic samples should be used outside an isolated VM.
"""
from __future__ import annotations

import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path

from .authorizations import Authorizations, digest_file, MAX_FILE_BYTES
from .workflow import BACKENDS


def _windows_job(process, memory_bytes):
    """Attach the gated worker and all descendants to a kill-on-close Job Object."""
    import win32api
    import win32job
    handle = win32job.CreateJobObject(None, "")
    try:
        info = win32job.QueryInformationJobObject(handle, win32job.JobObjectExtendedLimitInformation)
        info["BasicLimitInformation"]["LimitFlags"] = (
            win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | win32job.JOB_OBJECT_LIMIT_JOB_MEMORY)
        info["JobMemoryLimit"] = memory_bytes
        win32job.SetInformationJobObject(handle, win32job.JobObjectExtendedLimitInformation, info)
        proc = win32api.OpenProcess(0x0100 | 0x0001, False, process.pid)
        try:
            win32job.AssignProcessToJobObject(handle, proc)
        finally:
            win32api.CloseHandle(proc)
    except BaseException:
        handle.Close()
        raise
    return handle


def _terminate(process, handle):
    if sys.platform == "win32" and handle is not None:
        handle.Close()
    elif sys.platform != "win32":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is None:
        process.kill()
    process.wait()


class AnalysisJobs:
    def __init__(self, grants: Authorizations, *, timeout: int = 180,
                 memory_mb: int = 2048, ghidra_headless: str | None = None,
                 max_jobs: int = 16):
        if type(timeout) is not int or not 5 <= timeout <= 600:
            raise ValueError("timeout must be 5..600 seconds")
        if type(memory_mb) is not int or not 256 <= memory_mb <= 4096:
            raise ValueError("memory_mb must be 256..4096")
        if type(max_jobs) is not int or not 1 <= max_jobs <= 16:
            raise ValueError("max_jobs must be 1..16")
        self.grants, self.timeout, self.memory_mb = grants, timeout, memory_mb
        self.ghidra_headless, self.max_jobs = ghidra_headless, max_jobs
        self._jobs = {}
        self._lock = threading.RLock()
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="reverse-lab")
        self._closed = False

    def submit(self, file_id: str, backend: str = "basic") -> dict:
        if backend not in BACKENDS:
            raise ValueError("unsupported analysis backend")
        self.grants.resolve(file_id)
        # All job engines, including LIEF, are gated subprocesses.
        import psutil  # optional MCP extra; no import required by core CLI/GUI
        if sys.platform == "win32":
            import win32job  # fail closed without process-tree resource controls
        with self._lock:
            if self._closed:
                raise ValueError("analysis service stopped")
            now = time.monotonic()
            for key in list(self._jobs):
                job = self._jobs[key]
                if job["state"] not in ("queued", "running") and now - job["created"] > 1800:
                    del self._jobs[key]
            if len(self._jobs) >= self.max_jobs:
                raise ValueError("job capacity reached; restart service to clear transient results")
            job_id = secrets.token_hex(16)
            self._jobs[job_id] = {
                "id": job_id, "file_id": file_id, "backend": backend, "state": "queued",
                "created": now, "cancel": threading.Event(), "report": None,
            }
            self._pool.submit(self._run, job_id)
            return self.status(job_id)

    def _lookup(self, job_id: str) -> dict:
        job = self._jobs.get(job_id)
        if job is None:
            raise ValueError("unknown or expired analysis job")
        self.grants._entry(job["file_id"])  # recheck revocation/expiry on every access
        return job

    def status(self, job_id: str) -> dict:
        with self._lock:
            job = self._lookup(job_id)
            return {key: job[key] for key in ("id", "backend", "state")}

    def report(self, job_id: str) -> dict:
        with self._lock:
            job = self._lookup(job_id)
            if job["state"] != "completed":
                raise ValueError("analysis report is not ready")
            # Internal caller must project fields according to content permission.
            return job["report"]

    def permits_content(self, job_id: str) -> bool:
        with self._lock:
            job = self._lookup(job_id)
            return self.grants.permission(job["file_id"], "content")

    def cancel(self, job_id: str) -> dict:
        with self._lock:
            job = self._lookup(job_id)
            if job["state"] in ("queued", "running"):
                job["cancel"].set()
            return self.status(job_id)

    def _run(self, job_id: str):
        import psutil
        job = self._jobs[job_id]
        process = handle = None
        try:
            if job["cancel"].is_set():
                job["state"] = "cancelled"
                return
            job["state"] = "running"
            path = self.grants.resolve(job["file_id"])
            expected = self.grants._entry(job["file_id"])["sha256"]
            with ExitStack() as stack:
                directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="reverse-lab-job-"))
                work = Path(directory)
                target = work / "sample.bin"
                # Bounded copy + hash of the private snapshot closes source replacement races.
                with path.open("rb") as src, target.open("xb") as dst:
                    remaining = MAX_FILE_BYTES + 1
                    while remaining:
                        block = src.read(min(1024 * 1024, remaining))
                        if not block:
                            break
                        dst.write(block)
                        remaining -= len(block)
                if digest_file(target) != expected:
                    raise ValueError("source changed while copying")
                output = work / "result.json"
                request = work / "request.json"
                request.write_text(json.dumps({
                    "input": str(target), "output": str(output), "sha256": expected,
                    "memory_bytes": self.memory_mb * 1024 * 1024, "timeout": self.timeout,
                    "options": {"backend": job["backend"], "timeout": self.timeout,
                                "ghidra_headless": self.ghidra_headless,
                                "export_functions": True,
                                "export_pseudocode": job["backend"] == "ghidra",
                                "export_call_graph": job["backend"] == "ghidra"},
                }), encoding="utf-8")
                process = subprocess.Popen(
                    [sys.executable, "-m", "reverse_lab.job_worker", str(request)],
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    shell=False, start_new_session=sys.platform != "win32",
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
                )
                # LIFO: terminate descendants before deleting private temp files.
                stack.callback(lambda: _terminate(process, handle))
                if sys.platform == "win32":
                    handle = _windows_job(process, self.memory_mb * 1024 * 1024)
                process.stdin.write(b"1")
                process.stdin.close()
                deadline = time.monotonic() + self.timeout
                root = psutil.Process(process.pid)
                while process.poll() is None:
                    self.grants._entry(job["file_id"])
                    if job["cancel"].is_set():
                        job["state"] = "cancelled"
                        return
                    if time.monotonic() >= deadline:
                        job["state"] = "timed_out"
                        return
                    try:
                        memory = sum(p.memory_info().rss for p in [root] + root.children(recursive=True))
                    except psutil.NoSuchProcess:
                        memory = 0
                    if memory > self.memory_mb * 1024 * 1024:
                        job["state"] = "memory_limit"
                        return
                    if output.exists() and output.stat().st_size > 16 * 1024 * 1024:
                        raise ValueError("output limit")
                    job["cancel"].wait(0.05)
                if process.returncode != 0:
                    raise RuntimeError("worker failed")
                with output.open("rb") as stream:
                    raw = stream.read(16 * 1024 * 1024 + 1)
                if len(raw) > 16 * 1024 * 1024:
                    raise ValueError("output limit")
                from .reports import validate_report
                report = validate_report(json.loads(raw))
                if report["sha256"] != expected or report.get("analysis", {}).get("success") is False:
                    raise ValueError("invalid or failed engine report")
                self.grants._entry(job["file_id"])
                job["report"] = report
                job["state"] = "completed"
        except Exception:
            job["state"] = "failed"  # never retain private engine exception text
    def close(self):
        with self._lock:
            self._closed = True
            for job in self._jobs.values():
                job["cancel"].set()
        self._pool.shutdown(wait=True, cancel_futures=False)
        self._jobs.clear()
