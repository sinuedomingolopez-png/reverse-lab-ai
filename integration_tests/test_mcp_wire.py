"""Actual SDK clients, transports and worker. No mocked analysis engines.

HTTP tests use locally issued ephemeral test JWTs, not a real OAuth login.
They do not establish that a ChatGPT account is connected.
"""
import asyncio
import importlib.util
import json
import os
import socket
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from reverse_lab.authorizations import Authorizations
from reverse_lab.ghidra_probe import build_synthetic_elf


@unittest.skipUnless(importlib.util.find_spec("mcp"), "install .[mcp]")
class WireTests(unittest.IsolatedAsyncioTestCase):
    async def _analyze(self, client, file_id, engine="basic"):
        listing = await client.list_tools()
        self.assertEqual(len(listing.tools), 14)
        status = await client.call_tool("reverse_lab_status", {})
        self.assertTrue(status.structured_content["data"]["local_processing"])
        engines = await client.call_tool("list_analysis_engines", {})
        self.assertIn("ghidra", engines.structured_content["data"])
        authorized = await client.call_tool("list_authorized_files", {})
        self.assertIn(file_id, [f["id"] for f in authorized.structured_content["data"]["items"]])
        started = await client.call_tool("analyze_file", {"file_id": file_id, "engine": engine})
        self.assertFalse(started.is_error, str(started))
        self.assertIn("data", started.structured_content, str(started))
        job_id = started.structured_content["data"]["id"]
        for _ in range(3600):
            status = await client.call_tool("get_analysis_status", {"job_id": job_id})
            if status.structured_content["data"]["state"] not in ("running", "queued"):
                break
            await asyncio.sleep(0.05)
        self.assertEqual(status.structured_content["data"]["state"], "completed")
        report = await client.call_tool("get_analysis_report", {"job_id": job_id})
        self.assertEqual(report.structured_content["data"]["format"], "ELF")
        self.assertNotIn("stdout_tail", str(report))
        explanation = await client.call_tool("explain_analysis", {"job_id": job_id})
        self.assertEqual(explanation.structured_content["data"]["hypotheses"], [])
        return job_id

    async def test_stdio_real_client_and_optional_real_lief(self):
        from mcp import Client
        from mcp.client.stdio import StdioServerParameters
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "synthetic.elf"
            sample.write_bytes(build_synthetic_elf())
            manifest = root / "grants.json"
            item = Authorizations(manifest).grant(sample, root=root, content=True)
            params = StdioServerParameters(command=sys.executable,
                args=["-m", "reverse_lab.agent", "--manifest", str(manifest), "serve"],
                cwd=Path(__file__).resolve().parents[1],
                env={key: value for key, value in os.environ.items()
                     if key in ("TEMP", "TMP", "JAVA_HOME", "GHIDRA_HOME", "APPDATA", "LOCALAPPDATA", "PATH", "REVERSE_LAB_PYTHON")})
            async with Client(params, mode="legacy") as client:
                job_id = await self._analyze(client, item["id"])
                comparison = await client.call_tool("compare_reports", {"left_job_id": job_id, "right_job_id": job_id})
                self.assertTrue(comparison.structured_content["data"]["same_binary"])
                invalid = await client.call_tool("list_functions", {"job_id": job_id, "limit": 101})
                self.assertTrue(invalid.is_error)
                if importlib.util.find_spec("lief"):
                    lief_job = await self._analyze(client, item["id"], "lief")
                    sections = await client.call_tool("get_analysis_report", {"job_id": lief_job, "section": "sections"})
                    self.assertIn(".text", str(sections.structured_content))
                if shutil.which("rizin"):
                    await self._analyze(client, item["id"], "rizin")
                if os.environ.get("GHIDRA_HOME"):
                    ghidra_job = await self._analyze(client, item["id"], "ghidra")
                    functions = await client.call_tool("list_functions", {"job_id": ghidra_job})
                    entry = functions.structured_content["data"]["items"][0]["entry"]
                    code = await client.call_tool("get_pseudocode", {"job_id": ghidra_job, "entry": entry})
                    self.assertTrue(code.structured_content["data"]["available"])
                    details = await client.call_tool("inspect_function", {"job_id": ghidra_job, "entry": entry})
                    self.assertTrue(details.structured_content["data"]["available"])
                    calls = await client.call_tool("get_call_graph", {"job_id": ghidra_job})
                    self.assertGreaterEqual(calls.structured_content["data"]["total"], 1)
                    compared = await client.call_tool("compare_reports", {"left_job_id": ghidra_job,
                                                     "right_job_id": ghidra_job, "include_functions": True})
                    self.assertTrue(compared.structured_content["data"]["functions"]["comparable"])
                if importlib.util.find_spec("angr") or os.environ.get("REVERSE_LAB_PYTHON"):
                    angr_job = await self._analyze(client, item["id"], "angr")
                    graph = await client.call_tool("get_control_flow_graph", {"job_id": angr_job})
                    self.assertGreaterEqual(graph.structured_content["data"]["total"], 1)
                pending = await client.call_tool("analyze_file", {"file_id": item["id"]})
                cancelled = await client.call_tool("cancel_analysis", {"job_id": pending.structured_content["data"]["id"]})
                self.assertFalse(cancelled.is_error)

    async def test_http_authentication_discovery_scopes_and_analysis(self):
        import httpx2
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from mcp import Client
        from mcp.client.streamable_http import streamable_http_client
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "synthetic.elf"
            sample.write_bytes(build_synthetic_elf())
            manifest = root / "grants.json"
            item = Authorizations(manifest).grant(sample, root=root)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
            public["kid"] = "ephemeral-test"
            jwks = root / "jwks.json"
            jwks.write_text(json.dumps({"keys": [public]}), encoding="utf-8")
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            url = f"http://127.0.0.1:{port}/mcp"
            resource, issuer = "https://lab.example/mcp", "https://issuer.example/"
            command = [sys.executable, "-m", "reverse_lab.agent", "--manifest", str(manifest),
                       "serve", "--transport", "http", "--port", str(port), "--issuer", issuer,
                       "--resource-url", resource, "--jwks", str(jwks), "--owner-subject", "owner"]
            stop_file = root / "stop"
            command += ["--stop-file", str(stop_file)]
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                async with httpx2.AsyncClient(trust_env=False, timeout=5) as http:
                    for _ in range(100):
                        try:
                            unauth = await http.post(url, json={})
                            break
                        except httpx2.ConnectError:
                            self.assertIsNone(process.poll(), "HTTP service exited before ready")
                            await asyncio.sleep(0.05)
                    self.assertEqual(unauth.status_code, 401)
                    self.assertIn("resource_metadata", unauth.headers["WWW-Authenticate"])
                    discovery = await http.get(f"http://127.0.0.1:{port}/.well-known/oauth-protected-resource/mcp")
                    self.assertEqual(discovery.json()["resource"], resource)
                    self.assertIn("reverse:analyze", discovery.json()["scopes_supported"])
                    bad = await http.post(url, json={}, headers={"Authorization": "Bearer invalid"})
                    self.assertEqual(bad.status_code, 401)
                    claims = {"iss": issuer, "aud": resource, "sub": "owner", "client_id": "test-client",
                              "iat": int(time.time()), "exp": int(time.time()) + 120,
                              "scope": "reverse:read reverse:analyze"}
                    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "ephemeral-test"})
                    http.headers["Authorization"] = "Bearer " + token
                    async with Client(streamable_http_client(url, http_client=http), mode="legacy") as client:
                        advertised = await client.list_tools()
                        analyze_tool = next(tool for tool in advertised.tools if tool.name == "analyze_file")
                        self.assertIn("reverse:analyze", analyze_tool.meta["securitySchemes"][0]["scopes"])
                        job_id = await self._analyze(client, item["id"])
                        denied = await client.call_tool("cancel_analysis", {"job_id": job_id})
                        self.assertIn("error", denied.structured_content)
                        self.assertTrue(denied.is_error)
                        self.assertIn("insufficient_scope", denied.meta["mcp/www_authenticate"][0])
                        private = await client.call_tool("list_functions", {"job_id": job_id})
                        self.assertIn("error", private.structured_content)
                    jwks.write_text('{"keys": []}', encoding="utf-8")
                    revoked = await http.post(url, json={})
                    self.assertEqual(revoked.status_code, 401)
            finally:
                stop_file.write_text("stop", encoding="ascii")
                try:
                    self.assertEqual(process.wait(timeout=10), 0)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
