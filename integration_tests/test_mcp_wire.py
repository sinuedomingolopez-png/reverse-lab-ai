"""Actual SDK clients, transports and worker. No mocked analysis engines.

HTTP tests use locally issued ephemeral test JWTs, not a real OAuth login.
They do not establish that a ChatGPT account is connected.
"""
import asyncio
import importlib.util
import json
import os
import socket
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
        self.assertEqual(len(listing.tools), 13)
        started = await client.call_tool("analyze_file", {"file_id": file_id, "engine": engine})
        self.assertFalse(started.is_error, str(started))
        self.assertIn("data", started.structured_content, str(started))
        job_id = started.structured_content["data"]["id"]
        for _ in range(200):
            status = await client.call_tool("get_analysis_status", {"job_id": job_id})
            if status.structured_content["data"]["state"] not in ("running", "queued"):
                break
            await asyncio.sleep(0.05)
        self.assertEqual(status.structured_content["data"]["state"], "completed")
        report = await client.call_tool("get_analysis_report", {"job_id": job_id})
        self.assertEqual(report.structured_content["data"]["format"], "ELF")
        self.assertNotIn("stdout_tail", str(report))
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
                env={"TEMP": os.environ.get("TEMP", directory), "TMP": os.environ.get("TMP", directory)})
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
                        job_id = await self._analyze(client, item["id"])
                        denied = await client.call_tool("cancel_analysis", {"job_id": job_id})
                        self.assertIn("error", denied.structured_content)
                        private = await client.call_tool("list_functions", {"job_id": job_id})
                        self.assertIn("error", private.structured_content)
                    jwks.write_text('{"keys": []}', encoding="utf-8")
                    revoked = await http.post(url, json={})
                    self.assertEqual(revoked.status_code, 401)
            finally:
                process.terminate()
                process.wait(timeout=10)
