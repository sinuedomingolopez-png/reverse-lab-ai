import asyncio
import importlib.util
import tempfile
import unittest
from pathlib import Path

from reverse_lab.analysis_jobs import AnalysisJobs
from reverse_lab.authorizations import Authorizations


@unittest.skipUnless(importlib.util.find_spec("mcp"), "optional official MCP SDK")
class MCPServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_unicode_content_cannot_exceed_wire_response_budget(self):
        from mcp import Client
        from reverse_lab.mcp_server import create_server
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "fixture"
            sample.write_bytes(b"inert")
            grants = Authorizations(root / "grants.json")
            item = grants.grant(sample, root=root, content=True)
            jobs = AnalysisJobs(grants)
            try:
                started = jobs.submit(item["id"])
                for _ in range(100):
                    if jobs.status(started["id"])["state"] == "completed":
                        break
                    await asyncio.sleep(0.05)
                # Contract fixture for hostile engine output, not an engine test.
                jobs.report(started["id"])["analysis"] = {"functions": [
                    {"name": "\U0001f642" * 180, "entry": hex(0x401000 + i)} for i in range(100)]}
                async with Client(create_server(jobs)) as client:
                    result = await client.call_tool("list_functions", {"job_id": started["id"], "limit": 100})
                    self.assertTrue(result.is_error)
                    self.assertEqual(result.structured_content["error"], "response_limit")
                    small = await client.call_tool("list_functions", {"job_id": started["id"], "limit": 1})
                    self.assertFalse(small.is_error)
                    self.assertLessEqual(len(small.model_dump_json(by_alias=True).encode()), 65536)
            finally:
                jobs.close()

    async def test_real_sdk_contract_and_analysis(self):
        from mcp import Client
        from reverse_lab.mcp_server import create_server
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.bin"
            sample.write_bytes(b"authorized static fixture")
            grants = Authorizations(root / "grants.json")
            item = grants.grant(sample, root=root)
            jobs = AnalysisJobs(grants)
            try:
                async with Client(create_server(jobs)) as client:
                    tools = await client.list_tools()
                    names = {tool.name for tool in tools.tools}
                    self.assertEqual(len(names), 14)
                    self.assertIn("analyze_file", names)
                    descriptor = next(tool for tool in tools.tools if tool.name == "analyze_file")
                    self.assertEqual(set(descriptor.output_schema["required"]), {"schema", "trust", "data"})
                    start = await client.call_tool("analyze_file", {"file_id": item["id"]})
                    job_id = start.structured_content["data"]["id"]
                    for _ in range(100):
                        response = await client.call_tool("get_analysis_status", {"job_id": job_id})
                        if response.structured_content["data"]["state"] not in ("queued", "running"):
                            break
                        await asyncio.sleep(0.05)
                    self.assertEqual(response.structured_content["data"]["state"], "completed")
                    report = await client.call_tool("get_analysis_report", {"job_id": job_id})
                    self.assertEqual(report.structured_content["data"]["sha256"], item["sha256"])
                    denied = await client.call_tool("list_functions", {"job_id": job_id})
                    self.assertIn("error", denied.structured_content)
                    self.assertNotIn(str(root), str(report))
            finally:
                jobs.close()
