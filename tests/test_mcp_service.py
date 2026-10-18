import asyncio
import importlib.util
import tempfile
import unittest
from pathlib import Path

from reverse_lab.analysis_jobs import AnalysisJobs
from reverse_lab.authorizations import Authorizations


@unittest.skipUnless(importlib.util.find_spec("mcp"), "optional official MCP SDK")
class MCPServiceTests(unittest.IsolatedAsyncioTestCase):
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
                    self.assertEqual(len(names), 13)
                    self.assertIn("analyze_file", names)
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
