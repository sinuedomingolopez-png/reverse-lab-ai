"""Authentic optional engines, exclusively on generated non-executed inputs."""
import importlib.util
import os
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from reverse_lab.ghidra_probe import build_synthetic_elf, discover_ghidra
from reverse_lab.workflow import analyze


class RealEngines(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec("lief"), "real LIEF not installed")
    def test_lief_elf_pe_and_macho(self):
        import lief
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf = root / "generated.elf"
            elf.write_bytes(build_synthetic_elf())
            binary = lief.PE.Factory.create(lief.PE.PE_TYPE.PE32_PLUS)
            section = lief.PE.Section(".text")
            section.content = [0xC3]
            section.virtual_size = 1
            section.sizeof_raw_data = 512
            section.characteristics = 0x60000020
            binary.add_section(section)
            pe = root / "generated.exe"
            pe_binary = binary.get()
            pe_binary.add_import("KERNEL32.dll").add_entry("ExitProcess")
            exports = lief.PE.Export()
            exports.name = "generated.dll"
            exports.add_entry("synthetic_helper", 0x1000)
            pe_binary.set_export(exports)
            config = lief.PE.Builder.config_t()
            config.imports = True
            config.exports = True
            pe_binary.write(pe, config)
            macho = root / "generated.macho"
            header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x1000007, 3, 2, 1, 152, 0, 0)
            segment = struct.pack("<II16sQQQQiiII", 0x19, 152, b"__TEXT", 0x100000000,
                                  4096, 0, 256, 7, 5, 1, 0)
            section = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT", 0x1000000F0,
                                  1, 240, 0, 0, 0, 0x80000400, 0, 0, 0)
            prefix = header + segment + section
            macho.write_bytes(prefix + bytes(240 - len(prefix)) + b"\xc3" + bytes(15))
            for path, name in ((elf, ".text"), (pe, ".text"), (macho, "__text")):
                report = analyze(path, backend="lief")["analysis"]
                self.assertTrue(report["recognized"])
                self.assertIn(name, [s["name"] for s in report["sections"]])
                self.assertIsInstance(report["imports"], list)
                self.assertIsInstance(report["exports"], list)
                if path == pe:
                    self.assertIn("ExitProcess", report["imports"])
                    self.assertIn("KERNEL32.dll", report["libraries"])
                    self.assertIn("synthetic_helper", report["exports"])

    @unittest.skipUnless(shutil.which("rizin") and shutil.which("rz-bin"), "real Rizin absent")
    def test_rizin_discovers_two_functions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "generated.elf"
            path.write_bytes(build_synthetic_elf())
            report = analyze(path, backend="rizin", export_functions=True)["analysis"]
            self.assertIn("0x401000", [f["entry"] for f in report["functions"]])
            self.assertIn("0x40100a", [f["entry"] for f in report["functions"]])

    @unittest.skipUnless(discover_ghidra(), "real Ghidra absent")
    def test_ghidra_functions_pseudocode_and_call(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "generated.elf"
            path.write_bytes(build_synthetic_elf())
            report = analyze(path, backend="ghidra", ghidra_headless=str(discover_ghidra()),
                             export_functions=True, export_pseudocode=True,
                             export_call_graph=True)["analysis"]
            self.assertTrue(report["success"], report.get("stderr_tail"))
            self.assertGreaterEqual(len(report["functions"]), 2)
            self.assertTrue(any(p.get("pseudocode") for p in report["pseudocode"]))
            self.assertTrue(any(int(e["caller"]["entry"], 16) == 0x401000 and
                                int(e["callee"]["entry"], 16) == 0x40100A
                                for e in report["call_graph"]))

    @unittest.skipUnless(importlib.util.find_spec("angr") or os.environ.get("REVERSE_LAB_PYTHON"), "real angr absent")
    def test_angr_cfgfast(self):
        from reverse_lab.engine_probe import probe_engine
        self.assertEqual(probe_engine("angr", timeout=120)["status"], "passed")
