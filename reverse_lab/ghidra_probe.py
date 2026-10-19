"""Optional Ghidra self-test with a locally generated, non-executed ELF fixture.

No executable is downloaded, launched, or uploaded. Ghidra itself runs as an
external analyzer only when a local installation is explicitly available.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import tempfile
from pathlib import Path


# x86-64: call helper; xor eax,eax; ret; padding; helper: mov eax,42; ret.
_TEST_CODE = bytes.fromhex("e8 05 00 00 00 31 c0 c3 90 90 b8 2a 00 00 00 c3")


def build_synthetic_elf() -> bytes:
    """Construct a deterministic 64-bit ELF with an entry point and two functions."""
    text_offset = 0x1000
    text_address = 0x401000
    strings = b"\0.text\0.shstrtab\0"
    string_offset = text_offset + len(_TEST_CODE)
    sections_offset = (string_offset + len(strings) + 15) & ~15
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH", ident, 2, 62, 1, text_address,
        64, sections_offset, 0, 64, 56, 1, 64, 3, 2,
    )
    segment = struct.pack(
        "<IIQQQQQQ", 1, 5, text_offset, text_address, text_address,
        len(_TEST_CODE), len(_TEST_CODE), 0x1000,
    )
    text_section = struct.pack(
        "<IIQQQQIIQQ", 1, 1, 6, text_address, text_offset,
        len(_TEST_CODE), 0, 0, 16, 0,
    )
    strings_section = struct.pack(
        "<IIQQQQIIQQ", 7, 3, 0, 0, string_offset, len(strings), 0, 0, 1, 0,
    )
    prefix = header + segment
    return (prefix + bytes(text_offset - len(prefix)) + _TEST_CODE + strings
            + bytes(sections_offset - string_offset - len(strings))
            + bytes(64) + text_section + strings_section)


def discover_ghidra(explicit: str | Path | None = None) -> Path | None:
    """Find a local Ghidra headless launcher without running or installing tools."""
    name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    if explicit is not None:
        path = Path(explicit).expanduser()
        if path.is_dir():
            path = path / "support" / name
        return path.resolve() if path.is_file() else None
    candidates: list[Path] = []
    for key in ("GHIDRA_HOME", "GHIDRA_INSTALL_DIR"):
        home = os.environ.get(key)
        if home:
            candidates.append(Path(home).expanduser() / "support" / name)
    found = shutil.which(name) or shutil.which("analyzeHeadless")
    if found:
        candidates.append(Path(found))
    for path in candidates:
        if path.is_file():
            return path.resolve()
    return None


def ghidra_selftest(
    *, launcher: str | Path | None = None, timeout: int = 360,
    check_only: bool = False,
) -> dict:
    """Inspect an inert synthetic ELF using a real local Ghidra installation.

    Status passed means the expected JSON exports were produced and validated;
    it does not prove the recovered code is semantically accurate.
    """
    if not 30 <= timeout <= 3600:
        raise ValueError("timeout must be between 30 and 3600 seconds")
    executable = discover_ghidra(launcher)
    report = {
        "tool": "ghidra", "status": "missing",
        "launcher": str(executable) if executable else None,
        "checks": {"ghidra_available": bool(executable)},
        "counts": {}, "warnings": [],
    }
    if executable is None:
        report["error"] = ("No se encuentra analyzeHeadless. Instala Ghidra y usa "
                           "--ghidra-headless RUTA o configura GHIDRA_HOME.")
        return report
    if check_only:
        report["status"] = "available"
        return report

    from .integrations.ghidra_adapter import analyze_with_ghidra
    sample = build_synthetic_elf()
    report["checks"]["synthetic_elf_created"] = sample[:4] == b"\x7fELF"
    report["sample_sha256"] = hashlib.sha256(sample).hexdigest()
    with tempfile.TemporaryDirectory(prefix="reverse-lab-selftest-") as directory:
        target = Path(directory) / "synthetic_reverse_lab.elf"
        target.write_bytes(sample)
        try:
            result = analyze_with_ghidra(
                target, executable, timeout=timeout,
                export_functions=True, max_functions=300,
                export_pseudocode=True, pseudocode_max_functions=10,
                pseudocode_max_chars=2000, pseudocode_timeout=6,
                export_call_graph=True, call_graph_max_callers=100,
                call_graph_max_edges=200,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            report["status"] = "failed"
            report["error"] = f"Ghidra no pudo completar la autoprueba: {exc}"[:700]
            return report

    report["checks"]["analysis_success"] = result.get("success") is True
    for key in ("functions", "pseudocode", "call_graph"):
        entries = result.get(key)
        counter = {
            "functions": "function_count", "pseudocode": "pseudocode_count",
            "call_graph": "call_graph_count",
        }[key]
        valid = (isinstance(entries, list) and len(entries) > 0 and
                 result.get(counter, len(entries)) == len(entries))
        if key == "pseudocode" and isinstance(entries, list):
            valid = valid and any(isinstance(item.get("pseudocode"), str)
                                  and item["pseudocode"].strip() for item in entries)
        report["checks"][f"{key}_export_valid"] = bool(valid)
        if isinstance(entries, list):
            report["counts"][key] = len(entries)
            if not entries:
                report["warnings"].append(
                    f"La exportación {key} está vacía; Ghidra puede no detectar todas las funciones.")
    if all(report["checks"].values()):
        report["status"] = "passed"
    else:
        report["status"] = "failed"
        report["error"] = str(result.get("error") or result.get("stderr_tail") or
                              "Ghidra no generó todas las salidas esperadas.")[-700:]
    return report


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Autoprueba de Ghidra con un ELF sintético inerte")
    parser.add_argument("--ghidra-headless", help="Ruta del lanzador o instalación de Ghidra")
    parser.add_argument("--timeout", type=int, default=360)
    parser.add_argument("--check-only", action="store_true", help="Solo detectar Ghidra")
    parser.add_argument("--output", type=Path, help="Guardar el diagnóstico en JSON")
    args = parser.parse_args(argv)
    result = ghidra_selftest(launcher=args.ghidra_headless, timeout=args.timeout,
                             check_only=args.check_only)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    if result["status"] not in ("passed", "available"):
        raise SystemExit(2 if result["status"] == "missing" else 1)


if __name__ == "__main__":
    main()
