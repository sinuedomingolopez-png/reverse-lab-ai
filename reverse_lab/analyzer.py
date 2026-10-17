"""Minimal, safe static file analyzer."""
from __future__ import annotations

import hashlib
from pathlib import Path


def detect_format(header: bytes) -> str:
    if header.startswith(b"\\x7fELF"):
        return "ELF"
    if header.startswith(b"MZ"):
        return "PE (possible)"
    if header.startswith(b"\\x00asm"):
        return "WebAssembly"
    if header.startswith(b"PK\\x03\\x04"):
        return "ZIP"
    if header[:4] in (
        bytes.fromhex("feedface"), bytes.fromhex("cefaedfe"),
        bytes.fromhex("feedfacf"), bytes.fromhex("cffaedfe"),
        bytes.fromhex("cafebabe"), bytes.fromhex("bebafeca"),
    ):
        return "Mach-O (possible)"
    return "unknown"


def inspect_file(path: str | Path) -> dict[str, str | int]:
    candidate = Path(path)
    digest = hashlib.sha256()
    size = 0
    with candidate.open("rb") as stream:
        header = stream.read(16)
        digest.update(header)
        size += len(header)
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return {
        "filename": candidate.name,
        "size_bytes": size,
        "sha256": digest.hexdigest(),
        "format": detect_format(header),
    }
