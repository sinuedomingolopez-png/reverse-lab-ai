"""Safe static file inspection, without executing the target."""
from __future__ import annotations

import hashlib
from pathlib import Path


def detect_format(header: bytes) -> str:
    if header.startswith(bytes.fromhex("7f454c46")):
        return "ELF"
    if header.startswith(b"MZ"):
        return "PE (possible)"
    if header.startswith(bytes.fromhex("0061736d")):
        return "WebAssembly"
    if header.startswith(bytes.fromhex("504b0304")):
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
