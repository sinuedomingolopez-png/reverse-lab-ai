"""Local-only file grants. Never expose mutation methods as MCP tools."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
import time
from pathlib import Path
from contextlib import contextmanager

MAX_FILE_BYTES = 32 * 1024 * 1024


def digest_file(path: Path, max_bytes: int = MAX_FILE_BYTES) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(block)
            if total > max_bytes:
                raise ValueError("file exceeds authorized size limit")
            digest.update(block)
    return digest.hexdigest()


class Authorizations:
    """A private manifest editable only from the local CLI/UI by the owner.

    Local malicious processes with the user's permissions are outside this trust
    boundary. Place the manifest in a private user directory, outside sample roots.
    """

    def __init__(self, manifest: str | Path):
        self.manifest = Path(manifest).resolve()

    def _read(self) -> dict:
        if not self.manifest.exists():
            return {"schema": "reverse-lab-grants-v1", "files": {}}
        with self.manifest.open("rb") as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError("authorization manifest too large")
        result = json.loads(data)
        if result.get("schema") != "reverse-lab-grants-v1" or not isinstance(result.get("files"), dict):
            raise ValueError("invalid authorization manifest")
        return result

    def _write(self, data: dict) -> None:
        self.manifest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        name = None
        try:
            with tempfile.NamedTemporaryFile(dir=self.manifest.parent, mode="w",
                                             encoding="utf-8", delete=False) as stream:
                name = stream.name
                json.dump(data, stream, ensure_ascii=False, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.manifest)
        finally:
            if name:
                Path(name).unlink(missing_ok=True)

    @contextmanager
    def _transaction(self):
        """Serialize owner mutations across CLI processes and GUI instances.

        Keep the lock in a separate inode: atomic manifest replacement must not
        replace the object being locked. Readers see old or new complete JSON.
        """
        self.manifest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with Path(str(self.manifest) + ".lock").open("a+b") as lock:
            if os.fstat(lock.fileno()).st_size == 0:
                lock.write(b"\0")
                lock.flush()
            deadline = time.monotonic() + 5
            while True:
                try:
                    lock.seek(0)
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise ValueError("another local authorization update is in progress")
                    time.sleep(0.02)
            try:
                yield
            finally:
                lock.seek(0)
                if os.name == "nt":
                    msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def grant(self, target: str | Path, *, root: str | Path,
              content: bool = False, max_bytes: int = MAX_FILE_BYTES,
              lifetime: int = 3600) -> dict:
        if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_FILE_BYTES:
            raise ValueError("max_bytes must be 1..32 MiB")
        if type(lifetime) is not int or not 60 <= lifetime <= 86400:
            raise ValueError("grant lifetime must be 60..86400 seconds")
        path = Path(target).resolve(strict=True)
        allowed = Path(root).resolve(strict=True)
        if not allowed.is_dir() or not path.is_file() or not path.is_relative_to(allowed):
            raise ValueError("file is outside the allowed directory")
        sha256 = digest_file(path, max_bytes)
        item_id = secrets.token_hex(16)
        with self._transaction():
            data = self._read()
            if len(data["files"]) >= 100:
                raise ValueError("revoke old grants before authorizing more files")
            data["files"][item_id] = {
                "path": str(path), "root": str(allowed), "sha256": sha256,
                "max_bytes": max_bytes, "content": content,
                "expires_at": time.time() + lifetime,
            }
            self._write(data)
        return {"id": item_id, "sha256": sha256, "content": content}

    def _entry(self, file_id: str) -> dict:
        if not isinstance(file_id, str) or len(file_id) != 32:
            raise ValueError("file is not authorized")
        item = self._read()["files"].get(file_id)
        if not item or item["expires_at"] <= time.time():
            raise ValueError("file grant is absent, expired or revoked")
        return item

    def resolve(self, file_id: str) -> Path:
        item = self._entry(file_id)
        path = Path(item["path"]).resolve(strict=True)
        root = Path(item["root"]).resolve(strict=True)
        if not path.is_file() or not path.is_relative_to(root):
            raise ValueError("authorized path is no longer allowed")
        if digest_file(path, item["max_bytes"]) != item["sha256"]:
            raise ValueError("authorized file changed; renew local permission")
        return path

    def permission(self, file_id: str, operation: str) -> bool:
        item = self._entry(file_id)
        return operation == "metadata" or (operation == "content" and item["content"] is True)

    def list_files(self) -> list[dict]:
        # Opaque IDs and explicit hashes only. No paths or names cross MCP here.
        return [{"id": key, "sha256": value["sha256"], "content": value["content"]}
                for key, value in self._read()["files"].items()
                if value["expires_at"] > time.time()]

    def revoke(self, file_id: str) -> None:
        with self._transaction():
            data = self._read()
            data["files"].pop(file_id, None)
            self._write(data)
