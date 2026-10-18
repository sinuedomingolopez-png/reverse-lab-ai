"""Opt-in, bounded, local-only storage for complete analysis reports.

Reports may include recovered names, pseudocode and other sensitive data.
Nothing is saved automatically: callers MUST ask the user before calling save.
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .reports import validate_report

MAX_HISTORY_REPORT_BYTES = 4 * 1024 * 1024
MAX_HISTORY_RECORDS = 30
_ID = re.compile(r"^[a-f0-9]{32}$")
_SCHEMA = "reverse-lab-history-v1"


def default_history_directory() -> Path:
    """Use the current user's application-data directory, not the EXE folder."""
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or
                    Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or
                    Path.home() / ".local" / "share")
    return base / "ReverseLabAI" / "history"


class HistoryStore:
    def __init__(self, directory: str | Path | None = None, *,
                 max_records: int = MAX_HISTORY_RECORDS) -> None:
        if type(max_records) is not int or not 1 <= max_records <= 100:
            raise ValueError("max_records must be between 1 and 100")
        self.directory = (Path(directory) if directory is not None
                          else default_history_directory())
        self.max_records = max_records

    def _item_path(self, item_id: str) -> Path:
        if not isinstance(item_id, str) or not _ID.fullmatch(item_id):
            raise ValueError("Identificador de historial no válido")
        return self.directory / (item_id + ".json")

    def _read(self, path: Path) -> dict:
        if path.is_symlink():
            raise ValueError("El historial no permite enlaces simbólicos")
        if not path.is_file():
            raise FileNotFoundError(path)
        if path.stat().st_size > MAX_HISTORY_REPORT_BYTES:
            raise ValueError("Un informe del historial supera 4 MiB")
        with path.open("rb") as stream:
            data = stream.read(MAX_HISTORY_REPORT_BYTES + 1)
        if len(data) > MAX_HISTORY_REPORT_BYTES:
            raise ValueError("Un informe del historial supera 4 MiB")
        try:
            item = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("Informe del historial dañado o no válido") from exc
        if not isinstance(item, dict) or item.get("schema") != _SCHEMA:
            raise ValueError("Formato de historial incompatible")
        saved_at = item.get("saved_at")
        if not isinstance(saved_at, str) or not saved_at:
            raise ValueError("Historial sin fecha de guardado")
        validate_report(item.get("report"))
        return item

    @staticmethod
    def _metadata(item_id: str, data: dict) -> dict:
        report = data["report"]
        analysis = report.get("analysis", {})
        backend = analysis.get("backend", "basic")
        if not isinstance(backend, str):
            backend = "unknown"
        return {
            "id": item_id,
            "saved_at": data["saved_at"],
            "filename": report["filename"][:180],
            "backend": backend[:40],
            "format": report["format"][:60],
            "sha256": report["sha256"],
        }

    def list_entries(self) -> list[dict]:
        """List stored reports without creating a directory or changing files."""
        if not self.directory.exists():
            return []
        if self.directory.is_symlink() or not self.directory.is_dir():
            raise ValueError("La carpeta del historial no es segura")
        entries = []
        for path in self.directory.glob("*.json"):
            item_id = path.stem
            if not _ID.fullmatch(item_id) or path.is_symlink():
                continue
            try:
                data = self._read(path)
            except (ValueError, OSError):
                continue  # A corrupt record never prevents opening other records.
            entries.append(self._metadata(item_id, data))
        entries.sort(key=lambda item: (item["saved_at"], item["id"]), reverse=True)
        return entries

    def save(self, report: dict) -> dict:
        """Persist a complete report only after explicit user consent."""
        validate_report(report)
        item = {
            "schema": _SCHEMA,
            "saved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "report": report,
        }
        try:
            serialized = (json.dumps(item, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("El informe no puede serializarse en JSON") from exc
        if len(serialized) > MAX_HISTORY_REPORT_BYTES:
            raise ValueError("El informe supera el límite de 4 MiB del historial")
        if len(self.list_entries()) >= self.max_records:
            raise ValueError("El historial está lleno; borra entradas antes de guardar otra")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.directory.is_symlink():
            raise ValueError("La carpeta del historial no es segura")
        item_id = uuid.uuid4().hex
        final = self._item_path(item_id)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=self.directory, prefix=".pending-",
                suffix=".tmp", delete=False,
            ) as stream:
                temp_path = Path(stream.name)
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, final)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
        return self._metadata(item_id, item)

    def load(self, item_id: str) -> dict:
        """Load only a UUID-named record within the local history directory."""
        return self._read(self._item_path(item_id))["report"]

    def delete(self, item_id: str) -> bool:
        """Delete only an explicitly specified report, never external files."""
        path = self._item_path(item_id)
        if path.is_symlink():
            raise ValueError("El historial no permite enlaces simbólicos")
        if not path.is_file():
            return False
        path.unlink()
        return True
