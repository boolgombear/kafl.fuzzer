from __future__ import annotations

"""Helper utilities for mutating OOXML (ZIP-based) containers."""

import copy
import io
import zipfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

ZipEntry = Tuple[zipfile.ZipInfo, bytes]


class OOXMLAdapter:
    """Wraps mutation payloads into OOXML archives while targeting specific members."""

    def __init__(
        self,
        template_path: str,
        entry_paths: Optional[Iterable[str]] = None,
        *,
        max_payload: Optional[int] = None,
    ) -> None:
        path = Path(template_path)
        if not path.is_file():
            raise FileNotFoundError(f"OOXML template not found: {template_path}")

        self.template_bytes = path.read_bytes()
        if max_payload is not None and len(self.template_bytes) > max_payload:
            raise ValueError(
                "OOXML template size exceeds harness payload limit: "
                f"{len(self.template_bytes)} > {max_payload}"
            )

        if entry_paths is None:
            entries = []
        elif isinstance(entry_paths, str):
            entries = [entry_paths]
        else:
            entries = list(entry_paths)
        if not entries:
            raise ValueError("At least one --ooxml-entry must be supplied when using --ooxml-template")
        if len(entries) > 1:
            # multiple targets could be supported later, but current pipeline expects one
            raise ValueError("Multiple --ooxml-entry values are not supported yet")

        self.entry_path = entries[0]
        self.template_context = self._load_entries(self.template_bytes)
        if self.entry_path not in self.template_context:
            raise ValueError(
                f"Entry '{self.entry_path}' not present in OOXML template {template_path}"
            )

    @staticmethod
    def is_archive(data: Optional[bytes]) -> bool:
        if not data or len(data) < 4:
            return False
        return data[:4] == b"PK\x03\x04"

    def template_context_copy(self) -> Dict[str, ZipEntry]:
        return {
            name: (self._clone_zipinfo(info), data)
            for name, (info, data) in self.template_context.items()
        }

    def context_from_bytes(self, archive_bytes: bytes) -> Dict[str, ZipEntry]:
        context = self._load_entries(archive_bytes)
        if self.entry_path not in context:
            raise ValueError(
                f"OOXML archive missing required entry '{self.entry_path}'"
            )
        return context

    def extract_entry_from_context(self, context: Dict[str, ZipEntry]) -> bytes:
        return context[self.entry_path][1]

    def extract_entry(self, archive_bytes: bytes) -> bytes:
        return self.extract_entry_from_context(self.context_from_bytes(archive_bytes))

    def spawn_mutation_base(self, archive_bytes: bytes) -> bytes:
        try:
            return self.extract_entry(archive_bytes)
        except (FileNotFoundError, ValueError):
            return archive_bytes

    def build_archive(
        self,
        entry_data: bytes,
        context: Optional[Dict[str, ZipEntry]] = None,
    ) -> bytes:
        source = context if context is not None else self.template_context
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, (info, data) in source.items():
                payload = entry_data if name == self.entry_path else data
                archive.writestr(self._clone_zipinfo(info), payload)
        return buffer.getvalue()

    def _load_entries(self, archive_bytes: bytes) -> Dict[str, ZipEntry]:
        result: Dict[str, ZipEntry] = {}
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            for info in archive.infolist():
                info_copy = self._clone_zipinfo(info)
                if info_copy.is_dir():
                    data = b""
                else:
                    data = archive.read(info.filename)
                result[info.filename] = (info_copy, data)
        return result

    @staticmethod
    def _clone_zipinfo(info: zipfile.ZipInfo) -> zipfile.ZipInfo:
        # zipfile.ZipInfo lacks a public clone helper; replicate the relevant fields.
        clone = copy.copy(info)
        clone.compress_size = 0
        clone.file_size = 0
        clone.CRC = 0
        return clone
