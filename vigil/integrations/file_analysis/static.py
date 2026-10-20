from __future__ import annotations

import hashlib
import mimetypes
from pathlib import Path


class StaticFileAnalyzer:
    """Reads bytes only. It never imports, launches, extracts, or interprets the sample."""

    def __init__(self, allowed_root: Path, max_bytes: int = 5 * 1024 * 1024) -> None:
        self.allowed_root = allowed_root.resolve()
        self.max_bytes = max_bytes

    def analyze(self, requested: str) -> dict:
        candidate = Path(requested)
        if not candidate.is_absolute():
            candidate = self.allowed_root / candidate
        if candidate.is_symlink():
            raise PermissionError("symbolic links are not accepted for analysis")
        resolved = candidate.resolve(strict=True)
        if resolved != self.allowed_root and self.allowed_root not in resolved.parents:
            raise PermissionError("file is outside the configured analysis directory")
        if not resolved.is_file():
            raise ValueError("analysis target is not a regular file")
        size = resolved.stat().st_size
        if size > self.max_bytes:
            raise ValueError(f"file exceeds {self.max_bytes} byte limit")
        digest = hashlib.sha256()
        first = b""
        with resolved.open("rb") as stream:
            while chunk := stream.read(65536):
                if not first:
                    first = chunk[:16]
                digest.update(chunk)
        signatures = {b"MZ": "PE executable header", b"\x7fELF": "ELF executable header", b"PK\x03\x04": "ZIP container header"}
        magic = next((label for prefix, label in signatures.items() if first.startswith(prefix)), "unrecognized/plain data")
        return {"sha256": digest.hexdigest(), "size": size, "mime_guess": mimetypes.guess_type(resolved.name)[0] or "application/octet-stream", "magic": magic, "filename": resolved.name, "executed": False}

