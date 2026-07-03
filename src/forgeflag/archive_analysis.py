from __future__ import annotations

import gzip
from pathlib import Path
import tarfile
from typing import Any
import zipfile


INTERESTING_NAME_MARKERS = (
    "flag",
    "secret",
    "key",
    "password",
    "cpassword",
    "groups.xml",
    "preferences",
    "policy",
    "hint",
    "readme",
)
DEFAULT_PREVIEW_BYTES = 64_000


def analyze_archive(path: str | Path, limit: int = 80) -> dict[str, Any] | None:
    artifact = Path(path)
    if zipfile.is_zipfile(artifact):
        return _zip_summary(artifact, limit)
    if tarfile.is_tarfile(artifact):
        return _tar_summary(artifact, limit)
    if artifact.suffix.lower() in {".gz", ".gzip"} and _is_gzip(artifact):
        return _gzip_summary(artifact)
    return None


def preview_archive_text(path: str | Path, limit: int = 20, max_bytes: int = DEFAULT_PREVIEW_BYTES) -> list[dict[str, Any]]:
    artifact = Path(path)
    if zipfile.is_zipfile(artifact):
        return _zip_text_previews(artifact, limit, max_bytes)
    if tarfile.is_tarfile(artifact):
        return _tar_text_previews(artifact, limit, max_bytes)
    if artifact.suffix.lower() in {".gz", ".gzip"} and _is_gzip(artifact):
        return _gzip_text_previews(artifact, max_bytes)
    return []


def _zip_summary(path: Path, limit: int) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    encrypted = False
    comments: list[str] = []
    with zipfile.ZipFile(path) as zf:
        if zf.comment:
            comments.append(zf.comment.decode("utf-8", errors="replace"))
        for info in zf.infolist()[:limit]:
            is_encrypted = bool(info.flag_bits & 0x1)
            encrypted = encrypted or is_encrypted
            entries.append(
                {
                    "name": info.filename,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "encrypted": is_encrypted,
                    "is_dir": info.is_dir(),
                }
            )
    return {
        "kind": "zip",
        "entries": entries,
        "entry_count": len(entries),
        "encrypted": encrypted,
        "comments": comments,
        "interesting_entries": _interesting_entries(entries),
    }


def _tar_summary(path: Path, limit: int) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    with tarfile.open(path) as tf:
        for member in tf.getmembers()[:limit]:
            entries.append(
                {
                    "name": member.name,
                    "size": member.size,
                    "is_dir": member.isdir(),
                    "type": member.type.decode("ascii", errors="replace") if isinstance(member.type, bytes) else str(member.type),
                }
            )
    return {
        "kind": "tar",
        "entries": entries,
        "entry_count": len(entries),
        "encrypted": False,
        "comments": [],
        "interesting_entries": _interesting_entries(entries),
    }


def _gzip_summary(path: Path) -> dict[str, Any]:
    name = path.name
    for suffix in (".gzip", ".gz"):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
            break
    return {
        "kind": "gzip",
        "entries": [{"name": name or path.stem, "size": None, "is_dir": False}],
        "entry_count": 1,
        "encrypted": False,
        "comments": [],
        "interesting_entries": [name] if _interesting_name(name) else [],
    }


def _zip_text_previews(path: Path, limit: int, max_bytes: int) -> list[dict[str, Any]]:
    previews: list[dict[str, Any]] = []
    with zipfile.ZipFile(path) as zf:
        entries = sorted(
            zf.infolist(),
            key=lambda info: (_interesting_rank(info.filename), info.filename),
        )
        for info in entries:
            if len(previews) >= limit:
                break
            if info.is_dir() or info.file_size > max_bytes or info.flag_bits & 0x1:
                continue
            try:
                raw = zf.read(info)
            except (RuntimeError, zipfile.BadZipFile):
                continue
            preview = _text_preview(raw)
            if preview:
                previews.append({"name": info.filename, "size": info.file_size, "text_preview": preview})
    return previews


def _tar_text_previews(path: Path, limit: int, max_bytes: int) -> list[dict[str, Any]]:
    previews: list[dict[str, Any]] = []
    with tarfile.open(path) as tf:
        entries = sorted(
            (member for member in tf.getmembers() if member.isfile()),
            key=lambda member: (_interesting_rank(member.name), member.name),
        )
        for member in entries:
            if len(previews) >= limit:
                break
            if member.size > max_bytes:
                continue
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            preview = _text_preview(extracted.read(max_bytes + 1))
            if preview:
                previews.append({"name": member.name, "size": member.size, "text_preview": preview})
    return previews


def _gzip_text_previews(path: Path, max_bytes: int) -> list[dict[str, Any]]:
    with gzip.open(path, "rb") as gz:
        preview = _text_preview(gz.read(max_bytes + 1))
    if not preview:
        return []
    name = path.name
    for suffix in (".gzip", ".gz"):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
            break
    return [{"name": name or path.stem, "size": None, "text_preview": preview}]


def _is_gzip(path: Path) -> bool:
    try:
        with gzip.open(path, "rb") as gz:
            gz.peek(1)
    except (OSError, EOFError, gzip.BadGzipFile):
        return False
    return True


def _interesting_entries(entries: list[dict[str, Any]]) -> list[str]:
    names = []
    for entry in entries:
        name = str(entry.get("name", ""))
        if _interesting_name(name):
            names.append(name)
    return names[:20]


def _interesting_name(name: str) -> bool:
    return _interesting_rank(name) < len(INTERESTING_NAME_MARKERS)


def _interesting_rank(name: str) -> int:
    lowered = name.lower()
    for index, marker in enumerate(INTERESTING_NAME_MARKERS):
        if marker in lowered:
            return index
    return len(INTERESTING_NAME_MARKERS)


def _text_preview(raw: bytes, limit: int = 500) -> str:
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="replace").replace("\x00", " ")
    printable = sum(1 for char in text if char.isprintable() or char.isspace())
    if printable / max(len(text), 1) < 0.85:
        return ""
    return " ".join(text.split())[:limit]
