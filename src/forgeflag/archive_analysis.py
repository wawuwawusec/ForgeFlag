from __future__ import annotations

import gzip
from pathlib import Path
import tarfile
from typing import Any
import zipfile


INTERESTING_NAME_MARKERS = ("flag", "secret", "hint", "readme", "password", "key")


def analyze_archive(path: str | Path, limit: int = 80) -> dict[str, Any] | None:
    artifact = Path(path)
    if zipfile.is_zipfile(artifact):
        return _zip_summary(artifact, limit)
    if tarfile.is_tarfile(artifact):
        return _tar_summary(artifact, limit)
    if artifact.suffix.lower() in {".gz", ".gzip"} and _is_gzip(artifact):
        return _gzip_summary(artifact)
    return None


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
    lowered = name.lower()
    return any(marker in lowered for marker in INTERESTING_NAME_MARKERS)
