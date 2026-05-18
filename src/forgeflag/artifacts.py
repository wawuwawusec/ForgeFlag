from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Artifact:
    challenge_id: str
    original_path: str
    workspace_path: Path

    @property
    def name(self) -> str:
        return self.workspace_path.name


class ArtifactWorkspace:
    def __init__(self, root: str | Path = ".forgeflag/artifacts") -> None:
        self.root = Path(root)

    def challenge_dir(self, challenge_id: str) -> Path:
        safe_id = _safe_name(challenge_id)
        path = self.root / safe_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def register_file(self, challenge_id: str, source: str | Path) -> Artifact:
        source_path = Path(source).expanduser().resolve()
        if not source_path.is_file():
            raise FileNotFoundError(f"artifact not found: {source_path}")

        destination = self._available_destination(challenge_id, _safe_name(source_path.name))
        shutil.copy2(source_path, destination)
        return Artifact(
            challenge_id=challenge_id,
            original_path=str(source_path),
            workspace_path=destination,
        )

    def _available_destination(self, challenge_id: str, filename: str) -> Path:
        directory = self.challenge_dir(challenge_id)
        candidate = directory / filename
        if not candidate.exists():
            return candidate

        stem = candidate.stem
        suffix = candidate.suffix
        index = 2
        while True:
            numbered = directory / f"{stem}-{index}{suffix}"
            if not numbered.exists():
                return numbered
            index += 1


def _safe_name(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in ("-", "_", ".") else "_" for char in value.strip())
    cleaned = cleaned.strip("._")
    return cleaned or "artifact"
