from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Protocol

from forgeflag.domain import ChallengeCategory


@dataclass(frozen=True)
class KnowledgeBlock:
    source: str
    title: str
    category: ChallengeCategory
    content: str


class NotebookLike(Protocol):
    def list_challenges(self): ...
    def latest_run_summary(self, challenge_id: str): ...


_CATEGORY_LABELS = {
    "web": ChallengeCategory.WEB,
    "crypto": ChallengeCategory.CRYPTO,
    "forensics": ChallengeCategory.FORENSICS,
    "forensics and stego": ChallengeCategory.FORENSICS,
    "traffic": ChallengeCategory.TRAFFIC,
    "reverse": ChallengeCategory.REVERSE,
    "pwn": ChallengeCategory.PWN,
    "misc / programming": ChallengeCategory.MISC,
    "misc": ChallengeCategory.MISC,
    "universal triage": ChallengeCategory.UNKNOWN,
}


def default_playbook_path() -> Path:
    return Path(__file__).resolve().parents[2] / "docs" / "ctf-playbook.md"


def load_playbook_blocks(path: str | Path | None = None) -> list[KnowledgeBlock]:
    playbook = Path(path) if path else default_playbook_path()
    if not playbook.is_file():
        return []
    text = playbook.read_text(encoding="utf-8")
    blocks: list[KnowledgeBlock] = []
    matches = list(re.finditer(r"^###\s+(.+?)\s*$", text, flags=re.MULTILINE))
    for index, match in enumerate(matches):
        title = match.group(1).strip()
        if "method card" not in title.lower() and title.lower() != "universal triage":
            continue
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        content = _clean_block(text[start:end])
        if not content:
            continue
        blocks.append(
            KnowledgeBlock(
                source="ctf-playbook",
                title=title,
                category=_category_from_title(title),
                content=content,
            )
        )
    return blocks


def blocks_from_notebook_reports(notebook: NotebookLike, current_challenge_id: str | None = None) -> list[KnowledgeBlock]:
    blocks: list[KnowledgeBlock] = []
    try:
        challenges = notebook.list_challenges()
    except Exception:  # noqa: BLE001 - knowledge retrieval must never block solving.
        return []
    for challenge in challenges:
        if getattr(challenge, "challenge_id", None) == current_challenge_id:
            continue
        try:
            summary = notebook.latest_run_summary(challenge.challenge_id)
        except Exception:  # noqa: BLE001
            continue
        writeup = ((summary or {}).get("replay_report") or {}).get("writeup") or {}
        markdown = writeup.get("markdown")
        if not isinstance(markdown, str) or not markdown.strip():
            continue
        blocks.append(
            KnowledgeBlock(
                source="notebook-writeup",
                title=str(writeup.get("title") or challenge.title or challenge.challenge_id),
                category=_category_from_value(writeup.get("category")) or challenge.category,
                content=_clean_block(markdown),
            )
        )
    return blocks


def retrieve_knowledge(
    category: ChallengeCategory,
    query: str,
    blocks: list[KnowledgeBlock],
    limit: int = 3,
) -> list[KnowledgeBlock]:
    scored = [
        (_score_block(category, query, block), block)
        for block in blocks
    ]
    return [block for score, block in sorted(scored, key=lambda item: item[0], reverse=True) if score > 0][:limit]


def retrieved_knowledge_for(
    category: ChallengeCategory,
    query: str,
    notebook: NotebookLike | None = None,
    current_challenge_id: str | None = None,
    limit: int = 3,
) -> list[KnowledgeBlock]:
    blocks = load_playbook_blocks()
    if notebook is not None:
        blocks.extend(blocks_from_notebook_reports(notebook, current_challenge_id=current_challenge_id))
    return retrieve_knowledge(category, query, blocks, limit=limit)


def format_knowledge_blocks(blocks: list[KnowledgeBlock], max_chars_per_block: int = 700) -> str:
    if not blocks:
        return "retrieved_knowledge:\n- none"
    lines = ["retrieved_knowledge:"]
    for block in blocks:
        content = block.content
        if len(content) > max_chars_per_block:
            content = content[: max_chars_per_block - 3].rstrip() + "..."
        lines.append(f"- [{block.source} / {block.category.value} / {block.title}] {content}")
    return "\n".join(lines)


def _score_block(category: ChallengeCategory, query: str, block: KnowledgeBlock) -> int:
    query_terms = _terms(query)
    content_terms = _terms(f"{block.title} {block.content}")
    score = len(query_terms & content_terms)
    if block.category == category:
        score += 8
    if block.category == ChallengeCategory.UNKNOWN:
        score += 1
    return score


def _terms(text: str) -> set[str]:
    return {term.lower() for term in re.findall(r"[A-Za-z0-9_./{}-]{3,}", text)}


def _category_from_title(title: str) -> ChallengeCategory:
    label = title.lower().replace(" method card", "").strip()
    return _CATEGORY_LABELS.get(label, ChallengeCategory.UNKNOWN)


def _category_from_value(value: object) -> ChallengeCategory | None:
    if not isinstance(value, str):
        return None
    try:
        return ChallengeCategory(value)
    except ValueError:
        return _CATEGORY_LABELS.get(value.lower())


def _clean_block(text: str) -> str:
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped == "ForgeFlag next additions:":
            continue
        lines.append(stripped)
    return "\n".join(lines).strip()
