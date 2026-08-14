from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import json
import sqlite3
from pathlib import Path
from typing import Any

from forgeflag.domain import Challenge, ChallengeCategory, Finding, FindingStatus, Observation, ToolResult, utc_now
from forgeflag.tool_compression import with_compressed_summary


class SQLiteNotebook:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if self.path.parent:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                create table if not exists challenges (
                    challenge_id text primary key,
                    category text not null,
                    title text,
                    target text,
                    description text,
                    tags_json text not null,
                    attachment_paths_json text not null default '[]',
                    created_at text not null
                );

                create table if not exists findings (
                    id integer primary key autoincrement,
                    challenge_id text not null,
                    solver text not null,
                    finding text not null,
                    evidence_json text not null,
                    hypothesis text,
                    confidence real not null,
                    next_action text,
                    status text not null,
                    created_at text not null,
                    foreign key(challenge_id) references challenges(challenge_id)
                );

                create table if not exists tool_runs (
                    id integer primary key autoincrement,
                    challenge_id text,
                    tool text not null,
                    target text,
                    status text not null,
                    evidence_json text not null,
                    artifacts_json text not null,
                    next_hints_json text not null,
                    raw_json text not null,
                    created_at text not null
                );

                create table if not exists observations (
                    id integer primary key autoincrement,
                    challenge_id text not null,
                    source text not null,
                    kind text not null,
                    summary text not null,
                    evidence_json text not null,
                    created_at text not null,
                    foreign key(challenge_id) references challenges(challenge_id)
                );

                create table if not exists runs (
                    id integer primary key autoincrement,
                    challenge_id text not null,
                    status text not null,
                    summary_json text not null,
                    created_at text not null
                );
                """
            )
            columns = {
                row["name"]
                for row in conn.execute("pragma table_info(challenges)").fetchall()
            }
            if "attachment_paths_json" not in columns:
                conn.execute("alter table challenges add column attachment_paths_json text not null default '[]'")

    def add_challenge(self, challenge: Challenge) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                insert into challenges (
                    challenge_id, category, title, target, description, tags_json, attachment_paths_json, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(challenge_id) do update set
                    category = excluded.category,
                    title = excluded.title,
                    target = excluded.target,
                    description = excluded.description,
                    tags_json = excluded.tags_json,
                    attachment_paths_json = excluded.attachment_paths_json
                """,
                (
                    challenge.challenge_id,
                    challenge.category.value,
                    challenge.title,
                    challenge.target,
                    challenge.description,
                    json.dumps(challenge.tags, ensure_ascii=False),
                    json.dumps(challenge.attachment_paths, ensure_ascii=False),
                    challenge.created_at,
                ),
            )

    def get_challenge(self, challenge_id: str) -> Challenge:
        with self._connect() as conn:
            row = conn.execute(
                "select * from challenges where challenge_id = ?",
                (challenge_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"challenge not found: {challenge_id}")
        return self._challenge_from_row(row)

    def list_challenges(self) -> list[Challenge]:
        with self._connect() as conn:
            rows = conn.execute("select * from challenges order by created_at, challenge_id").fetchall()
        return [self._challenge_from_row(row) for row in rows]

    def add_finding(self, finding: Finding) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                insert into findings (
                    challenge_id, solver, finding, evidence_json, hypothesis,
                    confidence, next_action, status, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.challenge_id,
                    finding.solver,
                    finding.finding,
                    json.dumps(finding.evidence, ensure_ascii=False, sort_keys=True),
                    finding.hypothesis,
                    finding.confidence,
                    finding.next_action,
                    finding.status.value,
                    finding.created_at,
                ),
            )
            return int(cursor.lastrowid)

    def findings_for(self, challenge_id: str) -> list[Finding]:
        with self._connect() as conn:
            rows = conn.execute(
                "select * from findings where challenge_id = ? order by id",
                (challenge_id,),
            ).fetchall()
        return [self._finding_from_row(row) for row in rows]

    def add_observation(self, observation: Observation) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                insert into observations (
                    challenge_id, source, kind, summary, evidence_json, created_at
                ) values (?, ?, ?, ?, ?, ?)
                """,
                (
                    observation.challenge_id,
                    observation.source,
                    observation.kind,
                    observation.summary,
                    json.dumps(observation.evidence, ensure_ascii=False, sort_keys=True),
                    observation.created_at,
                ),
            )
            return int(cursor.lastrowid)

    def observations_for(self, challenge_id: str) -> list[Observation]:
        with self._connect() as conn:
            rows = conn.execute(
                "select * from observations where challenge_id = ? order by id",
                (challenge_id,),
            ).fetchall()
        return [self._observation_from_row(row) for row in rows]

    def add_tool_result(self, challenge_id: str | None, result: ToolResult) -> int:
        result = with_compressed_summary(result)
        with self._connect() as conn:
            cursor = conn.execute(
                """
                insert into tool_runs (
                    challenge_id, tool, target, status, evidence_json, artifacts_json,
                    next_hints_json, raw_json, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    challenge_id,
                    result.tool,
                    result.target,
                    result.status,
                    json.dumps(result.evidence, ensure_ascii=False),
                    json.dumps(result.artifacts, ensure_ascii=False),
                    json.dumps(result.next_hints, ensure_ascii=False),
                    json.dumps(result.raw, ensure_ascii=False, sort_keys=True),
                    result.created_at,
                ),
            )
            tool_run_id = int(cursor.lastrowid)
            if challenge_id:
                summary = result.raw.get("compressed_summary")
                if isinstance(summary, dict):
                    conn.execute(
                        """
                        insert into observations (
                            challenge_id, source, kind, summary, evidence_json, created_at
                        ) values (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            challenge_id,
                            result.tool,
                            "tool_summary",
                            _tool_summary_text(summary),
                            json.dumps(summary, ensure_ascii=False, sort_keys=True),
                            result.created_at,
                        ),
                    )
            return tool_run_id

    def record_run(self, challenge_id: str, status: str, summary: dict[str, Any]) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                insert into runs (challenge_id, status, summary_json, created_at)
                values (?, ?, ?, ?)
                """,
                (challenge_id, status, json.dumps(summary, ensure_ascii=False, sort_keys=True), utc_now()),
            )
            return int(cursor.lastrowid)

    def latest_run_summary(self, challenge_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "select summary_json from runs where challenge_id = ? order by id desc limit 1",
                (challenge_id,),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["summary_json"])

    def latest_run_status(self, challenge_id: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "select status from runs where challenge_id = ? order by id desc limit 1",
                (challenge_id,),
            ).fetchone()
        return None if row is None else str(row["status"])

    def delete_challenge(self, challenge_id: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        with self._connect() as conn:
            counts["findings"] = _delete_count(conn, "delete from findings where challenge_id = ?", (challenge_id,))
            counts["observations"] = _delete_count(conn, "delete from observations where challenge_id = ?", (challenge_id,))
            counts["tool_runs"] = _delete_count(conn, "delete from tool_runs where challenge_id = ?", (challenge_id,))
            counts["runs"] = _delete_count(conn, "delete from runs where challenge_id = ?", (challenge_id,))
            counts["challenges"] = _delete_count(conn, "delete from challenges where challenge_id = ?", (challenge_id,))
        return counts

    def clear_challenges(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        with self._connect() as conn:
            counts["findings"] = _delete_count(conn, "delete from findings")
            counts["observations"] = _delete_count(conn, "delete from observations")
            counts["tool_runs"] = _delete_count(conn, "delete from tool_runs where challenge_id is not null")
            counts["runs"] = _delete_count(conn, "delete from runs")
            counts["challenges"] = _delete_count(conn, "delete from challenges")
        return counts

    def _challenge_from_row(self, row: sqlite3.Row) -> Challenge:
        return Challenge(
            challenge_id=row["challenge_id"],
            category=ChallengeCategory(row["category"]),
            title=row["title"],
            target=row["target"],
            description=row["description"],
            tags=tuple(json.loads(row["tags_json"])),
            attachment_paths=tuple(json.loads(row["attachment_paths_json"])),
            created_at=row["created_at"],
        )

    def _finding_from_row(self, row: sqlite3.Row) -> Finding:
        return Finding(
            challenge_id=row["challenge_id"],
            solver=row["solver"],
            finding=row["finding"],
            evidence=json.loads(row["evidence_json"]),
            hypothesis=row["hypothesis"],
            confidence=float(row["confidence"]),
            next_action=row["next_action"],
            status=FindingStatus(row["status"]),
            created_at=row["created_at"],
        )

    def _observation_from_row(self, row: sqlite3.Row) -> Observation:
        return Observation(
            challenge_id=row["challenge_id"],
            source=row["source"],
            kind=row["kind"],
            summary=row["summary"],
            evidence=json.loads(row["evidence_json"]),
            created_at=row["created_at"],
        )


def _tool_summary_text(summary: dict[str, Any]) -> str:
    tool = str(summary.get("tool") or "tool")
    status = str(summary.get("status") or "")
    flags = summary.get("flags") if isinstance(summary.get("flags"), list) else []
    interesting = summary.get("interesting_lines") if isinstance(summary.get("interesting_lines"), list) else []
    if flags:
        return f"{tool} {status}: flag candidates {', '.join(str(flag) for flag in flags[:3])}"
    if interesting:
        return f"{tool} {status}: {str(interesting[0])[:180]}"
    return f"{tool} {status}: no compressed highlights"


def _delete_count(conn: sqlite3.Connection, sql: str, params: tuple[object, ...] = ()) -> int:
    cursor = conn.execute(sql, params)
    return int(cursor.rowcount if cursor.rowcount is not None else 0)
