from __future__ import annotations

import argparse
import json
from pathlib import Path

from forgeflag.domain import Challenge, ChallengeCategory, RunConfig
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="forgeflag", description="Scoped CTF multi-agent assistant")
    parser.add_argument("--db", default=".forgeflag/notebook.sqlite", help="Path to the SQLite shared notebook")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="Initialize the shared notebook")

    add = subparsers.add_parser("add-challenge", help="Add or update a challenge")
    add.add_argument("challenge_id")
    add.add_argument("--category", choices=[c.value for c in ChallengeCategory], default=ChallengeCategory.UNKNOWN.value)
    add.add_argument("--title")
    add.add_argument("--target")
    add.add_argument("--description")
    add.add_argument("--tag", action="append", default=[])

    subparsers.add_parser("list", help="List challenges")

    run = subparsers.add_parser("run", help="Run the manager on one challenge")
    run.add_argument("challenge_id")
    run.add_argument("--allow-host", action="append", default=[])
    run.add_argument("--active-probe", action="store_true", help="Enable scoped active probing")
    run.add_argument("--max-iterations", type=int, default=20)

    findings = subparsers.add_parser("findings", help="Show findings for one challenge")
    findings.add_argument("challenge_id")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    notebook = SQLiteNotebook(Path(args.db))

    if args.command == "init":
        print(json.dumps({"status": "ok", "db": str(Path(args.db))}, ensure_ascii=False))
        return 0

    if args.command == "add-challenge":
        challenge = Challenge(
            challenge_id=args.challenge_id,
            category=ChallengeCategory(args.category),
            title=args.title,
            target=args.target,
            description=args.description,
            tags=tuple(args.tag),
        )
        notebook.add_challenge(challenge)
        print(json.dumps({"status": "ok", "challenge_id": challenge.challenge_id}, ensure_ascii=False))
        return 0

    if args.command == "list":
        rows = [
            {
                "challenge_id": challenge.challenge_id,
                "category": challenge.category.value,
                "title": challenge.title,
                "target": challenge.target,
                "tags": list(challenge.tags),
            }
            for challenge in notebook.list_challenges()
        ]
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0

    if args.command == "run":
        config = RunConfig(
            max_iterations=args.max_iterations,
            active_probe=args.active_probe,
            allowed_hosts=tuple(args.allow_host),
        )
        summary = Manager(notebook, config=config).run_challenge(args.challenge_id)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    if args.command == "findings":
        rows = [
            {
                "solver": finding.solver,
                "finding": finding.finding,
                "confidence": finding.confidence,
                "hypothesis": finding.hypothesis,
                "next_action": finding.next_action,
                "evidence": finding.evidence,
            }
            for finding in notebook.findings_for(args.challenge_id)
        ]
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

