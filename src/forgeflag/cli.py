from __future__ import annotations

import argparse
import json
from pathlib import Path

from forgeflag.agent_roster import agent_roster_path_for_db, load_agent_roster, write_default_agent_roster
from forgeflag.analysis_hints import recommended_analysis_hints
from forgeflag.artifacts import ArtifactWorkspace, summarize_artifact_paths
from forgeflag.domain import Challenge, ChallengeCategory, LLMConfig, RunConfig
from forgeflag.health import format_system_health, system_health
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from forgeflag.project_catalog import recommended_projects
from forgeflag.safety import ScopePolicy
from forgeflag.tools.runner import ToolRunner
from forgeflag.webapp import run_webapp


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
    add.add_argument("--attachment", action="append", default=[], help="Local challenge artifact to copy into the workspace")

    subparsers.add_parser("list", help="List challenges")

    run = subparsers.add_parser("run", help="Run the manager on one challenge")
    run.add_argument("challenge_id")
    run.add_argument("--allow-host", action="append", default=[])
    run.add_argument("--active-probe", action="store_true", help="Enable scoped active probing")
    run.add_argument("--max-iterations", type=int, default=20)
    run.add_argument("--llm-provider", choices=["disabled", "openai", "zhipu"], help="Optional LLM provider for strategy planning")
    run.add_argument("--llm-model", help="Model name for the configured LLM provider")
    run.add_argument("--llm-base-url", help="Override the provider API base URL")

    findings = subparsers.add_parser("findings", help="Show findings for one challenge")
    findings.add_argument("challenge_id")

    observations = subparsers.add_parser("observations", help="Show distilled shared observations for one challenge")
    observations.add_argument("challenge_id")

    report = subparsers.add_parser("report", help="Show the latest CTF write-up and replay data for one challenge")
    report.add_argument("challenge_id")

    artifacts = subparsers.add_parser("artifacts", help="List registered artifacts for one challenge")
    artifacts.add_argument("challenge_id")

    subparsers.add_parser("tools", help="List configured CTF tool wrappers and local availability")
    doctor = subparsers.add_parser("doctor", help="Run deployment and readiness diagnostics")
    doctor.add_argument("--format", choices=["json", "text"], default="json", help="Diagnostic output format")
    doctor.add_argument(
        "--strict",
        nargs="?",
        const="core",
        choices=["core", "commercial"],
        help="Exit non-zero unless the selected readiness gate is ready; defaults to core",
    )
    agents = subparsers.add_parser("agents", help="List ForgeFlag subagent identities and responsibilities")
    agents.add_argument("--write-default", action="store_true", help="Write the default roster to .forgeflag/agent-roster.json")
    catalog = subparsers.add_parser("catalog", help="List recommended CTF projects and integration candidates")
    catalog.add_argument("--category", choices=[c.value for c in ChallengeCategory])
    hints = subparsers.add_parser("hints", help="List recommended CTF analysis hints from recent solve patterns")
    hints.add_argument("--category", choices=[c.value for c in ChallengeCategory])

    web = subparsers.add_parser("web", help="Start the local ForgeFlag web UI")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8080)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    notebook = SQLiteNotebook(Path(args.db))

    if args.command == "init":
        print(json.dumps({"status": "ok", "db": str(Path(args.db))}, ensure_ascii=False))
        return 0

    if args.command == "add-challenge":
        artifact_workspace = ArtifactWorkspace(Path(args.db).parent / "artifacts")
        attachment_paths = tuple(
            str(artifact_workspace.register_file(args.challenge_id, attachment).workspace_path)
            for attachment in args.attachment
        )
        challenge = Challenge(
            challenge_id=args.challenge_id,
            category=ChallengeCategory(args.category),
            title=args.title,
            target=args.target,
            description=args.description,
            tags=tuple(args.tag),
            attachment_paths=attachment_paths,
        )
        notebook.add_challenge(challenge)
        print(
            json.dumps(
                {
                    "status": "ok",
                    "challenge_id": challenge.challenge_id,
                    "attachment_paths": list(challenge.attachment_paths),
                },
                ensure_ascii=False,
            )
        )
        return 0

    if args.command == "list":
        rows = [
            {
                "challenge_id": challenge.challenge_id,
                "category": challenge.category.value,
                "title": challenge.title,
                "target": challenge.target,
                "tags": list(challenge.tags),
                "attachment_paths": list(challenge.attachment_paths),
            }
            for challenge in notebook.list_challenges()
        ]
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0

    if args.command == "run":
        llm_config = _llm_config_from_args(args)
        config = RunConfig(
            max_iterations=args.max_iterations,
            active_probe=args.active_probe,
            allowed_hosts=tuple(args.allow_host),
            llm_config=llm_config,
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

    if args.command == "observations":
        rows = [
            {
                "source": observation.source,
                "kind": observation.kind,
                "summary": observation.summary,
                "evidence": observation.evidence,
                "created_at": observation.created_at,
            }
            for observation in notebook.observations_for(args.challenge_id)
        ]
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0

    if args.command == "report":
        summary = notebook.latest_run_summary(args.challenge_id)
        replay_report = (summary or {}).get("replay_report")
        print(json.dumps(replay_report or {}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "artifacts":
        challenge = notebook.get_challenge(args.challenge_id)
        print(
            json.dumps(
                {
                    "challenge_id": challenge.challenge_id,
                    "artifacts": summarize_artifact_paths(challenge.attachment_paths),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.command == "tools":
        print(json.dumps(ToolRunner(ScopePolicy()).inventory(), ensure_ascii=False, indent=2))
        return 0

    if args.command == "doctor":
        payload = system_health(Path(args.db))
        if args.format == "text":
            print(format_system_health(payload))
        else:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        if args.strict:
            readiness_key = "core_readiness" if args.strict == "core" else "commercial_readiness"
            readiness = payload.get(readiness_key, {})
            return 0 if isinstance(readiness, dict) and readiness.get("status") == "ready" else 1
        return 0

    if args.command == "agents":
        path = agent_roster_path_for_db(args.db)
        roster = write_default_agent_roster(path) if args.write_default else load_agent_roster(path)
        print(json.dumps(roster.to_public_dict(), ensure_ascii=False, indent=2))
        return 0

    if args.command == "catalog":
        print(json.dumps(recommended_projects(args.category), ensure_ascii=False, indent=2))
        return 0

    if args.command == "hints":
        print(json.dumps(recommended_analysis_hints(args.category), ensure_ascii=False, indent=2))
        return 0

    if args.command == "web":
        run_webapp(Path(args.db), host=args.host, port=args.port)
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


def _llm_config_from_args(args: argparse.Namespace) -> LLMConfig:
    base = LLMConfig.from_env()
    return LLMConfig(
        provider=args.llm_provider or base.provider,
        model=args.llm_model or base.model,
        api_key=base.api_key,
        base_url=args.llm_base_url or base.base_url,
        timeout_seconds=base.timeout_seconds,
    )


if __name__ == "__main__":
    raise SystemExit(main())
