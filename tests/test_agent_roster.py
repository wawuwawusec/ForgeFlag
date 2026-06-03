from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from forgeflag.agent_roster import default_agent_roster, load_agent_roster, write_default_agent_roster
from forgeflag.domain import ChallengeCategory


class AgentRosterTest(unittest.TestCase):
    def test_default_roster_defines_professional_subagents(self) -> None:
        roster = default_agent_roster()

        self.assertEqual(roster.version, 1)
        self.assertEqual(roster.coordinator.id, "forgeflag-manager")
        self.assertEqual(len(roster.agents), 9)
        ids = {agent.id for agent in roster.agents}
        self.assertIn("challenge-triage", ids)
        self.assertIn("llm-route-planner", ids)
        self.assertIn("traffic-agent", ids)
        self.assertIn("browser-player-qa", ids)
        browser_agent = next(agent for agent in roster.agents if agent.id == "browser-player-qa")
        self.assertIn("Web UI", browser_agent.mission)
        self.assertIn("scripts/forgeflag-web-player-benchmark", browser_agent.playbooks)
        traffic_agent = next(agent for agent in roster.agents if agent.id == "traffic-agent")
        self.assertIn("TrafficSolver", traffic_agent.solvers)
        self.assertIn("tshark_tcp_streams", traffic_agent.tools)

    def test_roster_round_trips_through_project_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent-roster.json"

            write_default_agent_roster(path)
            loaded = load_agent_roster(path)

        self.assertEqual(loaded.to_dict(), default_agent_roster().to_dict())

    def test_default_roster_defines_rate_limit_safe_subagent_policy(self) -> None:
        roster = default_agent_roster()

        policy = roster.subagent_work_policy

        self.assertEqual(policy.mode, "conservative")
        self.assertEqual(policy.max_parallel, 1)
        self.assertEqual(policy.cooldown_seconds, 120)
        self.assertEqual(policy.failure_circuit_breaker, 1)
        self.assertTrue(policy.prefer_local_verification)
        self.assertIn("429 Too Many Requests", policy.blocked_after)
        self.assertIn("subagent_work_policy", roster.to_public_dict())

    def test_custom_subagent_policy_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent-roster.json"
            payload = default_agent_roster().to_dict()
            payload["subagent_work_policy"]["mode"] = "local_only"
            payload["subagent_work_policy"]["max_parallel"] = 0
            payload["subagent_work_policy"]["cooldown_seconds"] = 300
            path.write_text(json.dumps(payload), encoding="utf-8")

            loaded = load_agent_roster(path)

        self.assertEqual(loaded.subagent_work_policy.mode, "local_only")
        self.assertEqual(loaded.subagent_work_policy.max_parallel, 0)
        self.assertEqual(loaded.subagent_work_policy.cooldown_seconds, 300)

    def test_custom_roster_can_disable_agent_without_losing_identity_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent-roster.json"
            payload = default_agent_roster().to_dict()
            payload["agents"][0]["enabled"] = False
            path.write_text(json.dumps(payload), encoding="utf-8")

            loaded = load_agent_roster(path)

        self.assertFalse(loaded.agents[0].enabled)
        self.assertEqual(loaded.agents[0].id, default_agent_roster().agents[0].id)

    def test_explicit_empty_roster_stays_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent-roster.json"
            payload = default_agent_roster().to_dict()
            payload["agents"] = []
            path.write_text(json.dumps(payload), encoding="utf-8")

            loaded = load_agent_roster(path)

        self.assertEqual(loaded.agents, ())

    def test_malformed_roster_falls_back_with_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent-roster.json"
            path.write_text("{broken json", encoding="utf-8")

            loaded = load_agent_roster(path)

        self.assertEqual(loaded.coordinator.id, "forgeflag-manager")
        self.assertTrue(loaded.warnings)
        self.assertIn("agent-roster.json", loaded.warnings[0])

    def test_solver_names_for_category_follow_enabled_agent_order(self) -> None:
        roster = default_agent_roster()

        self.assertEqual(roster.solver_names_for(ChallengeCategory.WEB), ("ReconSolver", "LLMSolver", "WebSolver"))
        self.assertIn("WebSolver", roster.solver_names_for(ChallengeCategory.UNKNOWN))
        self.assertEqual(
            roster.solver_names_for(ChallengeCategory.TRAFFIC),
            ("ReconSolver", "LLMSolver", "TrafficSolver", "ForensicsSolver"),
        )

    def test_disabled_agent_removes_owned_solver_from_category_queue(self) -> None:
        payload = default_agent_roster().to_dict()
        for agent in payload["agents"]:
            if agent["id"] == "web-exploit":
                agent["enabled"] = False
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent-roster.json"
            path.write_text(json.dumps(payload), encoding="utf-8")

            roster = load_agent_roster(path)

        self.assertEqual(roster.solver_names_for(ChallengeCategory.WEB), ("ReconSolver", "LLMSolver"))


if __name__ == "__main__":
    unittest.main()
