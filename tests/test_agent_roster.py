from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from forgeflag.agent_roster import default_agent_roster, load_agent_roster, write_default_agent_roster


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


if __name__ == "__main__":
    unittest.main()
