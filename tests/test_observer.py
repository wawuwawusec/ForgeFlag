from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from forgeflag.domain import Challenge, ChallengeCategory, Finding, Observation
from forgeflag.notebook import SQLiteNotebook
from forgeflag.observer import Observer


class NotebookObservationTest(unittest.TestCase):
    def test_observation_round_trips_through_notebook(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(Challenge(challenge_id="obs-01", category=ChallengeCategory.MISC))
            notebook.add_observation(
                Observation(
                    challenge_id="obs-01",
                    source="Observer",
                    kind="solver_signal",
                    summary="Useful clue",
                    evidence={"confidence": 0.9},
                )
            )

            observations = notebook.observations_for("obs-01")

        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].kind, "solver_signal")
        self.assertEqual(observations[0].summary, "Useful clue")
        self.assertEqual(observations[0].evidence["confidence"], 0.9)


class ObserverTest(unittest.TestCase):
    def test_observer_promotes_high_confidence_findings(self) -> None:
        finding = Finding(
            challenge_id="obs-02",
            solver="ForensicsSolver",
            finding="Found likely XOR key",
            evidence={"key": "0x42"},
            confidence=0.82,
            next_action="Decode extracted payload.",
        )

        observations = Observer().observe_solver_result("obs-02", "ForensicsSolver", [finding], ())

        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].kind, "solver_signal")
        self.assertEqual(observations[0].source, "ForensicsSolver")
        self.assertEqual(observations[0].summary, "Found likely XOR key")

    def test_observer_promotes_flag_candidates_even_without_findings(self) -> None:
        observations = Observer().observe_solver_result("obs-03", "TrafficSolver", [], ("flag{network_trace}",))

        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].kind, "flag_candidate")
        self.assertEqual(observations[0].summary, "flag{network_trace}")


if __name__ == "__main__":
    unittest.main()
