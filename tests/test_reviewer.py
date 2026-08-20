import tempfile
import unittest
from pathlib import Path
from unittest import mock

from forgeflag.domain import Challenge, ChallengeCategory, Finding, FindingStatus, LLMConfig, Observation, RunConfig
from forgeflag.llm import LLMResponse
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook
from forgeflag.reviewer import (
    ReviewVerdict,
    ReviewerAgent,
    reflection_hint_from_observations,
    reviewer_observation,
)


class FakeJudgeProvider:
    name = "zhipu"
    model = "glm-5.3"
    enabled = True

    def __init__(self, content='{"quality":"weak_evidence","issues":["flag not derived from data"],"reflection_hint":"XOR pixel data of the two images instead of file bytes"}'):
        self.content = content

    def generate(self, instructions, prompt, **kwargs):
        return LLMResponse(content=self.content, raw={}, usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8})


def _notebook_with_findings(challenge_id: str = "rev-01") -> SQLiteNotebook:
    notebook = SQLiteNotebook(Path(tempfile.mkdtemp()) / "nb.sqlite")
    notebook.add_challenge(Challenge(challenge_id=challenge_id, category=ChallengeCategory.MISC))
    notebook.add_finding(
        Finding(
            challenge_id=challenge_id,
            solver="MiscSolver",
            finding="Analyzed misc archive artifact",
            evidence={"flag_candidates": ["CTF{fakeflag}"], "ctf_scope": {}},
            confidence=0.8,
            status=FindingStatus.ACTIVE,
        )
    )
    notebook.add_observation(
        Observation(
            challenge_id=challenge_id,
            source="MiscSolver",
            kind="tool_summary",
            summary="strings hit",
            evidence={},
        )
    )
    return notebook


class ReviewerAgentTest(unittest.TestCase):
    def test_placeholder_candidate_flagged_as_hallucination_risk(self):
        notebook = _notebook_with_findings()
        verdict = ReviewerAgent().review_challenge(notebook, "rev-01")
        self.assertEqual(verdict.quality, "hallucination_risk")
        self.assertTrue(any("placeholder" in i for i in verdict.issues))

    def test_llm_judge_adds_reflection_hint(self):
        notebook = _notebook_with_findings()
        verdict = ReviewerAgent(FakeJudgeProvider()).review_challenge(notebook, "rev-01")
        self.assertIn("XOR pixel", verdict.reflection_hint)
        self.assertEqual(verdict.llm_analysis.get("quality"), "weak_evidence")

    def test_manager_records_reviewer_verdict_on_failure(self):
        notebook = _notebook_with_findings("rev-mgr")
        notebook.add_challenge(Challenge(challenge_id="rev-mgr", category=ChallengeCategory.MISC))
        manager = Manager(notebook, solvers=[])
        manager.verifier = mock.Mock()
        manager.verifier.verify.return_value = mock.Mock(accepted=(), rejected=())
        summary = manager.run_challenge("rev-mgr")
        self.assertIn("reviewer", summary)
        kinds = [o.kind for o in notebook.observations_for("rev-mgr")]
        self.assertIn("reviewer_verdict", kinds)

    def test_reflection_hint_roundtrip(self):
        verdict = ReviewVerdict(challenge_id="rev-01", quality="clean")
        verdict.reflection_hint = "try known-plaintext"
        observation = reviewer_observation(verdict)
        self.assertEqual(reflection_hint_from_observations([observation]), "try known-plaintext")
        self.assertEqual(reflection_hint_from_observations([]), "")


class CorpusReviewTest(unittest.TestCase):
    def test_buckets_and_prioritization(self):
        scorecard = {
            "failures": [
                {"challenge_id": "a", "status": "flag_found"},
                {"challenge_id": "b", "status": "completed"},
                {"challenge_id": "c", "status": "harness_error:TimeoutError"},
                {"challenge_id": "d", "status": "completed"},
            ]
        }
        review = ReviewerAgent().review_corpus(scorecard, deployable_ids={"d"})
        self.assertEqual(review["buckets"]["near_miss_flag_found"], ["a"])
        self.assertEqual(review["buckets"]["retry_with_service"], ["d"])
        self.assertEqual(review["prioritized_retry_ids"][0], "a")

    def test_variance_report_detects_flaky_cases(self):
        scorecards = [
            {"suites": [{"passed_ids": ["x"], "rows": [{"challenge_id": "x"}, {"challenge_id": "y"}]}]},
            {"suites": [{"passed_ids": [], "rows": [{"challenge_id": "x"}, {"challenge_id": "y"}]}]},
        ]
        report = ReviewerAgent.variance_report(scorecards)
        self.assertEqual(report["flaky_challenges"]["x"]["rate"], 0.5)


if __name__ == "__main__":
    unittest.main()
