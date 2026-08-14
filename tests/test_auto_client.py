import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from forgeflag.auto import AutoClientConfig, AutoSolveClient
from forgeflag.domain import Challenge, ChallengeCategory
from forgeflag.notebook import SQLiteNotebook


class FakeManager:
    def __init__(self, notebook, config, runs=None):
        self.notebook = notebook
        self.runs = runs if runs is not None else {"n": 0}

    def run_challenge(self, challenge_id):
        self.runs["n"] += 1
        # every challenge solves on its second attempt
        solved = self.runs["n"] % 2 == 0
        status = "flag_found" if solved else "completed"
        self.notebook.record_run(challenge_id, status, {"status": status})
        return {
            "challenge_id": challenge_id,
            "status": status,
            "accepted_flags": ["flag{auto}"] if solved else [],
        }


def _notebook_with(*ids):
    import tempfile

    notebook = SQLiteNotebook(Path(tempfile.mkdtemp()) / "nb.sqlite")
    for cid in ids:
        notebook.add_challenge(
            Challenge(challenge_id=cid, category=ChallengeCategory.MISC)
        )
    return notebook


class TestAutoSolveClient(unittest.TestCase):
    def test_pending_challenges_skips_solved(self):
        notebook = _notebook_with("a", "b")
        notebook.record_run("a", "flag_found", {"status": "flag_found"})
        client = AutoSolveClient(notebook)
        self.assertEqual(client.pending_challenges(), ["b"])

    def test_retry_until_solved(self):
        notebook = _notebook_with("a")
        runs = {"n": 0}
        client = AutoSolveClient(
            notebook,
            config=AutoClientConfig(max_rounds=5, attempts_per_challenge=3),
            manager_factory=lambda nb, cfg: FakeManager(nb, cfg, runs),
        )
        summary = client.run()
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(summary["unsolved"], [])
        self.assertEqual(summary["progress"]["a"]["attempts"], 2)
        self.assertEqual(summary["progress"]["a"]["status"], "flag_found")

    def test_attempts_exhausted_reports_unsolved(self):
        notebook = _notebook_with("a")
        attempts = {"n": 0}

        class NeverSolves(FakeManager):
            def run_challenge(self, challenge_id):
                attempts["n"] += 1
                self.notebook.record_run(challenge_id, "completed", {})
                return {"challenge_id": challenge_id, "status": "completed", "accepted_flags": []}

        client = AutoSolveClient(
            notebook,
            config=AutoClientConfig(max_rounds=5, attempts_per_challenge=2),
            manager_factory=lambda nb, cfg: NeverSolves(nb, cfg),
        )
        summary = client.run()
        self.assertEqual(summary["unsolved"], ["a"])
        self.assertEqual(attempts["n"], 2)

    def test_solver_crash_does_not_kill_loop(self):
        notebook = _notebook_with("a", "b")
        runs = {"n": 0}

        class CrashingManager(FakeManager):
            def run_challenge(self, challenge_id):
                if challenge_id == "a":
                    raise RuntimeError("solver exploded")
                return super().run_challenge(challenge_id)

        client = AutoSolveClient(
            notebook,
            config=AutoClientConfig(max_rounds=3, attempts_per_challenge=2),
            manager_factory=lambda nb, cfg: CrashingManager(nb, cfg, runs),
        )
        summary = client.run()
        self.assertEqual(summary["progress"]["a"]["status"], "error")
        self.assertEqual(summary["progress"]["b"]["status"], "flag_found")

    def test_watch_mode_polls_then_stops_at_max_rounds(self):
        notebook = _notebook_with("a")
        sleeps = []
        runs = {"n": 0}
        client = AutoSolveClient(
            notebook,
            config=AutoClientConfig(max_rounds=4, attempts_per_challenge=2, watch=True),
            manager_factory=lambda nb, cfg: FakeManager(nb, cfg, runs),
            sleep=sleeps.append,
        )
        summary = client.run()
        self.assertEqual(summary["status"], "max_rounds_reached")
        self.assertEqual(len(sleeps), 2)
        self.assertEqual(summary["progress"]["a"]["status"], "flag_found")


class TestCliRunAll(unittest.TestCase):
    def test_run_all_prints_summary(self):
        import contextlib
        import io
        import json

        from forgeflag.cli import main

        with TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "nb.sqlite")
            main(["--db", db, "add-challenge", "misc-01", "--category", "misc"])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main(["--db", db, "run-all", "--rounds", "2", "--attempts", "1"])
            self.assertEqual(code, 0)
            payload = json.loads(out.getvalue())
            self.assertIn(payload["status"], {"completed", "max_rounds_reached"})
            self.assertIn("misc-01", payload["progress"])


if __name__ == "__main__":
    unittest.main()
