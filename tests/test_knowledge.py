from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from forgeflag.domain import Challenge, ChallengeCategory
from forgeflag.knowledge import (
    KnowledgeBlock,
    blocks_from_notebook_reports,
    load_playbook_blocks,
    retrieve_knowledge,
)
from forgeflag.notebook import SQLiteNotebook


class KnowledgeRetrievalTest(unittest.TestCase):
    def test_load_playbook_blocks_extracts_category_method_cards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            playbook = Path(tmp) / "ctf-playbook.md"
            playbook.write_text(
                """
### Traffic Method Card

- Start with protocol hierarchy, endpoints, and TCP streams.
- Inspect DNS queries/TXT and HTTP objects.

### Web Method Card

- Check /robots.txt and classify SQL injection before payloads.
""".strip(),
                encoding="utf-8",
            )

            blocks = load_playbook_blocks(playbook)

        self.assertEqual([block.category for block in blocks], [ChallengeCategory.TRAFFIC, ChallengeCategory.WEB])
        self.assertIn("protocol hierarchy", blocks[0].content)
        self.assertEqual(blocks[0].source, "ctf-playbook")

    def test_retrieve_knowledge_prefers_matching_category_and_keywords(self) -> None:
        blocks = [
            KnowledgeBlock(
                source="ctf-playbook",
                title="Traffic Method Card",
                category=ChallengeCategory.TRAFFIC,
                content="Inspect protocol hierarchy, DNS queries/TXT, HTTP objects, and TCP streams.",
            ),
            KnowledgeBlock(
                source="ctf-playbook",
                title="Web Method Card",
                category=ChallengeCategory.WEB,
                content="Check /robots.txt, login forms, SQL injection, and admin routes.",
            ),
        ]

        results = retrieve_knowledge(
            ChallengeCategory.TRAFFIC,
            "pcap with dns txt and http object",
            blocks,
            limit=1,
        )

        self.assertEqual(results[0].title, "Traffic Method Card")
        self.assertIn("DNS queries/TXT", results[0].content)

    def test_blocks_from_notebook_reports_adds_prior_writeup_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="old-traffic",
                    category=ChallengeCategory.TRAFFIC,
                    title="Old DNS exfil",
                )
            )
            notebook.record_run(
                "old-traffic",
                "flag_found",
                {
                    "replay_report": {
                        "writeup": {
                            "title": "Old DNS exfil",
                            "category": "traffic",
                            "markdown": "# Old DNS exfil\n\nUse tshark dns fields and reconstruct Base32 labels.",
                        }
                    }
                },
            )

            blocks = blocks_from_notebook_reports(notebook)

        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].source, "notebook-writeup")
        self.assertEqual(blocks[0].category, ChallengeCategory.TRAFFIC)
        self.assertIn("Base32 labels", blocks[0].content)


if __name__ == "__main__":
    unittest.main()
