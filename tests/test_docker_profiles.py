from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DockerProfileTest(unittest.TestCase):
    def test_ctf_dockerfile_has_explicit_heavyweight_targets(self) -> None:
        dockerfile = (ROOT / "docker" / "Dockerfile.ctf").read_text(encoding="utf-8")

        self.assertIn("AS forgeflag-core", dockerfile)
        self.assertIn("AS forgeflag-volatility", dockerfile)
        self.assertIn("AS forgeflag-sagemath", dockerfile)
        self.assertIn("AS forgeflag-ghidra-headless", dockerfile)
        self.assertIn("AS forgeflag-default", dockerfile)

    def test_core_stage_keeps_heavyweight_tools_out_of_base_venv(self) -> None:
        dockerfile = (ROOT / "docker" / "Dockerfile.ctf").read_text(encoding="utf-8")
        core_stage = dockerfile.split("FROM forgeflag-core AS forgeflag-volatility", 1)[0]

        self.assertNotIn("volatility3", core_stage)
        self.assertNotIn("sagemath", core_stage.lower())
        self.assertNotIn("ghidra", core_stage.lower())

    def test_tool_container_docs_describe_read_only_adapter_boundary(self) -> None:
        docs = (ROOT / "docs" / "tool-containers.md").read_text(encoding="utf-8")

        self.assertIn("--target forgeflag-volatility", docs)
        self.assertIn("--target forgeflag-sagemath", docs)
        self.assertIn("--target forgeflag-ghidra-headless", docs)
        self.assertIn("read-only", docs.lower())
        self.assertIn("registered attachment", docs.lower())


if __name__ == "__main__":
    unittest.main()
