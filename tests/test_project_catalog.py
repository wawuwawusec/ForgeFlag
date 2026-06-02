from __future__ import annotations

import unittest

from forgeflag.project_catalog import recommended_projects


class ProjectCatalogTest(unittest.TestCase):
    def test_catalog_contains_core_ctf_projects_by_category(self) -> None:
        projects = recommended_projects()
        names = {project["name"] for project in projects}

        self.assertIn("pwntools", names)
        self.assertIn("CyberChef", names)
        self.assertIn("CTFd", names)
        self.assertIn("Ghidra", names)
        self.assertIn("Wireshark", names)
        self.assertIn("Burp Suite Community", names)
        self.assertIn("Ciphey", names)
        self.assertIn("zsteg", names)
        self.assertIn("Zeek", names)
        self.assertIn("FLOSS", names)
        self.assertIn("one_gadget", names)

    def test_catalog_can_filter_by_category(self) -> None:
        projects = recommended_projects("traffic")

        self.assertTrue(projects)
        self.assertTrue(all("traffic" in project["categories"] for project in projects))
        self.assertIn("Zeek", {project["name"] for project in projects})

    def test_catalog_covers_all_major_solver_categories(self) -> None:
        projects = recommended_projects()

        coverage = {category for project in projects for category in project["categories"]}

        for category in ("web", "crypto", "misc", "forensics", "traffic", "reverse", "pwn", "infra"):
            self.assertIn(category, coverage)
        self.assertGreaterEqual(len(projects), 60)


if __name__ == "__main__":
    unittest.main()
