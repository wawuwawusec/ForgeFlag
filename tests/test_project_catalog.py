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

    def test_catalog_can_filter_by_category(self) -> None:
        projects = recommended_projects("traffic")

        self.assertTrue(projects)
        self.assertTrue(all("traffic" in project["categories"] for project in projects))


if __name__ == "__main__":
    unittest.main()
