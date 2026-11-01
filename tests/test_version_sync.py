from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path

import antirea
from antirea import defense_mcp


REPO_ROOT = Path(__file__).resolve().parent.parent


class VersionSyncTests(unittest.TestCase):
    def test_version_file_is_valid_semver(self) -> None:
        version_path = REPO_ROOT / "VERSION"
        self.assertTrue(version_path.is_file(), "VERSION file must exist at repository root")
        version = version_path.read_text(encoding="utf-8").strip()
        self.assertRegex(
            version,
            r"^[0-9]+\.[0-9]+\.[0-9]+$",
            f"VERSION must follow MAJOR.MINOR.PATCH SemVer, got {version!r}",
        )

    def test_all_project_version_manifests_match_version_file(self) -> None:
        version = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()

        # 1. pyproject.toml
        pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(pyproject["project"]["version"], version)

        # 2. antirea.__version__
        self.assertEqual(antirea.__version__, version)

        # 3. MCP initialize serverInfo.version
        bridge = defense_mcp.DefenseBridge(object())
        response = bridge.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "version-sync-test", "version": version},
                },
            }
        )
        self.assertIsNotNone(response)
        self.assertEqual(response["result"]["serverInfo"]["version"], version)

        # 4. rust/Cargo.toml workspace version
        cargo_toml = tomllib.loads((REPO_ROOT / "rust" / "Cargo.toml").read_text(encoding="utf-8"))
        self.assertEqual(cargo_toml["workspace"]["package"]["version"], version)

        # 5. Generated Cargo.toml templates in rust/crates/antirea-passes/src/lib.rs
        passes_lib = (REPO_ROOT / "rust" / "crates" / "antirea-passes" / "src" / "lib.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn(f'version = "{version}"', passes_lib)
        self.assertNotIn('version = "0.12.0"', passes_lib)

    def test_changelog_and_readmes_include_current_version(self) -> None:
        version = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()

        changelog_path = REPO_ROOT / "CHANGELOG.md"
        self.assertTrue(changelog_path.is_file(), "CHANGELOG.md must exist at repository root")
        changelog = changelog_path.read_text(encoding="utf-8")
        self.assertRegex(
            changelog,
            rf"(?m)^## \[{re.escape(version)}\] - [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}$",
            f"CHANGELOG.md must contain a release heading for [{version}]",
        )

        versioning_doc = REPO_ROOT / "docs" / "versioning.md"
        self.assertTrue(versioning_doc.is_file(), "docs/versioning.md must exist")

        badge_fragment = f"https://img.shields.io/badge/Version-v{version}-10b981?style=flat-square"
        readmes = [REPO_ROOT / "README.md"] + sorted((REPO_ROOT / "docs" / "readme").glob("README_*.md"))
        self.assertEqual(len(readmes), 22)
        for readme_path in readmes:
            content = readme_path.read_text(encoding="utf-8")
            self.assertIn(
                badge_fragment,
                content,
                f"{readme_path.name} is missing the Version-v{version} badge",
            )


if __name__ == "__main__":
    unittest.main()
