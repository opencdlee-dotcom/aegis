"""MCP registration coverage (research briefing, unknown-unknown #4).

The agent-surface walk discovers configs by SHAPE under a bounded set of
roots. Two kinds of registration were outside every root:

  * ~/.claude.json — Claude Code's user-level `mcpServers` store, a single
    FILE in $HOME (a root nothing may walk);
  * registries under agent directories the root list did not name (Windsurf,
    Copilot CLI, Zed, opencode, Hermes) and the Windows/Linux spellings of
    Claude Desktop and VS Code.

These hold that an explicit file is walked, that a new server registered in
it is a HIGH exec finding on the scan after adoption, and that the surface
keeps its health row.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling import
import aegis  # noqa: E402
from test_regression import Sandbox, needs_real_scan_lock  # noqa: E402


def _cfg(*names):
    return {"mcpServers": {n: {"command": "/tmp/%s.sh" % n, "args": []}
                           for n in names}}


class TestRootsNameTheRegistries(unittest.TestCase):
    def test_home_level_claude_json_is_an_explicit_file(self):
        self.assertIn(os.path.join(aegis.HOME, ".claude.json"),
                      aegis.AGENT_CONFIG_FILES)

    def test_roots_cover_every_body_spelling(self):
        joined = "\n".join(aegis.AGENT_CONFIG_ROOTS)
        for rel in (".codeium/windsurf", ".copilot", ".config/zed",
                    "AppData/Roaming/Claude", "AppData/Roaming/Code/User",
                    ".config/Claude", "Library/Application Support/Claude"):
            self.assertIn(rel, joined, rel)


class TestExplicitFileIsWalked(Sandbox):
    def _point_at(self, path):
        self._saved["AGENT_CONFIG_ROOTS"] = aegis.AGENT_CONFIG_ROOTS
        aegis.AGENT_CONFIG_ROOTS = []
        aegis.AGENT_CONFIG_FILES = [path]

    def test_present_file_is_snapshotted_with_its_execs(self):
        p = os.path.join(self.tmp, ".claude.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(_cfg("alpha"), f)
        self._point_at(p)
        self.assertEqual([p], aegis._agent_config_files())
        snap = aegis.snapshot_agent_surface()
        self.assertIn(p, snap)
        self.assertEqual(1, len(snap[p]["execs"]))

    def test_missing_file_is_absent_not_an_error(self):
        self._point_at(os.path.join(self.tmp, "nope.json"))
        self.assertEqual([], aegis._agent_config_files())

    def test_symlinked_file_is_skipped_like_the_walk_does(self):
        real = os.path.join(self.tmp, "real.json")
        with open(real, "w", encoding="utf-8") as f:
            json.dump(_cfg("alpha"), f)
        link = os.path.join(self.tmp, ".claude.json")
        os.symlink(real, link)
        self._point_at(link)
        self.assertEqual([], aegis._agent_config_files())


@needs_real_scan_lock
class TestNewServerFiresOnScan(Sandbox):
    def setUp(self):
        super().setUp()
        self.reg = os.path.join(self.tmp, ".claude.json")
        self._saved["AGENT_CONFIG_ROOTS"] = aegis.AGENT_CONFIG_ROOTS
        aegis.AGENT_CONFIG_ROOTS = []
        aegis.AGENT_CONFIG_FILES = [self.reg]

    def _write(self, *names):
        with open(self.reg, "w", encoding="utf-8") as f:
            json.dump(_cfg(*names), f)

    def _findings(self):
        with open(aegis.FINDINGS_LOG, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]

    def test_registered_server_after_adoption_is_high(self):
        self._write("alpha")
        aegis.cmd_scan(quiet=True)                       # adopts alpha
        self._write("alpha", "beta")
        aegis.cmd_scan(quiet=True)
        hits = [f for f in self._findings()
                if f["category"] == "agent-surface" and "beta" in f["detail"]]
        self.assertEqual(1, len(hits), self._findings())
        self.assertEqual("HIGH", hits[0]["severity"])
        health = {r["sensor_id"]: r for r in aegis.get_sensor_health()}
        self.assertEqual("OK", health["surface.agent_surface"]["status"])


if __name__ == "__main__":
    unittest.main()
