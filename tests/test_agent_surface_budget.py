#!/usr/bin/env python3
"""A single global file budget is order-dependent starvation, not partial coverage.

`_agent_config_files` used to take one 400-file budget and RETURN the moment it
ran out, walking roots in order. The roots reached last were therefore not
"partially covered" — they were not looked at AT ALL, and which ones depended on
how large the earlier roots happened to be that day.

Measured on the reference machine 2026-08-31: 558 candidate files against the
400 budget, with the whole 158-file shortfall landing on the last root reached
(`~/Library/Application Support/Code/User`, which saw 34 of its 192 files). The
sensor said so — "coverage here is PARTIAL" — 260 times, without ever saying
WHICH root it had stopped looking at. `~/.claude` grows with every session, so
the starvation front advances on its own.

This matters more than its LOW severity suggests: agent-surface is the most
precise detector in the tool (measured alert precision 0.91), so the surface
being silently truncated is the tool's best signal being thrown away.
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


class AgentBudgetBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._saved = (aegis.AGENT_CONFIG_ROOTS, aegis._AGENT_SCAN_FILE_CAP,
                       aegis._AGENT_SCAN_ROOT_CAP, aegis.STATE_DIR)
        aegis.STATE_DIR = os.path.join(self.tmp, ".aegis")
        os.makedirs(aegis.STATE_DIR)
        aegis._AGENT_SCAN_TRUNCATED[0] = False
        del aegis._AGENT_SCAN_TRUNCATED_ROOTS[:]

    def tearDown(self):
        (aegis.AGENT_CONFIG_ROOTS, aegis._AGENT_SCAN_FILE_CAP,
         aegis._AGENT_SCAN_ROOT_CAP, aegis.STATE_DIR) = self._saved
        aegis._AGENT_SCAN_TRUNCATED[0] = False
        del aegis._AGENT_SCAN_TRUNCATED_ROOTS[:]
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _root(self, name, n_files):
        d = os.path.join(self.tmp, name)
        os.makedirs(d, exist_ok=True)
        for i in range(n_files):
            with open(os.path.join(d, "cfg%03d.json" % i), "w") as f:
                f.write("{}")
        return d

    def _count_under(self, files, root):
        return sum(1 for p in files if p.startswith(root.rstrip(os.sep) + os.sep))


class TestNoRootStarvesALaterOne(AgentBudgetBase):
    def test_a_huge_first_root_cannot_blind_the_second(self):
        """THE regression. Old behaviour: first root eats the budget, returns,
        second root is never opened — zero files, no mention of which."""
        big = self._root("first", 40)
        small = self._root("second", 5)
        aegis.AGENT_CONFIG_ROOTS = (big, small)
        aegis._AGENT_SCAN_ROOT_CAP = 10       # first root cannot finish
        aegis._AGENT_SCAN_FILE_CAP = 3000     # global backstop far away

        files = aegis._agent_config_files()
        self.assertEqual(self._count_under(files, big), 10, "first root uncapped")
        self.assertEqual(self._count_under(files, small), 5,
                         "SECOND ROOT STARVED — the whole defect")

    def test_every_root_gets_its_own_budget(self):
        roots = [self._root("r%d" % i, 30) for i in range(4)]
        aegis.AGENT_CONFIG_ROOTS = tuple(roots)
        aegis._AGENT_SCAN_ROOT_CAP = 12
        aegis._AGENT_SCAN_FILE_CAP = 3000
        files = aegis._agent_config_files()
        for r in roots:
            self.assertEqual(self._count_under(files, r), 12)

    def test_the_truncated_root_is_named(self):
        big = self._root("noisy", 40)
        quiet = self._root("quiet", 2)
        aegis.AGENT_CONFIG_ROOTS = (big, quiet)
        aegis._AGENT_SCAN_ROOT_CAP = 10
        aegis._AGENT_SCAN_FILE_CAP = 3000
        aegis._agent_config_files()
        self.assertIn(big, aegis._AGENT_SCAN_TRUNCATED_ROOTS)
        self.assertNotIn(quiet, aegis._AGENT_SCAN_TRUNCATED_ROOTS,
                         "a root that finished must not be reported as cut")
        out = aegis.check_agent_surface_coverage()
        self.assertEqual(len(out), 1)
        self.assertIn("noisy", out[0]["detail"])
        self.assertNotIn("quiet", out[0]["detail"])


class TestGlobalBackstopStillHolds(AgentBudgetBase):
    def test_global_cap_bounds_the_total(self):
        roots = [self._root("r%d" % i, 50) for i in range(4)]
        aegis.AGENT_CONFIG_ROOTS = tuple(roots)
        aegis._AGENT_SCAN_ROOT_CAP = 500      # per-root is not the limit here
        aegis._AGENT_SCAN_FILE_CAP = 60
        files = aegis._agent_config_files()
        self.assertLessEqual(len(files), 60)
        self.assertTrue(aegis._AGENT_SCAN_TRUNCATED[0])

    def test_roots_starved_by_the_global_cap_are_all_named(self):
        """Not just the first one. 'Which roots did I not look at' is the whole
        question the finding exists to answer."""
        roots = [self._root("r%d" % i, 50) for i in range(3)]
        aegis.AGENT_CONFIG_ROOTS = tuple(roots)
        aegis._AGENT_SCAN_ROOT_CAP = 500
        aegis._AGENT_SCAN_FILE_CAP = 10
        aegis._agent_config_files()
        self.assertEqual(len(aegis._AGENT_SCAN_TRUNCATED_ROOTS), 3,
                         "later roots starved by the global cap went unreported")

    def test_cap_of_one_still_truncates(self):
        """Back-compat: the pre-existing test forces _AGENT_SCAN_FILE_CAP = 1
        and requires truncation on the very first candidate."""
        aegis.AGENT_CONFIG_ROOTS = (self._root("only", 5),)
        aegis._AGENT_SCAN_ROOT_CAP = 500
        aegis._AGENT_SCAN_FILE_CAP = 1
        files = aegis._agent_config_files()
        self.assertEqual(len(files), 1)
        self.assertTrue(aegis._AGENT_SCAN_TRUNCATED[0])

    def test_full_coverage_emits_no_finding(self):
        aegis.AGENT_CONFIG_ROOTS = (self._root("small", 3),)
        aegis._AGENT_SCAN_ROOT_CAP = 500
        aegis._AGENT_SCAN_FILE_CAP = 3000
        aegis._agent_config_files()
        self.assertFalse(aegis._AGENT_SCAN_TRUNCATED[0])
        self.assertEqual(aegis.check_agent_surface_coverage(), [])


class TestFingerprintTracksWhichRoots(AgentBudgetBase):
    def test_a_newly_starved_root_is_a_new_fact(self):
        """A standing 'truncated' fingerprint would hide a root that only just
        started being starved — exactly the silent progression this fixes."""
        a = self._root("a", 40)
        b = self._root("b", 40)
        aegis._AGENT_SCAN_FILE_CAP = 3000
        aegis._AGENT_SCAN_ROOT_CAP = 10

        aegis.AGENT_CONFIG_ROOTS = (a,)
        aegis._agent_config_files()
        fp_one = aegis.check_agent_surface_coverage()[0]["fingerprint"]

        aegis.AGENT_CONFIG_ROOTS = (a, b)
        aegis._agent_config_files()
        fp_two = aegis.check_agent_surface_coverage()[0]["fingerprint"]

        self.assertNotEqual(fp_one, fp_two,
                            "b becoming starved must re-alert, not hide")


if __name__ == "__main__":
    unittest.main()
