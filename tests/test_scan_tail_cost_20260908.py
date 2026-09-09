#!/usr/bin/env python3
"""Two reorders in the scan's tail, each with a counted delta and an identical
result (2026-09-08 profile, after the log-show and quick-look fixes):

  * the correlator re-ran a chain rule's right-hand predicate for every left
    that passed, over every observation in the 30-minute window -- 3153 rows
    live, so ~230 x 3153 calls for one rule; it was the largest pure-Python
    cost in a scan, and pure Python pays the agent's background-QoS
    multiplier in full;
  * the agent-surface walk lstat'd every file it listed (~30,000) to skip
    symlinks, before applying the name filter that admits a few hundred.

Both are pinned as counts, not timings, and each against a brute-force oracle
so the output is provably the same."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402
from test_regression import Sandbox  # noqa: E402


class TestCorrelationPairs(unittest.TestCase):
    def setUp(self):
        self._same = aegis._same_entity
        self.addCleanup(setattr, aegis, "_same_entity", self._same)
        aegis._same_entity = lambda a, b: a["e"] == b["e"]
        # 120 observations: ids 0..119, one every 10s, the category cycling
        # through four values and the entity through three, independently,
        # so lefts and rights share entities across categories.
        cats = ("persistence", "process", "hot-dir", "behavior")
        self.obs = [(i, 1000 + 10 * i,
                     {"e": (i // 4) % 3, "category": cats[i % 4]})
                    for i in range(120)]
        self.left_calls = []
        self.right_calls = []

    def left(self, f):
        self.left_calls.append(f)
        return f["category"] == "persistence"

    def right(self, f):
        self.right_calls.append(f)
        return f["category"] in ("process", "behavior")

    def _oracle(self, window):
        out = []
        for li, la, lf in self.obs:
            if not self.left(lf):
                continue
            for ri, ra, rf in self.obs:
                if li == ri or not self.right(rf):
                    continue
                if abs(la - ra) > window:
                    continue
                if not aegis._same_entity(lf, rf):
                    continue
                out.append((li, ri, lf, rf))
        return out

    def test_each_predicate_runs_once_per_observation(self):
        pairs = list(aegis._correlation_pairs(self.obs, self.left, self.right,
                                              900))
        self.assertTrue(pairs, "the fixture must produce pairs to be a test")
        self.assertEqual(len(self.obs), len(self.left_calls))
        self.assertEqual(len(self.obs), len(self.right_calls),
                         "right_pred must not run once per (left, right)")

    def test_the_pairs_and_their_order_match_the_brute_force_form(self):
        for window in (900, 50, 0):
            want = self._oracle(window)
            self.left_calls, self.right_calls = [], []
            got = list(aegis._correlation_pairs(self.obs, self.left,
                                                self.right, window))
            self.assertEqual(want, got, "window=%d" % window)

    def test_no_left_means_the_right_predicate_never_runs(self):
        got = list(aegis._correlation_pairs(
            self.obs, lambda f: False, self.right, 900))
        self.assertEqual([], got)
        self.assertEqual([], self.right_calls)


class TestAgentWalkStatsOnlyCandidates(Sandbox):
    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.tmp, "agent-root")
        os.makedirs(os.path.join(self.root, "deep"))
        self.noise = []
        for i in range(60):
            p = os.path.join(self.root, "deep" if i % 2 else "",
                             "noise-%d.txt" % i)
            with open(p, "w") as f:
                f.write("x")
            self.noise.append(p)
        self.wanted = [os.path.join(self.root, "settings.json"),
                       os.path.join(self.root, "deep", "config.toml")]
        for p in self.wanted:
            with open(p, "w") as f:
                f.write("{}")
        saved = {n: getattr(aegis, n) for n in
                 ("AGENT_CONFIG_ROOTS", "AGENT_CONFIG_FILES",
                  "_agent_repo_roots")}
        for n, v in saved.items():
            self.addCleanup(setattr, aegis, n, v)
        aegis.AGENT_CONFIG_ROOTS = [self.root]
        aegis.AGENT_CONFIG_FILES = []
        aegis._agent_repo_roots = lambda: ([], [])

    def _count_islink(self):
        calls = []
        real = os.path.islink

        def counting(p):
            calls.append(p)
            return real(p)
        os.path.islink = counting
        self.addCleanup(setattr, os.path, "islink", real)
        return calls

    def test_only_name_qualified_files_are_stat_checked(self):
        calls = self._count_islink()
        found = sorted(aegis._agent_config_files())
        self.assertEqual(sorted(self.wanted), found)
        # os.walk itself lstat's each SUBDIRECTORY it descends (to refuse
        # symlinked dirs); the cost under test is the per-FILE check.
        files = sorted(c for c in calls if os.path.isfile(c))
        self.assertEqual(sorted(self.wanted), files,
                         "an lstat per listed file was the whole cost")

    @unittest.skipIf(os.name != "posix", "symlink creation needs a privilege "
                                         "on Windows; the reorder is portable")
    def test_a_symlinked_candidate_is_still_skipped(self):
        link = os.path.join(self.root, "linked.json")
        os.symlink(self.wanted[0], link)
        found = aegis._agent_config_files()
        self.assertNotIn(link, found)
        self.assertIn(self.wanted[0], found)


if __name__ == "__main__":
    unittest.main()
