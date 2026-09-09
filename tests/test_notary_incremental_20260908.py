#!/usr/bin/env python3
"""The hourly anchor read re-parsed 24h of the log store for anchors it had
already seen: 13.2s CPU under the agent's background QoS for 115 anchors,
against 3.3s for the one hour actually appended since (2026-09-08).

The read now remembers, in process, what it has read back and reads only what
the store appended since -- with the window's MEANING intact: anchors age out
of memory at `hours` exactly as the store's window would have dropped them,
every conflict is judged over the whole retained set, a timeout leaves memory
where it was, and a fresh process (a by-hand `aegis.py notary`) always reads
the whole window."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

H = "a" * 64
H2 = "b" * 64
H3 = "c" * 64
T0 = 1_760_000_000          # an arbitrary epoch; every stamp is relative to it


def _line(ts, seq, head):
    """One syslog-style `log show` line, stamped in UTC (+0000)."""
    from datetime import datetime, timezone
    stamp = datetime.fromtimestamp(ts, timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.000000+0000")
    return "%s  localhost logger[123]: %s seq=%d head=%s" % (
        stamp, aegis._NOTARY_MARK, seq, head)


class _Mac(unittest.TestCase):
    """A macOS anchor channel with `run` scripted and the clock pinned."""

    def setUp(self):
        self._saved = {n: getattr(aegis, n) for n in
                       ("run", "IS_MAC", "IS_LINUX", "IS_WIN", "_epoch",
                        "_NOTARY_ANCHOR_MEMORY")}
        for n, v in self._saved.items():
            self.addCleanup(setattr, aegis, n, v)
        aegis.IS_MAC, aegis.IS_LINUX, aegis.IS_WIN = True, False, False
        aegis._NOTARY_ANCHOR_MEMORY = None
        aegis._UNEXAMINED.clear()
        self.now = T0
        aegis._epoch = lambda value=None: (self.now if value is None
                                           else self._saved["_epoch"](value))
        self.calls = []
        self.replies = []

        def run(argv, timeout=15, extra_env=None):
            self.calls.append(list(argv))
            return self.replies.pop(0)
        aegis.run = run

    def reply(self, *lines, rc=0):
        self.replies.append(("\n".join(lines) + "\n", "", rc))

    def argv(self, i):
        return self.calls[i]


class TestFirstReadIsTheWholeWindow(_Mac):
    def test_a_fresh_process_reads_last_24h(self):
        self.reply(_line(T0 - 100, 1, H), _line(T0 - 50, 2, H2))
        anchors, conflicts = aegis._notary_read_anchors(hours=24)
        self.assertIn("--last", self.argv(0))
        self.assertIn("24h", self.argv(0))
        self.assertNotIn("--start", self.argv(0))
        self.assertEqual({1: H, 2: H2}, anchors)
        self.assertEqual(set(), conflicts)

    def test_the_read_is_remembered(self):
        self.reply(_line(T0 - 100, 1, H))
        aegis._notary_read_anchors(hours=24)
        mem = aegis._NOTARY_ANCHOR_MEMORY
        self.assertEqual(T0, mem["until"])
        self.assertEqual({(1, H): T0 - 100}, mem["rows"])


class TestLaterReadsAreIncremental(_Mac):
    def setUp(self):
        super().setUp()
        self.reply(_line(T0 - 100, 1, H), _line(T0 - 50, 2, H2))
        aegis._notary_read_anchors(hours=24)
        self.now = T0 + 3600

    def test_the_second_read_starts_where_the_first_stopped(self):
        self.reply(_line(T0 + 3000, 3, H3))
        anchors, conflicts = aegis._notary_read_anchors(hours=24)
        argv = self.argv(1)
        self.assertIn("--start", argv)
        self.assertNotIn("--last", argv)
        start = argv[argv.index("--start") + 1]
        from datetime import datetime
        started = int(datetime.strptime(start, "%Y-%m-%d %H:%M:%S%z")
                      .timestamp())
        self.assertEqual(T0 - aegis._NOTARY_ANCHOR_OVERLAP, started,
                         "re-read a little past the last read for logd lag")
        # Everything from the first read is still there, plus the new one.
        self.assertEqual({1: H, 2: H2, 3: H3}, anchors)
        self.assertEqual(set(), conflicts)

    def test_an_anchor_re_read_in_the_overlap_is_not_a_conflict(self):
        self.reply(_line(T0 - 50, 2, H2))   # the same line, seen again
        anchors, conflicts = aegis._notary_read_anchors(hours=24)
        self.assertEqual({1: H, 2: H2}, anchors)
        self.assertEqual(set(), conflicts)

    def test_a_shadow_anchor_appended_later_is_a_conflict(self):
        # The siege finding, across reads: the genuine anchor was read an
        # hour ago, the forged one lands now. Last-wins must not hide it.
        self.reply(_line(T0 + 3000, 1, H3))
        anchors, conflicts = aegis._notary_read_anchors(hours=24)
        self.assertEqual({1}, conflicts)
        self.assertEqual(H3, anchors[1], "chronological, last wins")

    def test_an_empty_hour_is_an_answer_not_an_absent_channel(self):
        # `log show` prints a header even with nothing matching; and rc 0
        # with no output at all must still mean "read, found nothing new".
        self.replies.append(("", "", 0))
        res = aegis._notary_read_anchors(hours=24)
        self.assertIsNotNone(res)
        self.assertEqual({1: H, 2: H2}, res[0])

    def test_anchors_age_out_of_memory_at_the_window(self):
        # Memory is 24h-50s old (still incremental); seq 1 at T0-100 is now
        # 24h+50s old and gone, seq 2 at T0-50 is exactly 24h and kept.
        self.now = T0 + 24 * 3600 - 50
        self.reply(_line(self.now - 10, 4, H3))
        anchors, _c = aegis._notary_read_anchors(hours=24)
        self.assertIn("--start", self.argv(1))
        self.assertNotIn(1, anchors)
        self.assertEqual({2: H2, 4: H3}, anchors)

    def test_a_timeout_leaves_memory_where_it_was(self):
        self.replies.append(("", "timeout", 124))
        self.assertIs(aegis._notary_read_anchors(hours=24),
                      aegis._NOTARY_READ_TIMEOUT)
        self.assertEqual(T0, aegis._NOTARY_ANCHOR_MEMORY["until"],
                         "a failed read must not advance the watermark")
        rows = [r for rs in aegis._UNEXAMINED.values() for r in rs]
        blob = " ".join("%s %s" % (r[0], r[1]) for r in rows)
        self.assertIn("notary anchors", blob)
        self.assertIn("tamper-evidence", blob)
        # ...and the next read resumes from the same point.
        self.reply(_line(T0 + 3000, 3, H3))
        aegis._notary_read_anchors(hours=24)
        self.assertIn("--start", self.argv(2))

    def test_memory_older_than_the_window_starts_over(self):
        self.now = T0 + 25 * 3600
        self.reply(_line(self.now - 10, 9, H3))
        anchors, _c = aegis._notary_read_anchors(hours=24)
        self.assertIn("--last", self.argv(1))
        self.assertEqual({9: H3}, anchors, "stale memory is not merged")

    def test_a_clock_that_went_backwards_starts_over(self):
        self.now = T0 - 10
        self.reply(_line(self.now - 10, 9, H3))
        aegis._notary_read_anchors(hours=24)
        self.assertIn("--last", self.argv(1))


class TestRowParsing(unittest.TestCase):
    def test_a_line_without_a_stamp_is_dated_now(self):
        rows = aegis._notary_anchor_rows(
            "%s seq=7 head=%s\n" % (aegis._NOTARY_MARK, H), T0)
        self.assertEqual([(T0, 7, H)], rows)

    def test_a_real_log_show_line_parses(self):
        line = ("2026-09-08 21:26:56.089479-0700  localhost logger[86350]: "
                "AEGIS-ANCHOR seq=1113 head=" + H)
        rows = aegis._notary_anchor_rows(line, T0)
        from datetime import datetime
        want = int(datetime.strptime("2026-09-08 21:26:56-0700",
                                     "%Y-%m-%d %H:%M:%S%z").timestamp())
        self.assertEqual([(want, 1113, H)], rows)

    def test_lines_without_the_marker_are_ignored(self):
        self.assertEqual([], aegis._notary_anchor_rows(
            "Timestamp  (process)[PID]\nlogger[1]: hello\n", T0))


class TestOtherPlatformsAreUntouched(_Mac):
    def test_linux_still_reads_journalctl_and_parses_by_marker(self):
        aegis.IS_MAC, aegis.IS_LINUX = False, True
        self.reply("%s seq=1 head=%s" % (aegis._NOTARY_MARK, H),
                   "%s seq=1 head=%s" % (aegis._NOTARY_MARK, H2))
        anchors, conflicts = aegis._notary_read_anchors(hours=24)
        self.assertEqual("journalctl", self.argv(0)[0])
        self.assertEqual({1: H2}, anchors)
        self.assertEqual({1}, conflicts)
        self.assertIsNone(aegis._NOTARY_ANCHOR_MEMORY,
                          "memory is the macOS reader's alone")


if __name__ == "__main__":
    unittest.main()
