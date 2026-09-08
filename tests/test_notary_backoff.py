#!/usr/bin/env python3
"""A failed anchor read is still an attempt, and must not be silent.

`check_notary` splits into a cheap local half (chain linkage, per-link MAC,
sequence gaps) run every scan, and an expensive external half -- on macOS a
`log show --last 24h`, capped at 90s -- gated to hourly. Two defects met in
that gate.

1. The gate only advanced on SUCCESS, so a timeout re-opened it immediately and
   the next scan paid the full 90s again. Live evidence from the reference Mac,
   2026-09-07: four consecutive 90s reads at 01:43, 01:59, 02:18 and 02:22 --
   6.1 minutes inside 40, on a 10-minute cadence -- ending only when one call
   happened to succeed. An immediate retry re-reads the SAME 24h window, so it
   buys no coverage; it is pure cost.

2. Each of those four timeouts recorded status OK, empty detail, item_count 0.
   The only root-corroborated half of the tamper-evidence check did not run,
   four times running, and the sensor reported healthy -- byte-identical to
   "I checked and the chain is intact".

Fixed together on purpose: backing off lengthens the blind spot, so it may not
ship without making that spot visible.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aegis  # noqa: E402


class NotaryGate(unittest.TestCase):
    def setUp(self):
        self._saved = {k: getattr(aegis, k) for k in
                       ("_NOTARY_ANCHOR_LAST", "_NOTARY_ANCHOR_FAILS",
                        "_notary_verify", "NOTARY_FILE")}
        self.addCleanup(self._restore)
        aegis._NOTARY_ANCHOR_LAST = 0
        aegis._NOTARY_ANCHOR_FAILS = 0
        aegis.NOTARY_FILE = __file__          # must merely exist
        self.calls = []

    def _restore(self):
        for k, v in self._saved.items():
            setattr(aegis, k, v)

    def _verify_returns(self, status):
        def fake(with_anchors=False):
            self.calls.append(with_anchors)
            return [], 0, status
        aegis._notary_verify = fake

    def test_a_failed_read_is_not_retried_on_the_very_next_scan(self):
        """The storm: without this, every scan pays the 90s again."""
        self._verify_returns("timeout")
        aegis.check_notary()
        self.assertEqual(self.calls, [True], "first scan must attempt")
        for _ in range(4):
            aegis.check_notary()
        self.assertEqual(self.calls.count(True), 1,
                         "a failed anchor read was retried immediately")

    def test_the_backoff_grows_with_consecutive_failures(self):
        self._verify_returns("timeout")
        aegis.check_notary()
        first = aegis._NOTARY_ANCHOR_FAILS
        due_after_one = aegis._NOTARY_ANCHOR_LAST
        aegis._NOTARY_ANCHOR_LAST = 0          # force a second attempt
        aegis.check_notary()
        self.assertEqual(aegis._NOTARY_ANCHOR_FAILS, first + 1)
        self.assertGreater(aegis._NOTARY_ANCHOR_LAST, due_after_one - 1,
                           "the second failure must wait at least as long")

    def test_the_backoff_never_exceeds_the_normal_interval(self):
        """A broken channel must still be retried hourly, not exponentially
        forever -- the local half runs every scan regardless, but the external
        half is the only root-corroborated evidence there is."""
        self._verify_returns("timeout")
        for _ in range(20):
            aegis._NOTARY_ANCHOR_LAST = 0
            aegis.check_notary()
        now = aegis._epoch()
        self.assertLessEqual(now - aegis._NOTARY_ANCHOR_LAST,
                             aegis._NOTARY_ANCHOR_INTERVAL + 1)
        self.assertGreaterEqual(aegis._NOTARY_ANCHOR_LAST, 0)

    def test_a_success_clears_the_backoff_and_stamps_the_full_interval(self):
        self._verify_returns("timeout")
        aegis.check_notary()
        self.assertGreater(aegis._NOTARY_ANCHOR_FAILS, 0)
        aegis._NOTARY_ANCHOR_LAST = 0
        self._verify_returns("ok:3-anchors-matched")
        aegis.check_notary()
        self.assertEqual(aegis._NOTARY_ANCHOR_FAILS, 0)
        self.assertGreaterEqual(aegis._NOTARY_ANCHOR_LAST, aegis._epoch() - 1)

    def test_an_unreadable_channel_still_never_arms_the_throttle(self):
        """The pre-existing contract, deliberately preserved: a platform whose
        log store cannot be read AT ALL is retried, not treated as checked.
        That case fails instantly and costs nothing, so it needs no backoff --
        only the 90s timeout does. Conflating the two is what broke this."""
        self._verify_returns("unavailable")
        aegis.check_notary()
        self.assertEqual(0, aegis._NOTARY_ANCHOR_LAST)
        self.assertEqual(0, aegis._NOTARY_ANCHOR_FAILS)


class NotaryNonAnswerIsRecorded(unittest.TestCase):
    def setUp(self):
        self._run = aegis.run
        self.addCleanup(lambda: setattr(aegis, "run", self._run))
        aegis._UNEXAMINED.clear()

    def test_a_timed_out_anchor_read_is_recorded_as_unexamined(self):
        aegis.run = lambda *a, **k: ("", "timeout", 124)
        # The sentinel, not None: None means "this platform has no channel",
        # which must keep being retried. Only the timeout backs off.
        self.assertIs(aegis._notary_read_anchors(hours=24),
                      aegis._NOTARY_READ_TIMEOUT)
        rows = [r for rs in aegis._UNEXAMINED.values() for r in rs]
        self.assertTrue(rows, "a timed-out anchor read recorded nothing")
        blob = " ".join("%s %s" % (r[0], r[1]) for r in rows)
        self.assertIn("notary anchors", blob)
        self.assertIn("tamper-evidence", blob)

    def test_an_absent_channel_is_not_a_timeout(self):
        """rc 127 is "the binary is not here" -- a different answer needing
        opposite handling, and it must not be logged as a coverage gap on
        every scan of a platform that simply has no anchor channel."""
        aegis.run = lambda *a, **k: ("", "not-found", 127)
        self.assertIsNone(aegis._notary_read_anchors(hours=24))
        self.assertEqual([r for rs in aegis._UNEXAMINED.values() for r in rs], [])

    def test_a_successful_read_records_no_gap(self):
        aegis.run = lambda *a, **k: ("nothing matching here", "", 0)
        aegis._notary_read_anchors(hours=24)
        rows = [r for rs in aegis._UNEXAMINED.values() for r in rs]
        self.assertEqual(rows, [], "a successful read must not report a gap")


if __name__ == "__main__":
    unittest.main()
