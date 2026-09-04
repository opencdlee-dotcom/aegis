#!/usr/bin/env python3
"""The full structural check is a daily job, not a per-scan one.

`PRAGMA quick_check` reads every page of the event store. Measured on the
reference machine's live 57 MB store, warm: 0.26s — not a crisis, and worth
being precise about, because a wedge was initially suspected here and the
measurement is what ruled it out. What remains true is that watch mode starts
a scan as often as WATCH_MIN_GAP_SECS allows, so per-scan meant re-reading 57
MB about once a minute on an agent that otherwise runs Background/LowPriorityIO
/nice 10.

The cheap half stays per-scan, and it is the half that matters: quick_check
verifies page structure and says nothing about whether the tables this program
needs still exist — a dropped table reads as a perfectly healthy database.
"""
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


class IntegrityCadence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis-cadence-")
        self.state = os.path.join(self.tmp, ".aegis")
        os.makedirs(self.state, mode=0o700)
        self._saved = {n: getattr(aegis, n)
                       for n in ("STATE_DIR", "RUN_LOG", "EVENT_DB")}
        aegis.STATE_DIR = self.state
        aegis.RUN_LOG = os.path.join(self.state, "run.log")
        aegis.EVENT_DB = os.path.join(self.state, "aegis.db")

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(aegis, n, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_a_fresh_install_is_due(self):
        self.assertTrue(aegis._integrity_scan_due())

    def test_marking_it_makes_it_not_due(self):
        aegis._mark_integrity_scanned()
        self.assertFalse(aegis._integrity_scan_due())

    def test_it_comes_due_again_after_the_cadence(self):
        aegis._mark_integrity_scanned()
        later = int(time.time()) + aegis.INTEGRITY_SCAN_EVERY_SECS + 1
        self.assertTrue(aegis._integrity_scan_due(now=later))

    def test_an_unreadable_stamp_is_due(self):
        """Forgetting when it last ran is not a reason to skip it."""
        with open(aegis._integrity_stamp(), "w", encoding="utf-8") as fh:
            fh.write("not json")
        self.assertTrue(aegis._integrity_scan_due())

    def test_a_stamp_from_the_future_is_due(self):
        """A clock that jumped backwards must not park the check forever."""
        aegis.save_json(aegis._integrity_stamp(),
                        {"epoch": int(time.time()) + 86400 * 30})
        self.assertTrue(aegis._integrity_scan_due())

    def test_the_cheap_checks_still_run_every_scan(self):
        """The per-scan half is the one that catches a dropped table, which
        quick_check would call a perfectly healthy database."""
        aegis.init_event_store()
        aegis._mark_integrity_scanned()          # structural half is NOT due
        self.assertEqual([], aegis.check_store_integrity())

        db = aegis._event_connection()
        try:
            db.execute("DROP TABLE incidents")
            db.commit()
        finally:
            db.close()
        found = aegis.check_store_integrity()
        self.assertTrue(found, "a dropped table must be caught between "
                               "structural runs, not wait for the cadence")
        self.assertEqual("HIGH", found[0]["severity"])


if __name__ == "__main__":
    unittest.main()
