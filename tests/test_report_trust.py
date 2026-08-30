"""The report is the only thing the operator actually reads.

Three defects found on the live store 2026-08-29, all of the same shape: the
report stated things about THIS scan that were not true of this scan.

  · process.enumerate emitted health only when it FAILED, so one bad scan on
    08-26 pinned the stored row to DEGRADED and the report told the operator
    "the process table could not be read this scan" every hour for three days
    while it read fine.
  · Health is stored per sensor and read back whole, so a sensor that stops
    running keeps its last row forever — and one that stopped while OK kept
    counting toward "38/40 sensors OK" indefinitely. Silent coverage loss,
    rendered green, which is the failure `doctor`'s "unknown is never green"
    rule exists to prevent and which the report did not apply.
  · A monitor that stopped running altogether produced no line at all, because
    every line described the scan you were reading.

A coverage section that is wrong on most scans is one the reader learns to
skip — and then the warning that matters gets skipped with it.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


def _h(sensor_id, status="OK", last_run_at=1000, detail=""):
    return {"sensor_id": sensor_id, "status": status, "detail": detail,
            "last_run_at": last_run_at, "duration_ms": 0, "item_count": 0}


class StaleCoverageIsNeverGreen(unittest.TestCase):
    def test_a_sensor_that_did_not_run_is_not_counted_ok(self):
        live, stale, perm, deg = aegis._coverage_split(
            [_h("a"), _h("b"), _h("dead", last_run_at=100)])
        self.assertEqual([h["sensor_id"] for h in live], ["a", "b"])
        self.assertEqual([h["sensor_id"] for h in stale], ["dead"])
        self.assertEqual((perm, deg), ([], []))

    def test_a_stale_failure_is_reported_as_unknown_not_as_current(self):
        """The live case: a sensor that failed once, days ago, and has not run
        since must not be described in the present tense."""
        _live, stale, _p, deg = aegis._coverage_split(
            [_h("ok"), _h("process.enumerate", "DEGRADED", last_run_at=1)])
        self.assertEqual([h["sensor_id"] for h in stale], ["process.enumerate"])
        self.assertEqual(deg, [], "a stale row is not a current failure")

    def test_a_privilege_wall_is_permanent_not_a_fresh_failure(self):
        _l, _s, perm, deg = aegis._coverage_split(
            [_h("a"), _h("surface.btm", "PRIVILEGED")])
        self.assertEqual([h["sensor_id"] for h in perm], ["surface.btm"])
        self.assertEqual(deg, [])

    def test_a_current_failure_is_still_a_current_failure(self):
        """The safety half: quieting repetition must not quiet the real thing."""
        _l, _s, _p, deg = aegis._coverage_split(
            [_h("a"), _h("b", "DEGRADED")])
        self.assertEqual([h["sensor_id"] for h in deg], ["b"])

    def test_an_empty_or_unstamped_batch_degrades_gracefully(self):
        self.assertEqual(aegis._coverage_split([]), ([], [], [], []))
        live, stale, _p, _d = aegis._coverage_split([{"sensor_id": "x",
                                                      "status": "OK"}])
        self.assertEqual(len(live), 1)
        self.assertEqual(stale, [])


class OneScanStampsOneTime(unittest.TestCase):
    """The staleness rule compares each row's last_run_at against the newest
    in the batch, which is only sound because _record_health stamps a SINGLE
    `now` across every sensor in a scan. If that ever became a per-sensor
    time, healthy sensors a second behind the fastest would start reporting
    DID NOT RUN — a brand-new false alarm, in the one section this work exists
    to make trustworthy. Pinned here so the change that would break it fails
    loudly instead."""

    def test_record_health_stamps_the_whole_batch_identically(self):
        import sqlite3
        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        db.executescript("""
            CREATE TABLE sensor_status(sensor_id TEXT PRIMARY KEY, status TEXT,
              last_run_at INT, last_ok_at INT, duration_ms INT, item_count INT,
              detail TEXT, consecutive_failures INT, episode_started_at INT);
            CREATE TABLE events(id INTEGER PRIMARY KEY, occurred_at INT,
              observed_at INT, source TEXT, event_type TEXT, incident_id INT,
              data_json TEXT);
            CREATE TABLE incidents(id INTEGER PRIMARY KEY, kind TEXT,
              correlation_key TEXT, title TEXT, severity TEXT, status TEXT,
              created_at INT, first_seen INT, last_seen INT, updated_at INT,
              reminder_count INT DEFAULT 0, next_reminder_at INT,
              last_notified_at INT, resolution TEXT, subject_json TEXT,
              last_novel_at INT);
            CREATE TABLE incident_events(incident_id INT, event_id INT,
              PRIMARY KEY(incident_id, event_id));
        """)
        batch = [{"sensor_id": "a", "status": "OK", "detail": "",
                  "duration_ms": 1, "item_count": 0},
                 {"sensor_id": "b", "status": "OK", "detail": "",
                  "duration_ms": 9999, "item_count": 0}]
        with db:
            aegis._record_health(db, batch, 1_700_000_000)
        stamps = {r[0] for r in db.execute(
            "SELECT last_run_at FROM sensor_status")}
        db.close()
        self.assertEqual(stamps, {1_700_000_000},
                         "one scan must stamp one time, or _coverage_split "
                         "will call healthy sensors stale")
        self.assertEqual(aegis._coverage_split(
            [_h("a", last_run_at=1_700_000_000),
             _h("b", last_run_at=1_700_000_000)])[1], [])


class TheReportSaysWhetherItIsRunning(unittest.TestCase):
    def test_a_normal_cadence_reads_as_watched(self):
        line = aegis._liveness_line(aegis._epoch() - 3600)
        self.assertIn("Watched", line)
        self.assertIn("1 hour ago", line)

    def test_a_watch_gap_is_called_out(self):
        """A monitor that silently stopped is its worst failure, and it was
        the one thing the report could not show."""
        line = aegis._liveness_line(aegis._epoch() - 11 * 3600)
        self.assertIn("Watch gap", line)
        self.assertIn("not observed", line)

    def test_no_previous_scan_claims_nothing(self):
        for value in (None, 0, "yesterday"):
            self.assertEqual(aegis._liveness_line(value), "")


class TheBriefReportRendersAllOfIt(unittest.TestCase):
    def _render(self, health, prev=None):
        return aegis._brief_report([], [], [], health, False, 0, 0,
                                   prev_scan_at=prev)

    def test_a_stale_sensor_is_named_and_counted_apart(self):
        md = self._render([_h("a"), _h("gone", last_run_at=1)])
        self.assertIn("1 sensor did not run", md)
        self.assertIn("gone: DID NOT RUN", md)
        self.assertIn("1/2 sensors OK", md)

    def test_a_permanent_gap_is_counted_but_not_re_explained(self):
        md = self._render([_h("a"), _h("surface.btm", "PRIVILEGED",
                                       detail="needs admin authorization")])
        self.assertIn("1 permanent gap", md)
        self.assertNotIn("needs admin authorization", md,
                         "the full explanation belongs in --full, not in "
                         "every hourly report")
        self.assertIn("surface.btm", md)

    def test_a_real_failure_keeps_its_full_explanation(self):
        md = self._render([_h("a"), _h("b", "DEGRADED", detail="disk on fire")])
        self.assertIn("disk on fire", md)

    def test_the_liveness_line_reaches_the_report(self):
        self.assertIn("Watched", self._render([_h("a")],
                                              prev=aegis._epoch() - 600))
        self.assertNotIn("Watched", self._render([_h("a")]))


if __name__ == "__main__":
    unittest.main()
