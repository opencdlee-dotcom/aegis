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
import contextlib
import io
import os
import sys
import tempfile
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


class GreenMeansGreen(unittest.TestCase):
    """The verdict ladder's worst state was a true sentence that misled.

    With fourteen incidents waiting and nothing new that scan, the headline
    read "Nothing new" over a green dot — accurate, and exactly the thing that
    stops a reader looking. Stale red is annoying; misleading green is what
    costs you the next real alert."""

    @staticmethod
    def _inc(n, severity="HIGH"):
        return [{"id": i, "severity": severity, "status": "OPEN",
                 "title": "t", "evidence_count": 1} for i in range(n)]

    def _head(self, new_findings, incidents):
        return aegis._brief_report([], new_findings, incidents, [], False,
                                   0, 0).splitlines()[2]

    def test_a_backlog_is_never_green(self):
        head = self._head([], self._inc(14))
        self.assertIn("14 items waiting on you", head)
        self.assertNotIn(aegis.VERDICT_ICON["clear"], head)

    def test_clear_means_nothing_new_and_nothing_waiting(self):
        head = self._head([], [])
        self.assertIn("Protected", head)
        self.assertIn(aegis.VERDICT_ICON["clear"], head)

    def test_one_waiting_item_reads_singular(self):
        self.assertIn("1 item waiting on you", self._head([], self._inc(1)))

    def test_a_new_alert_still_outranks_the_backlog(self):
        """The safety half: a fresh HIGH must not be demoted to 'waiting'."""
        f = aegis.finding("HIGH", "process", "t", "d", "process:x:y:z")
        self.assertIn("NEW alert", self._head([f], self._inc(14)))

    def test_an_open_critical_still_outranks_the_backlog(self):
        head = self._head([], self._inc(3, severity="CRITICAL"))
        self.assertIn("CRITICAL", head)

    def test_the_self_check_catches_a_green_headline_over_a_queue(self):
        problems = aegis._report_self_check("clear", [], [], self._inc(4))
        self.assertTrue(any("waiting" in p for p in problems))
        self.assertEqual(aegis._report_self_check("review", [], [],
                                                  self._inc(4)), [])
        self.assertTrue(aegis._report_self_check("review", [], [], []))


class TheReportIsTrueWhenRead(unittest.TestCase):
    """cmd_report used to `cat` a file frozen at scan time, so resolving an
    incident left the report insisting it was still open until the next hourly
    scan — on the reference machine, "1 CRITICAL incident still open" in red,
    after the operator had closed it."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_rep_")
        self.saved = tuple(getattr(aegis, n) for n in
                           ("STATE_DIR", "EVENT_DB", "LATEST_JSON", "LATEST_MD",
                            "BASELINE"))
        aegis.STATE_DIR = self.tmp
        for name, fn in (("EVENT_DB", "t.db"), ("LATEST_JSON", "latest.json"),
                         ("LATEST_MD", "latest.md"),
                         ("BASELINE", "baseline.json")):
            setattr(aegis, name, os.path.join(self.tmp, fn))

    def tearDown(self):
        for name, value in zip(("STATE_DIR", "EVENT_DB", "LATEST_JSON",
                                "LATEST_MD", "BASELINE"), self.saved):
            setattr(aegis, name, value)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _render(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            aegis.cmd_report()
        return buf.getvalue()

    def test_resolving_an_incident_changes_the_report_without_a_rescan(self):
        now = aegis._epoch()
        db = aegis._event_connection()
        with db:
            db.execute(
                "INSERT INTO incidents(kind,correlation_key,title,severity,"
                "status,created_at,first_seen,last_seen,updated_at,"
                "reminder_count) VALUES('signal',?,?,'HIGH','OPEN',?,?,?,?,0)",
                ("signal:x:y", "a thing", now, now, now, now))
            iid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.close()
        aegis.save_json(aegis.LATEST_JSON, {
            "ts": "t", "findings": [], "incidents": [], "sensor_health": [],
            "new_fingerprints": [], "scan_at": now, "first_run": False,
            "aged": 0, "quiet": 0})
        self.assertIn("1 item waiting on you", self._render())
        aegis.transition_incident(iid, "FALSE_POSITIVE",
                                  reason_code="benign-positive")
        after = self._render()
        self.assertIn("Protected", after)
        self.assertNotIn("waiting on you", after)

    def test_scan_properties_are_not_recomputed_at_read_time(self):
        """Only the incident state is live. The findings and the
        new-since-last-scan set are properties OF that scan; recomputing them
        here would falsify them, not refresh them."""
        now = aegis._epoch()
        f = aegis.finding("MEDIUM", "process", "t", "d", "process:a:b:c")
        aegis.save_json(aegis.LATEST_JSON, {
            "ts": "t", "findings": [f], "incidents": [], "sensor_health": [],
            "new_fingerprints": [f["fingerprint"]], "scan_at": now,
            "first_run": False, "aged": 0, "quiet": 0})
        out = self._render()
        self.assertIn("1 new finding", out)
        self.assertIn("against 1 finding(s)", out)


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


class StatusLeadsWithTheAnswer(unittest.TestCase):
    """`status` printed forty-odd rows in source order, so its real problems
    sat among green ticks: on the reference machine XProtect definitions 93
    days stale was line 8 of 45, and stale intel feeds were never noticed at
    all until the verdict counted them. An operator asking "am I OK?" had to
    audit every row to answer it."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_status_")
        self.saved = tuple(getattr(aegis, n) for n in
                           ("STATE_DIR", "EVENT_DB", "BASELINE"))
        aegis.STATE_DIR = self.tmp
        aegis.EVENT_DB = os.path.join(self.tmp, "t.db")
        aegis.BASELINE = os.path.join(self.tmp, "baseline.json")

    def tearDown(self):
        for name, value in zip(("STATE_DIR", "EVENT_DB", "BASELINE"),
                               self.saved):
            setattr(aegis, name, value)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _status(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            aegis.cmd_status()
        return buf.getvalue()

    def test_the_verdict_is_the_first_line(self):
        first = self._status().splitlines()[0]
        self.assertTrue(
            any(icon in first for icon in ("🔴", "🟡", "🟢")),
            "the answer must precede the evidence, not follow 45 rows of it")

    def test_every_problem_row_is_repeated_at_the_top(self):
        out = self._status()
        head, _sep, _rest = out.partition("# Aegis hardening posture")
        for line in out.splitlines():
            if line.strip()[:1] == "✗":
                self.assertIn(line, head,
                              "a problem must appear above the fold")

    def test_the_full_column_is_still_printed(self):
        """Nothing is removed to make the surface look calmer — the verdict is
        an index into the evidence, not a replacement for it."""
        out = self._status()
        self.assertIn("# Aegis hardening posture", out)
        self.assertIn("# Survivability", out)

    def test_a_stale_sensor_is_not_a_green_tick(self):
        """status reads the stored health rows, so without the staleness rule
        a sensor that stopped running showed OK forever — in the one place an
        operator goes to check exactly that."""
        now = aegis._epoch()
        db = aegis._event_connection()
        with db:
            for sid, at in (("alive", now), ("dead", now - 5 * 86400)):
                db.execute(
                    "INSERT INTO sensor_status(sensor_id,status,last_run_at,"
                    "last_ok_at,duration_ms,item_count,detail,"
                    "consecutive_failures) VALUES(?,?,?,?,0,0,'',0)",
                    (sid, "OK", at, at))
        db.close()
        out = self._status()
        self.assertRegex(out, r"✗\s+dead\s+DID NOT RUN")
        self.assertRegex(out, r"✓\s+alive")


if __name__ == "__main__":
    unittest.main()
