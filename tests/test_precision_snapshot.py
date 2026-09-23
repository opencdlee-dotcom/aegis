"""The precision snapshot — the number the fixes are judged on, where the
operator reads, and a regression that surfaces on its own.

`backtest replay` already computes it, but it costs minutes on the live store,
so nothing ran it unless a human remembered to. These tests pin the four
things that make it a loop instead of a command:

  * it is cached, and refreshed from the scan's tail at most once a day — and
    a replay that fails costs the snapshot, never the scan;
  * `report` and `status` print it as one line in a fixed shape;
  * a drop in assay recall is a HIGH finding (it interrupts), a rise of three
    or more in re-alerting noise or teaching evaporation is a MEDIUM one (the
    digest), and a first snapshot, with nothing to compare, is silent;
  * teaching evaporation counts an incident opened AFTER the operator had
    already closed its identity as noise, and not one opened before.
"""
import contextlib
import io
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402
from conftest import SUSPICIOUS_TRUST  # noqa: E402
from test_backtest_replay import NOW, ReplaySandbox  # noqa: E402
from test_regression import Sandbox, needs_real_scan_lock  # noqa: E402

DAY = 86400


def snapshot(epoch, **numbers):
    """A stored snapshot with every number the line and the rules read."""
    snap = {"epoch": epoch, "ts": "t", "days": 30, "noise_reopened": 2,
            "noise_total": 10, "interrupts": 5, "open_cases": 3,
            "assay_routable_interrupting": 9, "assay_routable_total": 9,
            "assay_predicate_passing": 11, "assay_predicate_total": 11,
            "teaching_evaporation": 4, "problems": []}
    snap.update(numbers)
    return snap


class PrecisionSandbox(ReplaySandbox):
    """ReplaySandbox with the scan-path snapshot switched ON (conftest turns
    it off suite-wide, so an ordinary scan test never pays for a replay)."""

    def setUp(self):
        super().setUp()
        self.stub("PRECISION_SNAPSHOT_EVERY_SECS", 24 * 3600)

    def count_replays(self, fail=False):
        calls = []
        real = aegis._backtest_replay

        def counted(*args, **kwargs):
            calls.append(kwargs.get("now"))
            if fail:
                raise RuntimeError("replay exploded")
            return real(*args, **kwargs)

        self.stub("_backtest_replay", counted)
        return calls

    def run_log(self):
        try:
            with open(aegis._run_log_path(), encoding="utf-8") as f:
                return f.read()
        except OSError:
            return ""


class TheSnapshotIsThrottledToOnceADay(PrecisionSandbox):
    def test_runs_once_in_24h_not_twice(self):
        calls = self.count_replays()
        self.assertTrue(aegis._precision_tail(now=NOW))
        self.assertFalse(aegis._precision_tail(now=NOW + 3600))
        self.assertFalse(aegis._precision_tail(now=NOW + DAY - 1))
        self.assertEqual(1, len(calls))
        self.assertTrue(aegis._precision_tail(now=NOW + DAY))
        self.assertEqual(2, len(calls))

    def test_the_snapshot_is_written_with_its_numbers(self):
        self.count_replays()
        aegis._precision_tail(now=NOW)
        snap = aegis.load_json(aegis._precision_path(), None)
        self.assertEqual(os.path.join(aegis.STATE_DIR, "precision.json"),
                         aegis._precision_path())
        for key in aegis._PRECISION_NUMBERS:
            self.assertIsInstance(snap[key], int, key)
        self.assertEqual(NOW, snap["epoch"])
        self.assertNotIn("previous", snap, "a first snapshot has no baseline")

    def test_a_failing_replay_is_logged_and_not_retried_every_scan(self):
        calls = self.count_replays(fail=True)
        self.assertFalse(aegis._precision_tail(now=NOW))
        self.assertIn("precision snapshot failed", self.run_log())
        self.assertIn("replay exploded", self.run_log())
        # The attempt is stamped, so a replay that fails is not re-run on
        # every ten-minute tick for the rest of the day.
        self.assertFalse(aegis._precision_tail(now=NOW + 600))
        self.assertEqual(1, len(calls))
        rec = aegis.load_json(aegis._precision_path(), None)
        self.assertEqual(NOW, rec["attempted"])

    def test_a_failed_refresh_keeps_the_last_good_snapshot(self):
        self.count_replays()
        aegis._precision_tail(now=NOW)
        good = aegis.load_json(aegis._precision_path(), None)
        self.count_replays(fail=True)
        aegis._precision_tail(now=NOW + DAY)
        rec = aegis.load_json(aegis._precision_path(), None)
        self.assertEqual(good["epoch"], rec["epoch"])
        self.assertEqual(good["noise_total"], rec["noise_total"])
        self.assertIn("replay exploded", rec["error"])

    def test_the_second_snapshot_carries_the_first_as_its_baseline(self):
        self.count_replays()
        aegis._precision_tail(now=NOW)
        aegis._precision_tail(now=NOW + DAY)
        snap = aegis.load_json(aegis._precision_path(), None)
        self.assertEqual(NOW, snap["previous"]["epoch"])
        self.assertNotIn("previous", snap["previous"],
                         "the baseline must not nest a chain of snapshots")

    def test_zero_turns_the_scan_path_off(self):
        calls = self.count_replays()
        self.stub("PRECISION_SNAPSHOT_EVERY_SECS", 0)
        self.assertFalse(aegis._precision_tail(now=NOW))
        self.assertEqual([], calls)

    def test_the_numbers_are_the_replays_numbers(self):
        self.seed()
        r = aegis._backtest_replay(days=30, reobserve=True, now=NOW)
        snap = aegis._precision_measure(NOW)
        self.assertEqual(len(r["reopened"]), snap["noise_reopened"])
        self.assertEqual(len(r["noise"]), snap["noise_total"])
        self.assertEqual(sum(b[aegis.ROUTE_INTERRUPT]
                             for b in r["routes"].values()),
                         snap["interrupts"])
        self.assertEqual(len(r["open_cases"]), snap["open_cases"])
        statuses = [row["status"] for row in r["assay"]]
        self.assertEqual(statuses.count("interrupt"),
                         snap["assay_routable_interrupting"])
        self.assertEqual(statuses.count("interrupt")
                         + statuses.count("digest"),
                         snap["assay_routable_total"])
        self.assertEqual(statuses.count("predicate"),
                         snap["assay_predicate_passing"])
        self.assertEqual([], snap["problems"])


@needs_real_scan_lock
class AFailingReplayDoesNotBreakTheScan(Sandbox):
    def setUp(self):
        super().setUp()
        self._saved_every = aegis.PRECISION_SNAPSHOT_EVERY_SECS
        self._saved_replay = aegis._backtest_replay
        aegis.PRECISION_SNAPSHOT_EVERY_SECS = 24 * 3600

    def tearDown(self):
        aegis.PRECISION_SNAPSHOT_EVERY_SECS = self._saved_every
        aegis._backtest_replay = self._saved_replay
        super().tearDown()

    def test_the_scan_completes_and_says_why_there_is_no_snapshot(self):
        def explode(*_a, **_k):
            raise RuntimeError("replay exploded")

        aegis._backtest_replay = explode
        self.assertEqual(0, aegis.cmd_scan(quiet=True))
        with open(aegis._run_log_path(), encoding="utf-8") as f:
            log = f.read()
        self.assertIn("precision snapshot failed", log)
        self.assertIn("scan:", log, "the scan's own line is still written")
        self.assertEqual("ok", aegis.read_heartbeat().get("status"))

    def test_a_scan_refreshes_once_and_the_next_scan_does_not(self):
        calls = []
        real = self._saved_replay

        def counted(*a, **k):
            calls.append(1)
            return real(*a, **k)

        aegis._backtest_replay = counted
        aegis.cmd_scan(quiet=True)
        aegis.cmd_scan(quiet=True)
        self.assertEqual(1, len(calls))
        self.assertTrue(os.path.exists(aegis._precision_path()))


class TheRegressionRules(unittest.TestCase):
    def rules(self, prev, cur):
        return aegis._precision_regressions(prev, cur)

    def test_a_first_snapshot_has_nothing_to_compare(self):
        self.assertEqual([], self.rules(None, snapshot(NOW,
                                                       noise_reopened=50)))

    def test_nothing_moved_is_silent(self):
        self.assertEqual([], self.rules(snapshot(NOW - DAY), snapshot(NOW)))

    def test_a_routable_lane_that_stops_interrupting_is_high(self):
        got = self.rules(snapshot(NOW - DAY),
                         snapshot(NOW, assay_routable_interrupting=8))
        self.assertEqual(1, len(got))
        f = got[0]
        self.assertEqual(("HIGH", "self-protection",
                          "A detector positive control stopped firing"),
                         (f["severity"], f["category"], f["title"]))
        self.assertIn("9", f["detail"])
        self.assertIn("8", f["detail"])

    def test_a_predicate_lane_that_stops_passing_is_high(self):
        got = self.rules(snapshot(NOW - DAY),
                         snapshot(NOW, assay_predicate_passing=10))
        self.assertEqual(["HIGH"], [f["severity"] for f in got])

    def test_noise_rising_by_three_is_medium_and_names_both_numbers(self):
        got = self.rules(snapshot(NOW - DAY, noise_reopened=2),
                         snapshot(NOW, noise_reopened=5))
        self.assertEqual(1, len(got))
        f = got[0]
        self.assertEqual(("MEDIUM", "self-protection", "Precision regressed"),
                         (f["severity"], f["category"], f["title"]))
        self.assertIn("2 -> 5", f["detail"])

    def test_evaporation_rising_by_three_is_medium(self):
        got = self.rules(snapshot(NOW - DAY, teaching_evaporation=4),
                         snapshot(NOW, teaching_evaporation=7))
        self.assertEqual(["MEDIUM"], [f["severity"] for f in got])
        self.assertIn("4 -> 7", got[0]["detail"])

    def test_a_rise_of_two_is_nothing(self):
        self.assertEqual([], self.rules(
            snapshot(NOW - DAY, noise_reopened=2, teaching_evaporation=4),
            snapshot(NOW, noise_reopened=4, teaching_evaporation=6)))

    def test_improvement_is_nothing(self):
        self.assertEqual([], self.rules(
            snapshot(NOW - DAY, noise_reopened=9, teaching_evaporation=9),
            snapshot(NOW, noise_reopened=1, teaching_evaporation=0,
                     assay_routable_interrupting=10)))

    def test_recall_interrupts_and_precision_waits_for_the_digest(self):
        got = self.rules(snapshot(NOW - DAY),
                         snapshot(NOW, assay_routable_interrupting=8,
                                  noise_reopened=9))
        routing = aegis.route_findings(got, seen={})
        by_title = {f["title"]: routing[f["fingerprint"]]["route"]
                    for f in got}
        self.assertEqual(
            {"A detector positive control stopped firing":
                aegis.ROUTE_INTERRUPT,
             "Precision regressed": aegis.ROUTE_DIGEST}, by_title)

    def test_the_fingerprint_is_stable_per_snapshot_and_new_per_regression(self):
        prev = snapshot(NOW - DAY)
        a = self.rules(prev, snapshot(NOW, assay_routable_interrupting=8))
        b = self.rules(prev, snapshot(NOW, assay_routable_interrupting=8))
        c = self.rules(snapshot(NOW), snapshot(NOW + DAY,
                                               assay_routable_interrupting=7))
        self.assertEqual(a[0]["fingerprint"], b[0]["fingerprint"])
        self.assertNotEqual(a[0]["fingerprint"], c[0]["fingerprint"])


class TheSensorReadsTheSnapshot(PrecisionSandbox):
    def test_no_snapshot_is_silent(self):
        self.assertEqual([], aegis.check_precision())

    def test_a_first_snapshot_is_silent(self):
        aegis.save_json(aegis._precision_path(),
                        snapshot(NOW, assay_routable_interrupting=0))
        self.assertEqual([], aegis.check_precision())

    def test_a_regression_against_the_stored_baseline_is_emitted(self):
        cur = snapshot(NOW, assay_routable_interrupting=8)
        cur["previous"] = snapshot(NOW - DAY)
        aegis.save_json(aegis._precision_path(), cur)
        got = aegis.check_precision()
        self.assertEqual(["A detector positive control stopped firing"],
                         [f["title"] for f in got])

    def test_the_sensor_is_scheduled_by_gather_all(self):
        import inspect
        self.assertIn('("precision", check_precision',
                      inspect.getsource(aegis.gather_all))


class TheLineTheOperatorReads(unittest.TestCase):
    LINE = ("Precision (30d replay, 3 hours ago): 2/10 judged-noise would "
            "re-alert · 5 interrupts · assay 9/9 routable + 11/11 predicate "
            "· teaching evaporation 4")

    def test_the_line_format(self):
        snap = snapshot(int(time.time()) - 3 * 3600 - 30)
        self.assertEqual(self.LINE, aegis._precision_line(snap))

    def test_no_snapshot_says_how_to_get_one(self):
        line = aegis._precision_line(None)
        self.assertTrue(line.startswith("Precision (30d replay): "), line)
        self.assertIn("aegis.py precision --refresh", line)

    def test_a_failed_self_check_leads_the_line(self):
        snap = snapshot(int(time.time()) - 60,
                        problems=["2 finding row(s) loaded but the store "
                                  "holds 3"])
        line = aegis._precision_line(snap)
        head = line.split(": ", 1)[1]
        self.assertTrue(head.startswith("SELF-CHECK FAILED"), line)

    def test_a_failed_refresh_is_named_beside_the_stale_numbers(self):
        snap = snapshot(int(time.time()) - 2 * DAY,
                        attempted=int(time.time()) - 60,
                        error="replay exploded")
        line = aegis._precision_line(snap)
        self.assertIn("2 days ago", line)
        self.assertIn("replay exploded", line)


class ReportAndStatusPrintTheLine(Sandbox):
    def setUp(self):
        super().setUp()
        aegis.save_json(os.path.join(self.state, "precision.json"),
                        snapshot(int(time.time()) - 3 * 3600 - 30))

    def capture(self, fn, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            fn(*args)
        return out.getvalue()

    def test_status_prints_it(self):
        out = self.capture(aegis.cmd_status)
        self.assertIn(TheLineTheOperatorReads.LINE, out)

    def test_report_prints_it_with_no_scan_yet(self):
        out = self.capture(aegis.cmd_report)
        self.assertIn(TheLineTheOperatorReads.LINE, out)

    def test_report_prints_it_under_the_brief_report(self):
        now = aegis._epoch()
        aegis.save_json(aegis.LATEST_JSON, {
            "ts": "t", "findings": [], "incidents": [], "sensor_health": [],
            "new_fingerprints": [], "scan_at": now, "first_run": False,
            "aged": 0, "quiet": 0})
        out = self.capture(aegis.cmd_report)
        self.assertIn(TheLineTheOperatorReads.LINE, out)

    def test_the_precision_command_prints_the_cached_line(self):
        out = self.capture(aegis.cmd_precision)
        self.assertIn(TheLineTheOperatorReads.LINE, out)


class TeachingEvaporation(ReplaySandbox):
    """An incident opened AFTER the operator already closed its identity as
    noise is teaching that did not hold. One opened BEFORE the verdict is
    just the incident the verdict was about."""

    def open_incident(self, db, key, created, status="OPEN", resolution=None,
                      verdict=None, verdict_at=None):
        iid = db.execute(
            "INSERT INTO incidents(kind,correlation_key,title,severity,status,"
            "created_at,first_seen,last_seen,updated_at,resolution) "
            "VALUES('signal',?,'t','HIGH',?,?,?,?,?,?)",
            (key, status, created, created, created, created,
             resolution)).lastrowid
        if verdict:
            db.execute(
                "INSERT INTO dismissals(incident_id,correlation_key,"
                "reason_code,category,dismissed_at) VALUES(?,?,?,?,?)",
                (iid, key, verdict, "process", verdict_at))
        return iid

    @staticmethod
    def key(path, n):
        return "signal:process:%s:%s:%064x" % (path, SUSPICIOUS_TRUST, n)

    def count(self):
        live = aegis._replay_live_store()
        try:
            return aegis._teaching_evaporation(live, NOW - 30 * DAY)
        finally:
            live.close()

    def test_after_the_verdict_counts_and_before_does_not(self):
        tool, other = "/opt/evap/tool", "/opt/evap/other"
        db = aegis._event_connection()
        with db:
            # The judgement: closed benign-positive ten days ago.
            self.open_incident(db, self.key(tool, 1), NOW - 11 * DAY,
                               "FALSE_POSITIVE", "benign-positive",
                               verdict="benign-positive",
                               verdict_at=NOW - 10 * DAY)
            # Same identity (new bytes), opened AFTER it: counts.
            self.open_incident(db, self.key(tool, 2), NOW - 5 * DAY)
            # Same identity, opened BEFORE the verdict: does not.
            self.open_incident(db, self.key(tool, 3), NOW - 20 * DAY)
            # A different identity after the verdict: does not.
            self.open_incident(db, self.key(other, 4), NOW - 5 * DAY)
        db.close()
        self.assertEqual(1, self.count())

    def test_a_false_positive_verdict_teaches_too(self):
        tool = "/opt/evap/fp-tool"
        db = aegis._event_connection()
        with db:
            self.open_incident(db, self.key(tool, 1), NOW - 11 * DAY,
                               "FALSE_POSITIVE", "false-positive",
                               verdict="false-positive",
                               verdict_at=NOW - 10 * DAY)
            self.open_incident(db, self.key(tool, 2), NOW - 3 * DAY)
        db.close()
        self.assertEqual(1, self.count())

    def test_an_incident_the_machine_closed_at_birth_is_teaching_that_held(self):
        tool = "/opt/evap/held"
        db = aegis._event_connection()
        with db:
            self.open_incident(db, self.key(tool, 1), NOW - 11 * DAY,
                               "FALSE_POSITIVE", "benign-positive",
                               verdict="benign-positive",
                               verdict_at=NOW - 10 * DAY)
            self.open_incident(db, self.key(tool, 2), NOW - 3 * DAY,
                               "FALSE_POSITIVE", "auto-tolerated")
        db.close()
        self.assertEqual(0, self.count())

    def test_an_incident_older_than_the_window_is_not_counted(self):
        tool = "/opt/evap/old"
        db = aegis._event_connection()
        with db:
            self.open_incident(db, self.key(tool, 1), NOW - 50 * DAY,
                               "FALSE_POSITIVE", "benign-positive",
                               verdict="benign-positive",
                               verdict_at=NOW - 45 * DAY)
            self.open_incident(db, self.key(tool, 2), NOW - 40 * DAY)
        db.close()
        self.assertEqual(0, self.count())

    def test_the_snapshot_carries_it(self):
        tool = "/opt/evap/snap"
        db = aegis._event_connection()
        with db:
            self.open_incident(db, self.key(tool, 1), NOW - 11 * DAY,
                               "FALSE_POSITIVE", "benign-positive",
                               verdict="benign-positive",
                               verdict_at=NOW - 10 * DAY)
            self.open_incident(db, self.key(tool, 2), NOW - 5 * DAY)
        db.close()
        self.assertEqual(1, aegis._precision_measure(NOW)[
            "teaching_evaporation"])

    def test_measuring_it_writes_nothing(self):
        import hashlib

        def digest():
            with open(aegis.EVENT_DB, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()

        self.seed()
        before = digest()
        self.count()
        self.assertEqual(before, digest())


if __name__ == "__main__":
    unittest.main()
