#!/usr/bin/env python3
"""The monitor's own cost line read 5.7% against the 1% ceiling it set for
itself, and two mechanisms owned most of it (2026-09-08, reference machine,
under the launchd agent's background QoS):

  * the log-show harvest was floored at ONE HOUR on a ten-minute cadence, so
    the floor was the window and every scan re-parsed six times the log it
    could need -- 17.5s of a 32s scan, the single most expensive step;
  * a change event bought a FULL scan, and an agent session's IPC sockets
    churn /tmp every few seconds, so the loop rescanned as fast as its 60s
    floor allowed: 1577 event scans in five days, 33 in one hour (25% of that
    hour's CPU), none of them finding anything the floor scan would not have.

These pin the two fixes. The window is now sized in minutes from the previous
scan's START and floored at logd's ingest latency, not at an hour. A change
event now buys a QUICK LOOK -- the sensors for that path only, written
nowhere -- and a full scan only when one of their findings is something
emit() would record; every non-answer in the look falls through to the full
scan, so the gate can only ever remove scans whose findings were provably
already on record.
"""
import os
import select
import shutil
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402
from test_regression import Sandbox  # noqa: E402


class _Patched(Sandbox):
    """Sandbox plus a restore-by-value patch helper."""

    def patch(self, name, value):
        original = getattr(aegis, name)
        self.addCleanup(setattr, aegis, name, original)
        setattr(aegis, name, value)
        return original


# --------------------------------------------------------------------------- #
# The log-show window
# --------------------------------------------------------------------------- #
class TestLogShowWindow(_Patched):
    def setUp(self):
        super().setUp()
        aegis.init_event_store()
        self.patch("_LOG_SHOW_WINDOW", None)
        self.now = int(time.time())

    def _meta(self, key, value):
        db = aegis._event_connection()
        try:
            with db:
                db.execute("INSERT INTO meta(key,value) VALUES(?,?) ON "
                           "CONFLICT(key) DO UPDATE SET value=excluded.value",
                           (key, str(value)))
        finally:
            db.close()

    def _del_meta(self, key):
        db = aegis._event_connection()
        try:
            with db:
                db.execute("DELETE FROM meta WHERE key=?", (key,))
        finally:
            db.close()

    def test_no_history_is_the_old_six_hours(self):
        # The argv a store with no scans builds must be byte-identical to the
        # one the sensors always built (test_battle_20260812 pins it too).
        self.assertEqual("6h", aegis._log_show_window(None))

    def test_a_ten_minute_cadence_reads_ten_minutes_not_an_hour(self):
        self._meta("last_scan_started", self.now - 300)
        self.assertEqual("%dm" % aegis._LOG_SHOW_FLOOR_MIN,
                         aegis._log_show_window(None))

    def test_the_window_is_twice_the_gap_from_the_previous_start(self):
        self._meta("last_scan_started", self.now - 3000)
        self.assertEqual("100m", aegis._log_show_window(None))
        self._meta("last_scan_started", self.now - 1800)
        self.assertEqual("1h", aegis._log_show_window(None),
                         "a whole number of hours renders as hours")

    def test_the_window_is_capped_at_six_hours(self):
        self._meta("last_scan_started", self.now - 8 * 3600)
        self.assertEqual("6h", aegis._log_show_window(None))

    def test_record_security_state_stamps_when_the_scan_started(self):
        cost = {"sensor_id": "scan.cost", "status": "OK", "detail": "",
                "duration_ms": 45000, "item_count": 0}
        aegis.record_security_state([], sensor_health=[cost],
                                    now=1_700_000_000)
        self.assertEqual(1_700_000_000 - 45, aegis._last_scan_started_epoch())
        self.assertEqual(1_700_000_000, aegis._last_scan_epoch())

    def test_a_store_without_the_start_stamp_reaches_back_by_the_duration(self):
        # A store written by an older build has only the completion stamp.
        # Sizing from that alone would start the window AFTER the previous
        # harvest ran; the scan's recorded wall time closes that gap.
        cost = {"sensor_id": "scan.cost", "status": "OK", "detail": "",
                "duration_ms": 200_000, "item_count": 0}
        aegis.record_security_state([], sensor_health=[cost],
                                    now=self.now - 400)
        self._del_meta("last_scan_started")
        self.assertIsNone(aegis._last_scan_started_epoch())
        # gap = 400 + 200 = 600s -> 20m; from the completion stamp alone it
        # would have been ceil(800/60) = 14m.
        self.assertEqual("20m", aegis._log_show_window(None))

    def test_an_explicit_window_is_untouched(self):
        self.assertEqual("2h", aegis._log_show_window(2))


# --------------------------------------------------------------------------- #
# Which sensors a changed path selects
# --------------------------------------------------------------------------- #
class TestSensorsForChange(_Patched):
    def setUp(self):
        super().setUp()
        self.staging = os.path.join(self.tmp, "staging")
        os.makedirs(self.staging)
        self.patch("STAGING_DIRS", [self.staging])
        self.history = os.path.join(self.tmp, ".zsh_history")
        self.rc = os.path.join(self.tmp, ".zshrc")
        self.wallet = os.path.join(self.tmp, "wallet.json")
        self.extra = os.path.join(self.tmp, "crontab")
        self.patch("SHELL_HISTORY_FILES", [self.history])
        self.patch("SHELL_RC_FILES", [self.rc])
        self.patch("WALLET_CONFIG_FILES", [self.wallet])
        self.patch("EXTRA_PERSIST_FILES", [self.extra])
        self.patch("EXTRA_PERSIST_DIRS", [os.path.join(self.tmp, "periodic")])

    def test_a_hot_dir_selects_the_hot_dir_sensor_only(self):
        self.assertEqual({"hot-dir"}, aegis._sensors_for_change({self.hot}))

    def test_a_dir_that_is_both_hot_and_staging_selects_both(self):
        self.patch("STAGING_DIRS", [self.hot])
        self.assertEqual({"hot-dir", "staging"},
                         aegis._sensors_for_change({self.hot}))

    def test_an_armed_plist_selects_persistence(self):
        plist = os.path.join(self.pers, "com.example.thing.plist")
        self.assertEqual({"persistence"}, aegis._sensors_for_change({plist}))
        self.assertEqual({"persistence"},
                         aegis._sensors_for_change({self.pers}))

    def test_an_armed_app_under_a_hot_dir_selects_hot_dir(self):
        exe = os.path.join(self.hot, "Thing.app", "Contents", "MacOS", "Thing")
        self.assertEqual({"hot-dir"}, aegis._sensors_for_change({exe}))

    def test_the_file_shaped_surfaces_select_their_own_sensor(self):
        self.assertEqual({"shell-history"},
                         aegis._sensors_for_change({self.history}))
        self.assertEqual({"shellrc"}, aegis._sensors_for_change({self.rc}))
        self.assertEqual({"wallet"}, aegis._sensors_for_change({self.wallet}))
        self.assertEqual({"extra_persist"},
                         aegis._sensors_for_change({self.extra}))
        self.assertEqual({"extra_persist"}, aegis._sensors_for_change(
            {os.path.join(self.tmp, "periodic")}))

    def test_several_paths_union_their_sensors(self):
        self.assertEqual({"hot-dir", "shell-history"},
                         aegis._sensors_for_change({self.hot, self.history}))

    def test_a_wake_the_look_cannot_judge_means_the_full_scan(self):
        self.assertIsNone(aegis._sensors_for_change({aegis.WATCH_STREAM_WAKE}))
        self.assertIsNone(aegis._sensors_for_change({aegis.WATCH_UNKNOWN}))
        self.assertIsNone(aegis._sensors_for_change(
            {os.path.join(self.tmp, "not", "armed")}))
        # One unknown path in a set poisons the whole set: the look must not
        # answer for a path it did not examine.
        self.assertIsNone(aegis._sensors_for_change(
            {self.hot, os.path.join(self.tmp, "not", "armed")}))

    def test_every_armed_path_is_one_the_look_can_judge(self):
        # The guard against the watched set growing without this map: any
        # path _watch_paths() arms must select at least one sensor, or the
        # look would fall through to a full scan on every event there and the
        # gate would silently stop paying for itself.
        self.write_plist("com.example.armed.plist", ["/bin/true"])
        for p in aegis._watch_paths():
            self.assertIsNotNone(aegis._sensors_for_change({p}),
                                 "armed but not lookable: %s" % p)


# --------------------------------------------------------------------------- #
# The gate itself
# --------------------------------------------------------------------------- #
def _hit(fp="hotdir:/x/tool:adhoc:abc", severity="HIGH"):
    return aegis.finding(severity, "hot-dir", "Unsigned executable in watched "
                         "folder", "detail", fp, path="/x/tool")


class TestChangeWarrantsRescan(_Patched):
    def setUp(self):
        super().setUp()
        aegis.init_event_store()

    def _hot_dir_returns(self, value):
        if isinstance(value, Exception):
            def fn(max_age_days=14):
                raise value
        else:
            def fn(max_age_days=14):
                return value
        self.patch("check_hot_dirs", fn)

    def test_nothing_found_is_not_worth_a_scan(self):
        self._hot_dir_returns([])
        warranted, why = aegis._change_warrants_rescan({self.hot})
        self.assertFalse(warranted)
        self.assertIn("nothing found", why)

    def test_an_unrecorded_finding_is_worth_a_scan(self):
        self._hot_dir_returns([_hit()])
        warranted, why = aegis._change_warrants_rescan({self.hot})
        self.assertTrue(warranted)
        self.assertIn("1 unrecorded", why)

    def test_a_finding_the_seen_ledger_holds_is_not(self):
        f = _hit()
        aegis.save_json(aegis.SEEN, {f["fingerprint"]: f["ts"]})
        self._hot_dir_returns([f])
        warranted, why = aegis._change_warrants_rescan({self.hot})
        self.assertFalse(warranted)
        self.assertIn("already on record", why)

    def test_an_allowlisted_finding_is_not(self):
        f = _hit()
        aegis.save_json(aegis.ALLOWLIST, [f["fingerprint"]])
        self._hot_dir_returns([f])
        self.assertFalse(aegis._change_warrants_rescan({self.hot})[0])

    def test_a_digest_routed_finding_still_warrants(self):
        # Below the notify floor is still RECORDED by emit(); only the
        # interrupt is withheld. The look asks "would this be recorded", not
        # "would this notify".
        self._hot_dir_returns([_hit(severity="LOW")])
        self.assertTrue(aegis._change_warrants_rescan({self.hot})[0])

    def test_a_sensor_non_answer_falls_through_to_the_scan(self):
        self._hot_dir_returns(None)
        warranted, why = aegis._change_warrants_rescan({self.hot})
        self.assertTrue(warranted)
        self.assertIn("no answer", why)

    def test_a_raising_sensor_falls_through_to_the_scan(self):
        self._hot_dir_returns(RuntimeError("listdir exploded"))
        warranted, why = aegis._change_warrants_rescan({self.hot})
        self.assertTrue(warranted)
        self.assertIn("quick look failed", why)

    def test_the_live_xprotect_tail_always_buys_a_scan(self):
        self._hot_dir_returns([])
        self.assertTrue(
            aegis._change_warrants_rescan({aegis.WATCH_STREAM_WAKE})[0])

    def test_a_persistence_change_with_no_baseline_falls_through(self):
        plist = os.path.join(self.pers, "com.example.new.plist")
        self.assertTrue(aegis._change_warrants_rescan({plist})[0])

    def test_a_persistence_change_the_baseline_explains_is_not(self):
        # Stamped at the current schema so load_baseline() hands it over
        # untouched instead of migrating (and rewriting) it on the way in.
        aegis.save_json(aegis.BASELINE, {
            "schema_version": aegis.BASELINE_SCHEMA_VERSION,
            "persistence": {"k": {"v": 1}}})
        self.patch("snapshot_persistence", lambda: {"k": {"v": 1}})
        calls = []

        def diff(prior, current):
            calls.append((prior, current))
            return []
        self.patch("check_persistence", diff)
        warranted, why = aegis._change_warrants_rescan({self.pers})
        self.assertFalse(warranted)
        self.assertEqual([({"k": {"v": 1}}, {"k": {"v": 1}})], calls,
                         "the look diffs the live snapshot against the "
                         "stored baseline, exactly as the scan does")

    def test_a_surface_not_yet_adopted_falls_through(self):
        rc = os.path.join(self.tmp, ".zshrc")
        self.patch("SHELL_RC_FILES", [rc])
        aegis.save_json(aegis.BASELINE, {           # no shellrc key
            "schema_version": aegis.BASELINE_SCHEMA_VERSION,
            "persistence": {}})
        self.patch("snapshot_shellrc", lambda: {})
        warranted, why = aegis._change_warrants_rescan({rc})
        self.assertTrue(warranted)
        self.assertIn("no answer", why)

    def test_the_look_writes_nothing(self):
        self._hot_dir_returns([_hit()])
        before = {n: os.path.exists(getattr(aegis, n))
                  for n in ("SEEN", "FINDINGS_LOG", "LATEST_JSON",
                            "BASELINE", "HEARTBEAT_FILE")}
        aegis._change_warrants_rescan({self.hot})
        after = {n: os.path.exists(getattr(aegis, n)) for n in before}
        self.assertEqual(before, after, "a look must not create scan state")


@unittest.skipUnless(aegis.IS_MAC and shutil.which("clang"),
                     "a real hot-dir verdict needs codesign and clang")
class TestChangeWarrantsRescanLive(_Patched):
    """The gate against the real hot-dir sensor, not a stub of it."""

    def test_a_planted_binary_warrants_once_and_then_is_on_record(self):
        self.adhoc_binary(os.path.join(self.hot, "tool"))
        aegis._sigcache = {}
        warranted, why = aegis._change_warrants_rescan({self.hot})
        self.assertTrue(warranted, why)
        # What the full scan would do with it: record the fingerprint. After
        # that the same change is churn to the look.
        fp = aegis.check_hot_dirs()[0]["fingerprint"]
        aegis.save_json(aegis.SEEN, {fp: "now"})
        warranted, why = aegis._change_warrants_rescan({self.hot})
        self.assertFalse(warranted, why)


# --------------------------------------------------------------------------- #
# The waiters name the path that woke them
# --------------------------------------------------------------------------- #
class TestPollNamesTheChangedPath(_Patched):
    def test_a_create_in_a_watched_dir_names_that_dir(self):
        self.patch("WATCH_POLL_SECS", 0.2)
        t = threading.Timer(
            0.3, lambda: open(os.path.join(self.hot, "drop"), "w").close())
        t.start()
        try:
            changed = aegis._poll_for_change(10)
        finally:
            t.join()
        self.assertIn(self.hot, changed)
        self.assertNotIn(self.pers, changed)

    def test_a_timeout_is_an_empty_set_and_still_false(self):
        self.patch("WATCH_POLL_SECS", 0.1)
        changed = aegis._poll_for_change(0.3)
        self.assertEqual(frozenset(), changed)
        self.assertFalse(changed)


@unittest.skipUnless(aegis.IS_MAC and hasattr(select, "kqueue"),
                     "kqueue is the macOS waiter")
class TestKqueueNamesTheChangedPath(_Patched):
    def test_build_watch_maps_each_fd_to_its_path(self):
        kq, fds = aegis._build_watch()
        try:
            self.assertIsInstance(fds, dict)
            self.assertIn(self.hot, fds.values())
            self.assertIn(self.pers, fds.values())
        finally:
            aegis._close_watch(kq, fds)

    def test_a_create_in_a_watched_dir_names_that_dir(self):
        kq, fds = aegis._build_watch()
        try:
            t = threading.Timer(
                0.3, lambda: open(os.path.join(self.hot, "drop"), "w").close())
            t.start()
            changed = aegis._wait_for_change(kq, 10, fds)
            t.join()
            self.assertEqual(frozenset([self.hot]), changed)
        finally:
            aegis._close_watch(kq, fds)

    def test_the_stream_fd_is_named_as_the_stream(self):
        r, w = os.pipe()
        os.set_blocking(r, False)
        kq, fds = aegis._build_watch(extra_read_fds=(r,))
        try:
            self.assertNotIn(r, fds, "the tail's fd is not ours to close")
            t = threading.Timer(0.3, lambda: os.write(w, b'{"event":1}\n'))
            t.start()
            changed = aegis._wait_for_change(kq, 10, fds)
            t.join()
            self.assertEqual(frozenset([aegis.WATCH_STREAM_WAKE]), changed)
        finally:
            aegis._close_watch(kq, fds)
            os.close(r)
            os.close(w)

    def test_without_a_map_a_wake_is_unknown(self):
        kq, fds = aegis._build_watch()
        try:
            t = threading.Timer(
                0.3, lambda: open(os.path.join(self.hot, "drop"), "w").close())
            t.start()
            changed = aegis._wait_for_change(kq, 10)
            t.join()
            self.assertEqual(frozenset([aegis.WATCH_UNKNOWN]), changed)
        finally:
            aegis._close_watch(kq, fds)

    def test_a_timeout_is_an_empty_set(self):
        kq, fds = aegis._build_watch()
        try:
            self.assertEqual(frozenset(), aegis._wait_for_change(kq, 0.3, fds))
        finally:
            aegis._close_watch(kq, fds)


# --------------------------------------------------------------------------- #
# The loop: a look that finds nothing costs no scan, and cannot defer the floor
# --------------------------------------------------------------------------- #
class _Clock(object):
    """Stands in for aegis.time inside cmd_watch: the loop reads the clock
    through it and every sleep advances it, so a scenario runs in no time."""

    def __init__(self):
        self.now = 0.0

    def time(self):
        return self.now

    def monotonic(self):
        return self.now

    def sleep(self, secs):
        self.now += secs


class TestWatchLoop(_Patched):
    """Drives the polled arm, which every platform can run; the arm-specific
    waiters are proven above and the logic after `changed` is shared."""

    def setUp(self):
        super().setUp()
        self.clock = _Clock()
        self.patch("time", self.clock)
        self.patch("_watch_sleep", self.clock.sleep)
        self.patch("IS_MAC", False)
        self.patch("_inotify_libc", lambda: None)
        self.patch("_trim_stdio_logs", lambda: None)
        self.scans, self.waits, self.looks, self.log = [], [], [], []
        self.patch("cmd_scan", lambda quiet=False, wait=False:
                   self.scans.append(self.clock.now) or 0)
        self.patch("log_run", self.log.append)

    def _script(self, waiter_steps, look_answers):
        steps = list(waiter_steps)
        answers = list(look_answers)

        def wait(timeout):
            self.waits.append(timeout)
            kind, at, paths = steps.pop(0)
            if kind == "stop":
                raise KeyboardInterrupt
            if kind == "change":
                self.clock.now = at
                return frozenset(paths)
            self.clock.now += timeout   # a timeout lands at the floor
            return frozenset()
        self.patch("_poll_for_change", wait)

        def look(changed):
            self.looks.append(changed)
            return answers.pop(0)
        self.patch("_change_warrants_rescan", look)

    def test_churn_costs_a_look_and_the_floor_is_not_deferred(self):
        deb, gap = aegis.WATCH_DEBOUNCE_SECS, aegis.WATCH_LOOK_GAP_SECS
        self._script(
            [("change", 100, [self.hot]),    # look says churn
             ("change", 200, [self.hot]),    # look says unrecorded
             ("timeout", None, None),        # the floor comes due
             ("stop", None, None)],
            [(False, "nothing found under hot-dir"),
             (True, "1 unrecorded finding(s) under hot-dir")])
        self.assertEqual(0, aegis.cmd_watch(interval=600))
        # One initial scan, one after the warranted look, one at the floor --
        # and NOT one after the churn look.
        after_churn = 200 + deb
        self.assertEqual([0, after_churn, after_churn + 600], self.scans)
        self.assertEqual(2, len(self.looks))
        # The second wait was for what REMAINED of the floor, not a fresh
        # interval: churn must not push the reconciliation scan out.
        self.assertEqual(600, self.waits[0])
        self.assertEqual(600 - (100 + deb + gap), self.waits[1])
        self.assertEqual(600, self.waits[2])
        self.assertTrue(any("-> rescan (1 unrecorded" in line
                            for line in self.log), self.log)
        self.assertTrue(any("2 change event(s) looked at since the last full "
                            "scan; 1 warranted no rescan" in line
                            for line in self.log), self.log)

    def test_a_warranted_look_still_honours_the_event_scan_rate_limit(self):
        deb = aegis.WATCH_DEBOUNCE_SECS
        self._script([("change", 20, [self.hot]), ("stop", None, None)],
                     [(True, "1 unrecorded finding(s) under hot-dir")])
        self.assertEqual(0, aegis.cmd_watch(interval=600))
        # 20s in, plus the debounce, then held to the 60s floor since the
        # last full scan started.
        self.assertEqual([0, max(20 + deb, aegis.WATCH_MIN_GAP_SECS)],
                         self.scans)

    def test_a_scan_worth_of_churn_never_scans(self):
        deb, gap = aegis.WATCH_DEBOUNCE_SECS, aegis.WATCH_LOOK_GAP_SECS
        steps = [("change", 10 * (i + 1) + i * (deb + gap), [self.hot])
                 for i in range(5)] + [("stop", None, None)]
        self._script(steps, [(False, "nothing found under hot-dir")] * 5)
        self.assertEqual(0, aegis.cmd_watch(interval=600))
        self.assertEqual([0], self.scans, "five churn events, zero scans")
        self.assertEqual(5, len(self.looks))


if __name__ == "__main__":
    unittest.main()
