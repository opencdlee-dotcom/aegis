#!/usr/bin/env python3
"""Three ways a scan could wedge, and the operator's escape hatch wedging too.

S1 -- there was no AGGREGATE scan deadline. Every subprocess is bounded
      individually (run() defaults to timeout=15 and returns rc 124 rather
      than raising) but nothing bounded their sum, and the sum is the number
      the hourly schedule cares about. gather_all now carries a wall-clock
      budget checked BETWEEN sensors, and a sensor the budget never reached is
      recorded DEGRADED with the budget named -- never left reporting its last
      row as OK, which is the false-green class doctor's "unknown is never
      green" rule exists to prevent.

S2 -- _scan_lock was an unconditional blocking flock with no message and no
      holder record, so a by-hand `aegis.py scan` fired during the scheduled
      scan HUNG with zero output. It is now non-blocking by default, names the
      holding pid and its start time, and exits 0; `wait=True` / `scan --wait`
      is the opt-in for the old behaviour, and cmd_baseline keeps it.

S3 -- the four per-scan prep snapshots (process table, Linux socket-inode map,
      Windows netstat table, macOS `log show` prewarm) ran OUTSIDE the try that
      isolates each sensor, so a raise in any of them aborted every sensor
      below. They now go through _collect_prep and degrade the same way.

S4 -- there was no test anywhere exercising two CONCURRENT scans; only
      inspect.getsource string assertions about the lock. TestConcurrentScans
      below spawns a real second process that really holds the real lock.

Fully sandboxed: STATE_DIR, RUN_LOG, EVENT_DB and every path global these
paths touch are redirected into a tmp dir, so nothing here can reach the real
~/.aegis (tests/conftest.py fails the test that tries).
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

# simbody flips IS_WIN, so _lock_fd takes the msvcrt branch -- but msvcrt does
# not exist on a POSIX host, and no flag can conjure it. This file first wrote
# that marker; it now shares one definition with the other four files that hit
# the same wall. See test_regression.needs_real_scan_lock.
from test_regression import needs_real_scan_lock as _needs_real_lock  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Sandbox(unittest.TestCase):
    REBOUND = ("STATE_DIR", "RUN_LOG", "EVENT_DB", "BASELINE", "SELFSTATE",
               "ALLOWLIST", "WRIT_FILE", "SEEN", "SIGCACHE", "LATEST_JSON",
               "FINDINGS_LOG")

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis-lockbudget-")
        self.state = os.path.join(self.tmp, ".aegis")
        os.makedirs(self.state, mode=0o700)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        # Captured ONCE, restored by VALUE: a helper that re-read the attribute
        # at cleanup time restored a stub last round and poisoned 27 unrelated
        # tests, so every restore below is bound to the value seen here.
        self._saved = {n: getattr(aegis, n) for n in self.REBOUND
                       if hasattr(aegis, n)}
        for n, v in {
                "STATE_DIR": self.state,
                "RUN_LOG": os.path.join(self.state, "run.log"),
                "EVENT_DB": os.path.join(self.state, "aegis.db"),
                "BASELINE": os.path.join(self.state, "baseline.json"),
                "SELFSTATE": os.path.join(self.state, "selfstate.json"),
                "ALLOWLIST": os.path.join(self.state, "allowlist.json"),
                "WRIT_FILE": os.path.join(self.state, "writ.json"),
                "SEEN": os.path.join(self.state, "seen.json"),
                "SIGCACHE": os.path.join(self.state, "sigcache.json"),
                "LATEST_JSON": os.path.join(self.state, "latest.json"),
                "FINDINGS_LOG": os.path.join(self.state, "findings.jsonl"),
        }.items():
            if hasattr(aegis, n):
                setattr(aegis, n, v)

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(aegis, n, v)

    def patch(self, name, value):
        """Rebind aegis.<name>, restoring the ORIGINAL VALUE captured now."""
        original = getattr(aegis, name)
        self.addCleanup(setattr, aegis, name, original)
        setattr(aegis, name, value)
        return original


# --------------------------------------------------------------------------- #
# S1: the aggregate scan deadline
# --------------------------------------------------------------------------- #
class TestScanTimeBudget(Sandbox):
    """The budget is derived from the cadence this machine actually installed."""

    def _selfstate(self, **kw):
        aegis.save_json(aegis.SELFSTATE, kw)

    def test_watch_cadence_gives_half_of_the_600s_floor(self):
        self._selfstate(installed=True, install_mode="watch")
        self.assertEqual(aegis._scan_time_budget(), 300.0)

    def test_hourly_cadence_gives_half_an_hour(self):
        self._selfstate(installed=True, install_mode="scan")
        self.assertEqual(aegis._scan_time_budget(), 1800.0)

    def test_uninstalled_machine_falls_back_to_the_hourly_assumption(self):
        # No schedule to reason from; the honest default is the scan-mode one.
        self.assertEqual(aegis._scan_time_budget(), 1800.0)

    def test_a_tiny_custom_interval_is_floored_not_zeroed(self):
        # 120s cadence -> 60s of sensors. A nonsense interval must not be able
        # to disable the sensor loop outright.
        self._selfstate(installed=True, install_mode="scan", install_interval=120)
        self.assertEqual(aegis._scan_time_budget(), 60.0)

    def test_a_daily_interval_is_capped(self):
        self._selfstate(installed=True, install_mode="scan", install_interval=86400)
        self.assertEqual(aegis._scan_time_budget(), 1800.0)

    def test_explicit_override_wins_and_zero_means_unbounded(self):
        self.patch("SCAN_TIME_BUDGET", 12.5)
        self.assertEqual(aegis._scan_time_budget(), 12.5)
        aegis.SCAN_TIME_BUDGET = 0
        self.assertIsNone(aegis._scan_time_budget())


class _SensorStubs(Sandbox):
    """gather_all with every check_* replaced, so no real sensor runs."""

    def stub_sensors(self, slow=None, delay=0.0):
        """Replace every aegis.check_* with a recorder. `slow` runs `delay`s."""
        self.called = []
        for name in sorted(dir(aegis)):
            if not name.startswith("check_"):
                continue
            fn = getattr(aegis, name)
            if not callable(fn):
                continue
            self.patch(name, self._stub(name, slow, delay))
        # The preps are real subprocess/procfs work; neutralise them too so the
        # timings under test are the ones this test controls.
        self.patch("_iter_processes", lambda: iter(()))
        self.patch("_prewarm_log_show", lambda *a, **k: {})
        self.patch("_linux_socket_inode_pids", lambda *a, **k: {})
        self.patch("_netstat_tcp_rows", lambda *a, **k: [])

    def _stub(self, name, slow, delay):
        called = self.called

        def _run(*args, **kw):
            called.append(name)
            if name == slow:
                time.sleep(delay)
            return []
        return _run

    @staticmethod
    def by_id(health):
        return {h["sensor_id"]: h for h in health}


class TestBudgetSkipsAndDegrades(_SensorStubs):

    def test_sensors_past_the_deadline_are_degraded_naming_the_budget(self):
        # The first sensor overruns the whole budget, so every sensor after it
        # is unreachable -- deterministic, not a race: 0.30s > 0.05s always.
        self.stub_sensors(slow="check_persistence", delay=0.30)
        self.patch("SCAN_TIME_BUDGET", 0.05)
        health = []
        findings = aegis.gather_all(None, {}, health=health)
        self.assertEqual(findings, [])
        self.assertEqual(self.called, ["check_persistence"],
                         "only the sensor that consumed the budget may run")
        rows = self.by_id(health)
        skipped = [h for h in health if "time budget" in (h.get("detail") or "")]
        self.assertTrue(skipped, "no sensor was recorded as budget-skipped")
        for h in skipped:
            self.assertEqual(h["status"], "DEGRADED")
            self.assertIn("did not run", h["detail"])
        # Named sensors that are known to sit after persistence.diff.
        for late in ("process", "behavior", "hot-dir", "supply-chain"):
            self.assertEqual(rows[late]["status"], "DEGRADED", late)
            self.assertIn("time budget", rows[late]["detail"], late)
        # A skipped sensor must never be reported as live coverage.
        live, stale, permanent, degraded = aegis._coverage_split(
            [dict(h, last_run_at=1) for h in health])
        degraded_ids = {h["sensor_id"] for h in degraded}
        self.assertIn("process", degraded_ids)
        self.assertNotIn("process", {h["sensor_id"] for h in live})

    def test_within_budget_every_sensor_runs_and_nothing_is_budget_marked(self):
        self.stub_sensors(slow="check_persistence", delay=0.0)
        self.patch("SCAN_TIME_BUDGET", 600.0)
        health = []
        aegis.gather_all(None, {}, health=health)
        self.assertIn("check_persistence", self.called)
        self.assertIn("check_processes", self.called)
        self.assertIn("check_hot_dirs", self.called)
        self.assertFalse([h for h in health
                          if "time budget" in (h.get("detail") or "")],
                         "a scan inside its budget must mark nothing skipped")
        rows = self.by_id(health)
        for sid in ("process", "behavior", "hot-dir", "supply-chain"):
            self.assertEqual(rows[sid]["status"], "OK", sid)

    def test_budget_of_zero_disables_the_deadline_entirely(self):
        self.stub_sensors()
        self.patch("SCAN_TIME_BUDGET", 0)
        health = []
        aegis.gather_all(None, {}, health=health)
        self.assertFalse([h for h in health
                          if "time budget" in (h.get("detail") or "")])


# --------------------------------------------------------------------------- #
# S3: the prep snapshots are isolated like sensors
# --------------------------------------------------------------------------- #
class TestPrepIsolation(_SensorStubs):

    def test_a_raising_process_walk_no_longer_aborts_every_sensor(self):
        self.stub_sensors()

        def boom():
            raise RuntimeError("proc table exploded")
        self.patch("_iter_processes", boom)
        health = []
        aegis.gather_all(None, {}, health=health)      # must not raise
        self.assertIn("check_hot_dirs", self.called,
                      "a failed prep must not take the sensor loop with it")
        row = self.by_id(health)["prep.process-table"]
        self.assertEqual(row["status"], "DEGRADED")
        self.assertIn("proc table exploded", row["detail"])
        # And the snapshot is left cleared, so nothing downstream reads a
        # half-built table.
        self.assertIsNone(aegis._PROC_SNAPSHOT)

    def test_a_working_process_walk_is_recorded_ok_with_its_item_count(self):
        self.stub_sensors()
        self.patch("_iter_processes",
                   lambda: iter([("1", "0", "/bin/sh", "sh"),
                                 ("2", "0", "/bin/ls", "ls")]))
        health = []
        aegis.gather_all(None, {}, health=health)
        row = self.by_id(health)["prep.process-table"]
        self.assertEqual(row["status"], "OK")
        self.assertEqual(row["item_count"], 2)
        self.assertEqual(row["detail"], "")

    @unittest.skipUnless(aegis.IS_MAC, "the log-show prewarm is macOS-only")
    def test_a_raising_log_show_prewarm_degrades_only_itself(self):
        self.stub_sensors()

        def boom(*a, **k):
            raise OSError("log show unavailable")
        self.patch("_prewarm_log_show", boom)
        health = []
        aegis.gather_all(None, {}, health=health)
        self.assertIn("check_hot_dirs", self.called)
        row = self.by_id(health)["prep.log-show"]
        self.assertEqual(row["status"], "DEGRADED")
        self.assertIn("log show unavailable", row["detail"])

    @unittest.skipUnless(aegis.IS_LINUX, "the socket-inode map is Linux-only")
    def test_a_raising_socket_inode_map_degrades_only_itself(self):
        self.stub_sensors()

        def boom(*a, **k):
            raise OSError("procfs denied")
        self.patch("_linux_socket_inode_pids", boom)
        health = []
        aegis.gather_all(None, {}, health=health)
        self.assertIn("check_hot_dirs", self.called)
        row = self.by_id(health)["prep.socket-inode"]
        self.assertEqual(row["status"], "DEGRADED")
        self.assertIn("procfs denied", row["detail"])

    @unittest.skipUnless(aegis.IS_WIN, "the netstat table is Windows-only")
    def test_a_raising_netstat_table_degrades_only_itself(self):
        self.stub_sensors()

        def boom(*a, **k):
            raise OSError("netstat missing")
        self.patch("_netstat_tcp_rows", boom)
        health = []
        aegis.gather_all(None, {}, health=health)
        self.assertIn("check_hot_dirs", self.called)
        row = self.by_id(health)["prep.netstat"]
        self.assertEqual(row["status"], "DEGRADED")
        self.assertIn("netstat missing", row["detail"])

    def test_preps_absent_on_a_platform_are_not_reported_at_all(self):
        # A table that cannot exist on this body is ABSENT, never permanently
        # DEGRADED -- the same rule the sensor list itself follows.
        self.stub_sensors()
        health = []
        aegis.gather_all(None, {}, health=health)
        ids = set(self.by_id(health))
        self.assertIn("prep.process-table", ids)
        self.assertEqual("prep.log-show" in ids, aegis.IS_MAC)
        self.assertEqual("prep.socket-inode" in ids, aegis.IS_LINUX)
        self.assertEqual("prep.netstat" in ids, aegis.IS_WIN)


# --------------------------------------------------------------------------- #
# S2 + S4: two scans at once, for real
# --------------------------------------------------------------------------- #
_HOLDER = r'''
import os, sys, time
sys.path.insert(0, %(repo)r)
import aegis
aegis.STATE_DIR = %(state)r
aegis.RUN_LOG = os.path.join(%(state)r, "run.log")
with aegis._scan_lock(wait=True, quiet=True) as got:
    with open(%(ready)r, "w") as f:
        f.write("1" if got else "0")
    for _ in range(1200):
        if os.path.exists(%(release)r):
            break
        time.sleep(0.05)
'''


@_needs_real_lock
class TestConcurrentScans(Sandbox):
    """A REAL second process, holding the REAL lock file.

    A thread in this process would not prove it: flock is per open file
    description and msvcrt locks are per process, so a same-process test would
    be asserting something other than the thing that actually happens when
    launchd fires a scan while the operator is typing one.
    """

    def setUp(self):
        Sandbox.setUp(self)
        self.ready = os.path.join(self.tmp, "ready")
        self.release = os.path.join(self.tmp, "release")
        self.lock_path = os.path.join(self.state, ".scan.lock")
        self.child = None

    def tearDown(self):
        self._release()
        Sandbox.tearDown(self)

    def _release(self):
        if self.child is None:
            return
        try:
            with open(self.release, "w") as f:
                f.write("go")
            self.child.wait(timeout=30)
        except Exception:
            self.child.kill()
            self.child.wait(timeout=30)
        self.child = None

    def _start_holder(self):
        script = os.path.join(self.tmp, "holder.py")
        with open(script, "w") as f:
            f.write(_HOLDER % {"repo": REPO, "state": self.state,
                               "ready": self.ready, "release": self.release})
        self.child = subprocess.Popen([sys.executable, script],
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
        deadline = time.time() + 60
        while time.time() < deadline:
            if os.path.exists(self.ready):
                with open(self.ready) as f:
                    self.assertEqual(f.read().strip(), "1",
                                     "holder process failed to take the lock")
                return
            if self.child.poll() is not None:
                self.fail("holder died: %s" % (self.child.communicate(),))
            time.sleep(0.05)
        self.fail("holder never took the lock")

    def test_a_second_scan_reports_the_holder_and_does_not_hang(self):
        self._start_holder()
        buf = io.StringIO()
        started = time.time()
        with contextlib.redirect_stdout(buf):
            with aegis._scan_lock() as acquired:
                self.assertFalse(acquired)
        elapsed = time.time() - started
        self.assertLess(elapsed, 15, "contention must return, not block")
        out = buf.getvalue()
        self.assertIn("already running", out)
        self.assertIn("pid %d" % self.child.pid, out)
        self.assertIn("--wait", out)
        # The pid/start record really is in the lock file, not invented.
        holder = aegis._read_lock_holder(self.lock_path)
        self.assertEqual(holder["pid"], self.child.pid)
        self.assertTrue(holder["started"])

    def test_cmd_scan_skips_the_work_entirely_while_contended(self):
        ran = []
        self.patch("_cmd_scan_locked",
                   lambda *a, **k: ran.append(1) or 99)
        self._start_holder()
        with contextlib.redirect_stdout(io.StringIO()):
            rc = aegis.cmd_scan(quiet=False)
        self.assertEqual(rc, 0, "a skipped scan is not a fault; exit 0")
        self.assertEqual(ran, [], "the scan body must not run while contended")
        # ...and once the holder is gone the very same call does the work.
        self._release()
        with contextlib.redirect_stdout(io.StringIO()):
            rc = aegis.cmd_scan(quiet=False)
        self.assertEqual(rc, 99)
        self.assertEqual(ran, [1])

    def test_quiet_contention_is_logged_but_not_printed(self):
        self.patch("_cmd_scan_locked", lambda *a, **k: 0)
        self._start_holder()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            aegis.cmd_scan(quiet=True)
        self.assertEqual(buf.getvalue(), "",
                         "the scheduled --quiet job must not chatter")
        with open(os.path.join(self.state, "run.log")) as f:
            self.assertIn("scan skipped", f.read())

    def test_wait_true_really_blocks_until_the_holder_releases(self):
        self._start_holder()
        acquired = []

        def waiter():
            with aegis._scan_lock(wait=True, quiet=True) as got:
                acquired.append(got)

        t = threading.Thread(target=waiter, daemon=True)
        t.start()
        t.join(1.0)
        self.assertTrue(t.is_alive(), "wait=True must block while contended")
        self.assertEqual(acquired, [])
        self._release()
        t.join(30)
        self.assertFalse(t.is_alive(), "wait=True must acquire once free")
        self.assertEqual(acquired, [True])

    def test_uncontended_lock_stamps_this_process(self):
        with aegis._scan_lock() as acquired:
            self.assertTrue(acquired)
            holder = aegis._read_lock_holder(self.lock_path)
        self.assertEqual(holder["pid"], os.getpid())
        # Taken and released cleanly: the next taker gets it immediately.
        with aegis._scan_lock() as again:
            self.assertTrue(again)

    def test_holder_record_survives_a_missing_or_junk_lock_file(self):
        self.assertIsNone(aegis._read_lock_holder(
            os.path.join(self.tmp, "nope.lock")))
        junk = os.path.join(self.tmp, "junk.lock")
        with open(junk, "wb") as f:
            f.write(b"#not json at all\n")
        self.assertIsNone(aegis._read_lock_holder(junk))


@_needs_real_lock
class TestBaselineStillWaits(Sandbox):
    """cmd_baseline is the caller the wait opt-in exists for."""

    def test_baseline_takes_the_lock_with_wait_true(self):
        seen = {}
        original = aegis._scan_lock

        @contextlib.contextmanager
        def spy(*a, **kw):
            seen.update(kw)
            with original(*a, **kw) as got:
                yield got
        self.patch("_scan_lock", spy)
        self.patch("_cmd_baseline_locked", lambda trust="verified": 0)
        self.assertEqual(aegis.cmd_baseline(), 0)
        self.assertTrue(seen.get("wait"), "baseline must not silently skip")
        self.assertEqual(seen.get("what"), "baseline")


class TestScanCli(Sandbox):
    """`scan --wait` is the documented opt-in, and the default is not it."""

    def test_wait_flag_is_threaded_through_from_argv(self):
        seen = []
        self.patch("cmd_scan", lambda quiet=False, wait=False:
                   seen.append((quiet, wait)) or 0)
        self.patch("_trim_stdio_logs", lambda *a, **k: None)
        aegis.main(["aegis.py", "scan"])
        aegis.main(["aegis.py", "scan", "--wait"])
        aegis.main(["aegis.py", "scan", "--quiet", "--wait"])
        self.assertEqual(seen, [(False, False), (False, True), (True, True)])

    def test_help_documents_the_flag(self):
        self.assertIn("scan [--wait]", aegis.HELP)


if __name__ == "__main__":
    unittest.main()
