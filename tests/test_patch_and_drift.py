#!/usr/bin/env python3
"""Three "is this measurement actually current?" mechanisms.

Each covers a case where the tool reported something *green or red that it had
not measured*:

1. `_xprotect_corpus_age` — the old code stat()'d the bundle DIRECTORY. Apple
   rewrites files under Contents/ in place, so the directory mtime only moves
   when an entry is added or removed. Measured 2026-08-30 on the reference
   machine: /var/protected/xprotect/XProtect.bundle had a directory mtime of
   2024-09-29 while its contents were from 2026-08-25 — a 700-day error that
   printed a hard "definitions are stale" verdict about a current corpus.

2. `_check_macos_patch_gap` — the patch-gap control existed only for Linux, so
   a Mac 300 days behind on OS updates showed 52 green ticks.

3. `_runtime_source_drift` — the scheduled agent IS the runtime copy, so
   `_runtime_copy_status()` can only answer 'self' there; the one process whose
   staleness costs detections could not report it, and doctor printed that
   blind spot as a pass.
"""
import io
import os
import plistlib
import shutil
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


def _bundle(root, name, inner_mtime, dir_mtime):
    """A bundle whose DIRECTORY mtime is deliberately older than its contents —
    the exact shape that produced the 700-day error."""
    b = os.path.join(root, name)
    os.makedirs(os.path.join(b, "Contents"))
    inner = os.path.join(b, "Contents", "XProtect.yara")
    with open(inner, "w") as f:
        f.write("rule x {}\n")
    os.utime(inner, (inner_mtime, inner_mtime))
    os.utime(b, (dir_mtime, dir_mtime))       # set the dir mtime LAST
    return b


class TestXprotectCorpusAge(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._bundles = aegis.XPROTECT_BUNDLES
        self._run = aegis.run
        aegis.run = lambda cmd, timeout=15, extra_env=None: ("5357", "", 0)

    def tearDown(self):
        aegis.XPROTECT_BUNDLES = self._bundles
        aegis.run = self._run
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_age_comes_from_contents_not_the_directory(self):
        now = time.time()
        aegis.XPROTECT_BUNDLES = [_bundle(self.tmp, "A.bundle",
                                          inner_mtime=now - 5 * 86400,
                                          dir_mtime=now - 700 * 86400)]
        age, version = aegis._xprotect_corpus_age()
        self.assertIsNotNone(age)
        self.assertLess(age, 6.0, "directory mtime leaked into the age")
        self.assertGreater(age, 4.0)
        self.assertEqual(version, "5357")

    def test_stale_contents_are_still_reported_stale(self):
        # The fix must not become a way to never report staleness.
        now = time.time()
        aegis.XPROTECT_BUNDLES = [_bundle(self.tmp, "B.bundle",
                                          inner_mtime=now - 200 * 86400,
                                          dir_mtime=now)]
        age, _ = aegis._xprotect_corpus_age()
        self.assertGreater(age, aegis.XPROTECT_STALE_DAYS)

    def test_newest_bundle_wins_across_locations(self):
        now = time.time()
        aegis.XPROTECT_BUNDLES = [
            _bundle(self.tmp, "old.bundle", now - 300 * 86400, now),
            _bundle(self.tmp, "new.bundle", now - 3 * 86400, now - 900 * 86400),
        ]
        age, _ = aegis._xprotect_corpus_age()
        self.assertLess(age, 4.0)

    def test_absent_bundles_claim_nothing(self):
        aegis.XPROTECT_BUNDLES = [os.path.join(self.tmp, "nope.bundle")]
        self.assertEqual(aegis._xprotect_corpus_age(), (None, None))


class TestMacosPatchGap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._sv, self._su = aegis._SYSTEM_VERSION_PLIST, aegis._SU_PREFS

    def tearDown(self):
        aegis._SYSTEM_VERSION_PLIST, aegis._SU_PREFS = self._sv, self._su
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, running, offers):
        sv = os.path.join(self.tmp, "SystemVersion.plist")
        su = os.path.join(self.tmp, "SoftwareUpdate.plist")
        with open(sv, "wb") as f:
            plistlib.dump({"ProductVersion": running}, f)
        with open(su, "wb") as f:
            plistlib.dump({"FirstOfferDateDictionary": offers}, f)
        aegis._SYSTEM_VERSION_PLIST, aegis._SU_PREFS = sv, su

    @staticmethod
    def _ago(days):
        # plistlib writes <date> as naive UTC, which is what softwareupdated
        # stores and what the parser therefore has to handle.
        return (datetime.now(timezone.utc).replace(tzinfo=None)
                - timedelta(days=days))

    def test_the_reference_machine_shape_is_high(self):
        # macOS 26.0.1 with 12 later updates offered, oldest 299 days ago.
        offers = {"MSU_UPDATE_25A362_patch_26.0.1_minor": self._ago(335),
                  "MSU_UPDATE_25B78_patch_26.1_minor": self._ago(299),
                  "MSU_UPDATE_25G83_patch_26.6.2_minor": self._ago(13)}
        self._write("26.0.1", offers)
        out = aegis._check_macos_patch_gap()
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "HIGH")
        self.assertEqual(out[0]["pending_updates"], 2)
        self.assertIn("26.6.2", out[0]["detail"])
        self.assertEqual(out[0]["fingerprint"],
                         "hardening:macos:patchgap:26.0.1")

    def test_moderate_gap_is_medium(self):
        self._write("26.6.1", {"MSU_UPDATE_25G83_patch_26.6.2_minor":
                               self._ago(45)})
        out = aegis._check_macos_patch_gap()
        self.assertEqual(out[0]["severity"], "MEDIUM")

    def test_normal_cadence_is_not_a_finding(self):
        self._write("26.6.1", {"MSU_UPDATE_25G83_patch_26.6.2_minor":
                               self._ago(9)})
        self.assertEqual(aegis._check_macos_patch_gap(), [])

    def test_fully_patched_machine_is_silent(self):
        # The offered build IS the running one — the common case, and the one
        # that must never produce a standing alert.
        self._write("26.6.2", {"MSU_UPDATE_25G83_patch_26.6.2_minor":
                               self._ago(400)})
        self.assertEqual(aegis._check_macos_patch_gap(), [])

    def test_point_release_ordering_is_numeric_not_lexical(self):
        # '26.10' > '26.9' numerically but not as strings; a lexical compare
        # would call a patched machine unpatched forever.
        self._write("26.10", {"MSU_UPDATE_x_patch_26.9_minor": self._ago(400)})
        self.assertEqual(aegis._check_macos_patch_gap(), [])

    def test_unreadable_prefs_claim_nothing(self):
        aegis._SYSTEM_VERSION_PLIST = os.path.join(self.tmp, "missing.plist")
        aegis._SU_PREFS = os.path.join(self.tmp, "missing2.plist")
        self.assertEqual(aegis._check_macos_patch_gap(), [])

    def test_unparseable_keys_are_skipped_not_fatal(self):
        self._write("26.0.1", {"garbage": self._ago(400),
                               "MSU_UPDATE_x_patch_26.5_minor": self._ago(400)})
        out = aegis._check_macos_patch_gap()
        self.assertEqual(out[0]["pending_updates"], 1)


class TestRuntimeSourceDrift(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._selfstate, self._selfpath = aegis.SELFSTATE, aegis._SELF_PATH
        aegis.SELFSTATE = os.path.join(self.tmp, "selfstate.json")
        self.runtime = os.path.join(self.tmp, "runtime.py")
        with open(self.runtime, "w") as f:
            f.write("# v2\n")
        aegis._SELF_PATH = self.runtime

    def tearDown(self):
        aegis.SELFSTATE, aegis._SELF_PATH = self._selfstate, self._selfpath
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _record(self, source_path):
        aegis.save_json(aegis.SELFSTATE, {"source_path": source_path})

    def _source(self, text):
        p = os.path.join(self.tmp, "repo.py")
        with open(p, "w") as f:
            f.write(text)
        return p

    def test_nothing_recorded_is_none_not_clean(self):
        aegis.save_json(aegis.SELFSTATE, {"installed": True})
        self.assertIsNone(aegis._runtime_source_drift())

    def test_identical_source_is_in_sync(self):
        self._record(self._source("# v2\n"))
        self.assertEqual(aegis._runtime_source_drift(), "in-sync")

    def test_source_moved_ahead_is_drift(self):
        # The whole point: the scheduled agent, which IS the runtime copy,
        # can now see that the repo it was cut from has moved on.
        self._record(self._source("# v3 — a whole new detector\n"))
        self.assertEqual(aegis._runtime_source_drift(), "drift")

    def test_missing_source_is_unknown_never_clean(self):
        self._record(os.path.join(self.tmp, "deleted-repo.py"))
        self.assertEqual(aegis._runtime_source_drift(), "source-unknown")

    def test_source_is_the_runtime_copy_itself(self):
        self._record(self.runtime)
        self.assertIsNone(aegis._runtime_source_drift())

    def test_drift_token_is_distinct_from_hash_failure(self):
        # 'source-unknown' must never collide with _runtime_copy_status()'s
        # 'unknown', or the existing caller would start reporting a case it
        # cannot diagnose.
        self._record(os.path.join(self.tmp, "gone.py"))
        self.assertNotEqual(aegis._runtime_source_drift(), "unknown")


if __name__ == "__main__":
    unittest.main()


class TestAlertPrecision(unittest.TestCase):
    """`backtest` scored the question nobody was asking.

    Rule precision counts a benign-positive as CORRECT by design (the event was
    real, the rule worked), so `persistence` scored 1.00 with 31 of its 55
    interrupts dismissed. Alert precision asks the operator's actual question:
    of the times this category interrupted you, how often was that worth it.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._db, self._state = aegis.EVENT_DB, aegis.STATE_DIR
        aegis.STATE_DIR = os.path.join(self.tmp, ".aegis")
        os.makedirs(aegis.STATE_DIR)
        aegis.EVENT_DB = os.path.join(aegis.STATE_DIR, "aegis.db")
        aegis.init_event_store()

    def tearDown(self):
        aegis.EVENT_DB, aegis.STATE_DIR = self._db, self._state
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _incident(self, category, correlation_key, notified, dismissed):
        db = aegis._event_connection()
        try:
            now = int(time.time())
            self._n = getattr(self, "_n", 0) + 1
            sig = db.execute(
                "INSERT INTO signals (fingerprint, rule_id, rule_version, "
                "category, severity, title, detail, first_seen, last_seen) "
                "VALUES (?,?,1,?,'HIGH','t','d',?,?)",
                ("fp-%s-%d" % (category, self._n),
                 "aegis.%s.t" % category, category, now, now)).lastrowid
            inc = db.execute(
                "INSERT INTO incidents (kind, correlation_key, title, severity,"
                " status, created_at, first_seen, last_seen, updated_at, "
                " last_notified_at) VALUES "
                "('signal',?,'t','HIGH','OPEN',?,?,?,?,?)",
                (correlation_key, now, now, now, now,
                 now if notified else None)).lastrowid
            db.execute(
                "INSERT INTO events (occurred_at, observed_at, source, "
                "event_type, signal_id, incident_id) VALUES "
                "(?,?,'test','observation.finding',?,?)",
                (now, now, sig, inc))
            if dismissed:
                db.execute(
                    "INSERT INTO dismissals (incident_id, correlation_key, "
                    "reason_code, category, dismissed_at) VALUES "
                    "(?,?,'benign-positive',?,?)",
                    (inc, correlation_key, category, now))
            db.commit()
        finally:
            db.close()

    def _run(self):
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            aegis.cmd_backtest()
        return buf.getvalue()

    def test_category_comes_from_signals_not_the_correlation_key(self):
        # The regression this join exists to prevent: the key says 'beacon',
        # the finding's category is 'net-beacon'. Deriving from the key split
        # one detector into two half-populated rows.
        for i in range(aegis.BACKTEST_MIN_SAMPLES):
            self._incident("net-beacon", "signal:beacon:host-%d" % i,
                           notified=True, dismissed=(i < 10))
        out = self._run()
        self.assertIn("net-beacon", out)
        self.assertNotIn("\n  beacon ", out)
        self.assertIn("ALERT precision 0.50", out)

    def test_diverges_from_rule_precision_on_the_same_data(self):
        # Every incident dismissed benign-positive: the rule is perfect and
        # every single interrupt was unwanted. The two numbers must disagree.
        n = aegis.BACKTEST_MIN_SAMPLES
        for i in range(n):
            self._incident("persistence", "signal:persistence:p-%d" % i,
                           notified=True, dismissed=True)
        out = self._run()
        self.assertIn("ALERT precision 0.00 over %d interrupt(s)" % n, out)
        self.assertIn("rule precision 1.00", out)

    def test_uninterrupting_category_is_named_as_such(self):
        self._incident("staging", "signal:staging:x",
                       notified=False, dismissed=True)
        self.assertIn("never interrupted", self._run())

    def test_refuses_below_the_sample_floor(self):
        self._incident("hot-dir", "signal:hotdir:x", notified=True,
                       dismissed=False)
        self.assertIn("ALERT precision REFUSED — 1 interrupt(s)", self._run())


class TestChromeProfileDiscovery(unittest.TestCase):
    """Download provenance reached `Default` only. On the reference machine
    that was 1 of 15 profiles and 0 of 1,479 download rows."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._roots = aegis._CHROME_ROOTS
        self.root = os.path.join(self.tmp, "Chrome")
        aegis._CHROME_ROOTS = [self.root]

    def tearDown(self):
        aegis._CHROME_ROOTS = self._roots
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _profile(self, name, with_history=True):
        d = os.path.join(self.root, name)
        os.makedirs(d, exist_ok=True)
        if with_history:
            with open(os.path.join(d, "History"), "w") as f:
                f.write("")

    def test_finds_every_numbered_profile_not_just_default(self):
        self._profile("Default")
        for i in range(1, 15):
            self._profile("Profile %d" % i)
        found = aegis._chrome_history_dbs()
        self.assertEqual(len(found), 15)
        self.assertTrue(any("Profile 7" in p for p in found))

    def test_profile_without_a_history_db_is_skipped(self):
        self._profile("Default")
        self._profile("Guest Profile", with_history=False)
        self.assertEqual(len(aegis._chrome_history_dbs()), 1)

    def test_absent_browser_root_is_not_an_error(self):
        aegis._CHROME_ROOTS = [os.path.join(self.tmp, "NotInstalled")]
        self.assertEqual(aegis._chrome_history_dbs(), [])

    def test_resolved_per_call_so_a_new_profile_is_seen(self):
        # A long-lived `watch` process must see a profile created after import.
        self._profile("Default")
        self.assertEqual(len(aegis._chrome_history_dbs()), 1)
        self._profile("Profile 1")
        self.assertEqual(len(aegis._chrome_history_dbs()), 2)


class TestPatchGapIgnoresMajorUpgrades(TestMacosPatchGap):
    """A major upgrade offered to a fully-patched machine is not a patch gap.

    Declining macOS 27 on a current 26.6.2 is a supported choice; counting it
    would pin a permanent HIGH on a machine with nothing wrong with it — the
    alert-fatigue failure the whole signal-to-noise tier exists to prevent.
    """

    def test_major_upgrade_offer_is_not_a_gap(self):
        self._write("26.6.2", {"MSU_UPDATE_26A100_patch_27.0_major":
                               self._ago(300)})
        self.assertEqual(aegis._check_macos_patch_gap(), [])

    def test_a_real_patch_still_counts_alongside_a_major_offer(self):
        self._write("26.6.1", {"MSU_UPDATE_26A100_patch_27.0_major":
                               self._ago(300),
                               "MSU_UPDATE_25G83_patch_26.6.2_minor":
                               self._ago(120)})
        out = aegis._check_macos_patch_gap()
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["pending_updates"], 1)
        self.assertIn("26.6.2", out[0]["detail"])


class TestAssayCoverageSurfaced(unittest.TestCase):
    """Decayed positive controls were invisible on both status screens.

    check_assay grades the stale case INFO/low-confidence, which routes to the
    digest and never interrupts — so coverage could rot past its half-life in
    silence. That silently disarms every deadfall lane, because
    _deadfall_coverage_fresh requires a PROVEN control.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._f = aegis.ASSAY_FILE
        aegis.ASSAY_FILE = os.path.join(self.tmp, "assay.json")

    def tearDown(self):
        aegis.ASSAY_FILE = self._f
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _lanes(self, lanes):
        aegis.save_json(aegis.ASSAY_FILE, lanes)

    def test_never_run_is_a_question_mark_never_a_tick(self):
        mark, text = aegis._assay_coverage_line()
        self.assertEqual(mark, "?")
        self.assertIn("asserted", text)

    def test_all_fresh_is_a_tick(self):
        now = aegis._epoch()
        self._lanes({"a": {"ok": True, "last_ok": now},
                     "b": {"ok": True, "last_ok": now}})
        mark, text = aegis._assay_coverage_line()
        self.assertEqual(mark, "✓")
        self.assertIn("2/2 proven", text)

    def test_decayed_past_the_half_life_is_not_green(self):
        now = aegis._epoch()
        self._lanes({"a": {"ok": True, "last_ok": now},
                     "b": {"ok": True,
                           "last_ok": now - aegis.ASSAY_HALF_LIFE_SECS - 86400}})
        mark, text = aegis._assay_coverage_line()
        self.assertEqual(mark, "?")
        self.assertIn("unproven", text)

    def test_a_failing_lane_outranks_staleness(self):
        now = aegis._epoch()
        self._lanes({"a": {"ok": False, "last_ok": now},
                     "b": {"ok": True,
                           "last_ok": now - aegis.ASSAY_HALF_LIFE_SECS - 86400}})
        mark, text = aegis._assay_coverage_line()
        self.assertEqual(mark, "✗")
        self.assertIn("LOST", text)

    def test_doctor_and_status_cannot_disagree(self):
        # Both screens read the same helper; that is the point of extracting it.
        now = aegis._epoch()
        self._lanes({"a": {"ok": True, "last_ok": now}})
        import inspect
        for fn in (aegis.cmd_doctor, aegis.cmd_status):
            self.assertIn("_assay_coverage_line", inspect.getsource(fn))
