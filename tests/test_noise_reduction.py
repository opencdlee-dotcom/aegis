"""The noise-reduction tier: the five fixes that made the report readable.

Measured cause, on this machine, 2026-08-20: 281 incidents lifetime, 131
adjudicated FALSE_POSITIVE, 129 still OPEN, and not one true positive that a
test fixture had not planted. The detector was not blind — it was unreadable,
which is the failure mode that silences every future alert too.

Each class below pins one fix AND the safety property that keeps the fix from
becoming a blind spot. The safety half is the point: every one of these
suppresses something, so every one of them must prove what it still says.
"""
import os
import sys
import time
import hashlib
import sqlite3
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


class ExecIdentityIsWhatRuns(unittest.TestCase):
    """Fix 2a — an exec entry is identified by its command, not its position."""

    @staticmethod
    def _snap(cmds, path="/cfg/settings.json"):
        execs = {}
        for i, c in enumerate(cmds):
            ent = {"cmd": c, "args": [], "target": "/usr/bin/" + c,
                   "target_sha": "a" * 64,
                   "label": "hooks.SessionStart[%d].hooks[0]" % i}
            execs[aegis._exec_identity(c, [])] = ent
        return {path: {"sha256": "x" * 64, "execs": execs}}

    def _new_execs(self, before, after):
        return [f for f in aegis.diff_agent_surface(before, after)
                if f["title"] == "New agent exec entry registered"]

    def test_inserting_one_hook_does_not_realert_the_others(self):
        """The cascade: one insertion used to renumber every later sibling and
        re-open a HIGH incident for each. 55 of 67 un-generalizable open
        incidents on the reference machine were this."""
        base = ["alpha", "bravo", "charlie", "delta", "echo"]
        fs = self._new_execs(self._snap(base), self._snap(["zulu"] + base))
        self.assertEqual(len(fs), 1, "renumbering must not re-alert")
        self.assertIn("zulu", fs[0]["detail"])

    def test_a_genuinely_new_command_still_fires(self):
        """The safety half: quieting position must not quiet content."""
        fs = self._new_execs(self._snap(["alpha"]), self._snap(["alpha", "evil"]))
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["severity"], "HIGH")

    def test_reordering_alone_is_silent(self):
        before, after = ["a", "b", "c"], ["c", "a", "b"]
        self.assertEqual(self._new_execs(self._snap(before),
                                         self._snap(after)), [])

    def test_legacy_positional_snapshot_migrates_silently(self):
        """An upgrade must not present every baselined entry as new."""
        legacy = {"/cfg/settings.json": {"sha256": "x" * 64, "execs": {
            "hooks.SessionStart[0].hooks[0]|alpha": {
                "cmd": "alpha", "args": [], "target": "/usr/bin/alpha",
                "target_sha": "a" * 64}}}}
        self.assertEqual(self._new_execs(legacy, self._snap(["alpha"])), [])

    def test_identity_ignores_position_but_not_arguments(self):
        self.assertEqual(aegis._exec_identity("node", ["a"]),
                         aegis._exec_identity("node", ["a"]))
        self.assertNotEqual(aegis._exec_identity("node", ["a"]),
                            aegis._exec_identity("node", ["b"]))


class RotatingEndpointsNeedEvidence(unittest.TestCase):
    """Fix 2b — a load-balanced service generalizes only once rotation is
    demonstrated across distinct addresses."""

    def test_class_factors_out_address_and_version(self):
        k = aegis._beacon_endpoint_class("beacon:/app-1.2.3/bin/x:1.2.3.4:443")
        self.assertIsNotNone(k)
        self.assertNotIn("1.2.3.4", k[0])
        self.assertIn("#", k[0])
        self.assertEqual(k[1], "1.2.3.4")

    def test_a_hostname_is_a_fact_and_never_generalizes(self):
        self.assertIsNone(
            aegis._beacon_endpoint_class("beacon:/bin/x:evil.example.com:443"))

    def test_attack_defined_prefixes_never_generalize(self):
        for p in ("decoy:", "latch:", "canary:"):
            self.assertIsNone(
                aegis._beacon_endpoint_class(p + "beacon:/bin/x:1.2.3.4:443"))

    def test_port_is_part_of_the_class(self):
        a = aegis._beacon_endpoint_class("beacon:/bin/x:1.2.3.4:443")[0]
        b = aegis._beacon_endpoint_class("beacon:/bin/x:1.2.3.4:4444")[0]
        self.assertNotEqual(a, b)


class _DBCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_noise_")
        self.db = sqlite3.connect(os.path.join(self.tmp, "t.db"))
        self.db.row_factory = sqlite3.Row
        self.now = 1_700_000_000
        self.db.executescript("""
            CREATE TABLE incidents(id INTEGER PRIMARY KEY, correlation_key TEXT,
              title TEXT, severity TEXT, kind TEXT, status TEXT,
              resolution TEXT, created_at INT, updated_at INT,
              next_reminder_at INT, reminder_count INT DEFAULT 0,
              last_notified_at INT);
            CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE events(id INTEGER PRIMARY KEY, occurred_at INT,
              observed_at INT, source TEXT, event_type TEXT, signal_id INT,
              incident_id INT, data_json TEXT);
        """)

    def tearDown(self):
        self.db.close()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _inc(self, ident, sev="HIGH", kind="signal", status="OPEN", age_days=0,
             key=None):
        self.db.execute(
            "INSERT INTO incidents(correlation_key,title,severity,kind,status,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (key or ("signal:" + ident), ident, sev, kind, status,
             self.now - age_days * 86400, self.now - age_days * 86400))
        return self.db.execute("SELECT last_insert_rowid()").fetchone()[0]

    def _status(self, i):
        return self.db.execute("SELECT status FROM incidents WHERE id=?",
                               (i,)).fetchone()[0]


class IncidentsAgeOut(_DBCase):
    """Fix 4 — a queue that only grows communicates nothing."""

    def test_a_quiet_incident_closes_as_ambient(self):
        i = self._inc("process:/bin/x", age_days=30)
        self.assertEqual(aegis._age_out_incidents(self.db, self.now), 1)
        self.assertEqual(self._status(i), "FALSE_POSITIVE")
        res = self.db.execute("SELECT resolution FROM incidents WHERE id=?",
                              (i,)).fetchone()[0]
        self.assertIn("aged out", res)

    def test_a_recent_incident_is_untouched(self):
        i = self._inc("process:/bin/x", age_days=1)
        self.assertEqual(aegis._age_out_incidents(self.db, self.now), 0)
        self.assertEqual(self._status(i), "OPEN")

    def test_critical_never_ages_out(self):
        i = self._inc("chain:x", sev="CRITICAL", age_days=999)
        aegis._age_out_incidents(self.db, self.now)
        self.assertEqual(self._status(i), "OPEN")

    def test_correlation_chains_never_age_out(self):
        i = self._inc("chain:x", kind="correlation", age_days=999)
        aegis._age_out_incidents(self.db, self.now)
        self.assertEqual(self._status(i), "OPEN")

    def test_attack_defined_evidence_never_ages_out(self):
        """A quiet week is not an acquittal for a tripped decoy."""
        for p in ("decoy:", "latch:", "canary:"):
            i = self._inc(p + "tripped", age_days=999)
            aegis._age_out_incidents(self.db, self.now)
            self.assertEqual(self._status(i), "OPEN", p)

    def test_age_out_writes_no_dismissal_row(self):
        """A machine verdict must never feed tolerance or backtest precision."""
        self._inc("process:/bin/x", age_days=30)
        aegis._age_out_incidents(self.db, self.now)
        tables = [r[0] for r in self.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        self.assertNotIn("dismissals", tables,
                         "age-out must not create or write dismissals")


class LegacyExecIncidentsRetire(_DBCase):
    """Fix 2a's migration — incidents no scan can ever re-evidence."""

    def test_positional_incidents_are_retired_once(self):
        old = self._inc(
            "x", key="signal:agent-surface:newexec:/c.json:hooks.A[0]|node srv")
        new = self._inc(
            "y", key="signal:agent-surface:newexec:/c.json:node srv|a1b2c3d4e5f6")
        self.assertEqual(aegis._retire_legacy_exec_incidents(self.db, self.now), 1)
        self.assertEqual(self._status(old), "FALSE_POSITIVE")
        self.assertEqual(self._status(new), "OPEN")
        # idempotent: a second pass retires nothing
        self.assertEqual(aegis._retire_legacy_exec_incidents(self.db, self.now), 0)

    def test_non_agent_incidents_are_untouched(self):
        i = self._inc("p", key="signal:persistence:changed:/a.plist:deadbeef00")
        aegis._retire_legacy_exec_incidents(self.db, self.now)
        self.assertEqual(self._status(i), "OPEN")


class ReportLeadsWithAVerdict(unittest.TestCase):
    """Fix 5 — and the self-check that keeps the headline honest."""

    def _f(self, sev, fp):
        return aegis.finding(sev, "process", "T-" + fp, "detail", fp)

    def test_clear_verdict_when_nothing_is_new(self):
        f = self._f("HIGH", "a")
        md = aegis._brief_report([f], [], [], [], False, 0, 0)
        self.assertIn("Nothing new", md)
        self.assertIn("Self-check", md)

    def test_new_high_produces_an_alert_headline(self):
        f = self._f("HIGH", "a")
        md = aegis._brief_report([f], [f], [], [], False, 0, 0)
        self.assertIn("NEW alert", md)

    def test_self_check_catches_a_headline_that_contradicts_its_input(self):
        """The failure this exists for: a green headline over red findings."""
        problems = aegis._report_self_check("clear", [self._f("HIGH", "a")],
                                            [self._f("HIGH", "a")], [])
        self.assertTrue(problems)

    def test_self_check_flags_a_quiet_headline_over_an_open_critical(self):
        for verdict in ("clear", "minor", "learning"):
            self.assertTrue(aegis._report_self_check(
                verdict, [], [], [{"severity": "CRITICAL", "id": 1}]), verdict)

    def test_an_open_critical_outranks_a_quiet_scan(self):
        """Caught on real data by the self-check: the first draft printed
        'Nothing new' over two open CRITICAL chains."""
        crit = [{"severity": "CRITICAL", "id": 9, "title": "chain",
                 "status": "OPEN", "evidence_count": 4}]
        md = aegis._brief_report([], [], crit, [], False, 0, 0)
        self.assertIn("CRITICAL incident", md)
        self.assertNotIn("Nothing new", md)
        self.assertNotIn("SELF-CHECK FAILED", md)

    def test_an_open_critical_outranks_the_learning_period(self):
        crit = [{"severity": "CRITICAL", "id": 9, "title": "chain",
                 "status": "OPEN", "evidence_count": 4}]
        md = aegis._brief_report([], [], crit, [], False, 9, 0)
        self.assertNotIn("SELF-CHECK FAILED", md)
        self.assertIn("CRITICAL incident", md)

    def test_a_failed_self_check_is_published_above_the_evidence(self):
        """A reader who trusts the first paragraph must not have to reach the
        last line to learn it was wrong. Driven through the real renderer with
        a headline forced to contradict its input."""
        f = self._f("HIGH", "a")
        real = aegis._report_self_check
        aegis._report_self_check = lambda *a, **k: ["forced contradiction"]
        try:
            text = aegis._brief_report([f], [], [], [], False, 0, 0)
        finally:
            aegis._report_self_check = real
        self.assertIn("SELF-CHECK FAILED", text)
        lines = [l for l in text.splitlines() if l.strip()]
        warn = next(i for i, l in enumerate(lines) if "SELF-CHECK FAILED" in l)
        self.assertLessEqual(warn, 2, "the warning must sit at the top")

    def test_a_consistent_headline_publishes_a_clean_self_check(self):
        f = self._f("HIGH", "a")
        text = aegis._brief_report([f], [f], [], [], False, 0, 0)
        self.assertNotIn("SELF-CHECK FAILED", text)
        self.assertIn("Self-check: headline verified", text)

    def test_report_is_short(self):
        """The 208-line wall is the thing being replaced."""
        fs = [self._f("MEDIUM", str(i)) for i in range(200)]
        incs = [{"severity": "HIGH", "id": i, "title": "t", "status": "OPEN",
                 "evidence_count": 3} for i in range(90)]
        md = aegis._brief_report(fs, [], incs, [], False, 0, 0)
        self.assertLess(len(md.splitlines()), 25,
                        "the brief report must stay brief under load")


class LearningPeriod(unittest.TestCase):
    """Fix 3 — a detector's first weeks are its worst."""

    def test_window_is_active_then_expires(self):
        b = {"learning_until": 1000}
        self.assertTrue(aegis._in_learning_period(999, b))
        self.assertFalse(aegis._in_learning_period(1000, b))
        self.assertFalse(aegis._in_learning_period(500, {}))

    def test_setting_the_window_rewatermarks_the_baseline(self):
        """`learn` writes a watched trust store out-of-band. Without a
        re-watermark the next scan reports Aegis's own documented command as
        'baseline modified out-of-band' — which it did, once, on the live
        machine."""
        tmp = tempfile.mkdtemp(prefix="aegis_learn_")
        saved = (aegis.STATE_DIR, aegis.BASELINE, aegis.SELFSTATE,
                 aegis.HMAC_KEY_FILE)
        aegis.STATE_DIR = tmp
        aegis.BASELINE = os.path.join(tmp, "baseline.json")
        aegis.SELFSTATE = os.path.join(tmp, "selfstate.json")
        aegis.HMAC_KEY_FILE = os.path.join(tmp, "hmac.key")
        try:
            aegis.save_json(aegis.BASELINE, {"persistence": {}})
            aegis.record_selfstate()
            before = aegis.load_json(aegis.SELFSTATE, {}).get("baseline_mac")
            aegis._set_learning_period(7)
            after = aegis.load_json(aegis.SELFSTATE, {}).get("baseline_mac")
            self.assertIsNotNone(after)
            self.assertNotEqual(before, after, "watermark must follow the write")
            self.assertEqual(after, aegis._hmac_file(aegis.BASELINE))
        finally:
            (aegis.STATE_DIR, aegis.BASELINE, aegis.SELFSTATE,
             aegis.HMAC_KEY_FILE) = saved
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_report_says_it_is_learning(self):
        md = aegis._brief_report([], [], [], [], False, 5, 0)
        self.assertIn("Learning this machine", md)
        self.assertIn("5 day", md)


if __name__ == "__main__":
    unittest.main()
