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
from conftest import SUSPICIOUS_TRUST  # noqa: E402


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

    def test_a_settled_baseline_is_a_plain_compare(self):
        """Exec keys are settled in the store (baseline v3), so the steady-
        state diff must not re-hash every entry on both sides each scan — a
        forever-tax paid for a baseline vintage most installs never had. A
        legacy-shaped prior is still re-keyed in memory, because the
        watermark-mismatch path leaves a tampered file untouched on disk."""
        calls = []
        real = aegis._migrate_exec_keys
        aegis._migrate_exec_keys = lambda execs: (calls.append(1), real(execs))[1]
        try:
            aegis.diff_agent_surface(self._snap(["a"]), self._snap(["a", "b"]))
            self.assertEqual(calls, [], "steady state must not re-key")
            legacy = {"/cfg/settings.json": {"sha256": "x" * 64, "execs": {
                "hooks.SessionStart[0].hooks[0]|a": {"cmd": "a", "args": []}}}}
            fs = self._new_execs(legacy, self._snap(["a"]))
            self.assertTrue(calls, "a legacy-shaped prior must be re-keyed")
            self.assertEqual(fs, [], "re-keyed legacy prior must match")
        finally:
            aegis._migrate_exec_keys = real

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
              last_notified_at INT, subject_json TEXT, last_novel_at INT);
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
             key=None, novel_days=None, reminders=None):
        """`novel_days` is how long ago this incident last said something NEW
        (default: its whole age), and `reminders` how many times it has been
        surfaced (default: the full ladder, i.e. the operator has been told)."""
        at = self.now - age_days * 86400
        novel = self.now - (age_days if novel_days is None
                            else novel_days) * 86400
        self.db.execute(
            "INSERT INTO incidents(correlation_key,title,severity,kind,status,"
            "created_at,updated_at,last_novel_at,reminder_count) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (key or ("signal:" + ident), ident, sev, kind, status, at, at,
             novel, len(aegis._REMINDER_DELAYS) if reminders is None
             else reminders))
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

    def test_evidence_that_only_repeats_itself_does_not_buy_a_reprieve(self):
        """The fix. A condition that is CONTINUOUSLY true re-emits the same
        evidence on every scan, so keying age-out on updated_at made it
        unreachable: on the reference machine all 27 open incidents had
        refreshed updated_at on the final scan, one of them across 2,122
        events over 17 days, and none could ever be retired. Recurrence is
        not news."""
        i = self._inc("persistence:new:/L/x.plist", age_days=30)
        self.db.execute("UPDATE incidents SET updated_at=? WHERE id=?",
                        (self.now, i))          # re-seen this very scan
        self.assertEqual(aegis._age_out_incidents(self.db, self.now), 1)
        self.assertEqual(self._status(i), "FALSE_POSITIVE")

    def test_a_new_fingerprint_resets_the_clock(self):
        """The safety half: an old incident that says something it has never
        said before is live, however long it has been open."""
        i = self._inc("persistence:new:/L/x.plist", age_days=30, novel_days=1)
        self.assertEqual(aegis._age_out_incidents(self.db, self.now), 0)
        self.assertEqual(self._status(i), "OPEN")

    def test_nothing_is_retired_before_the_operator_was_told(self):
        """Age-out closes what the operator has ignored, which requires that
        they were asked. Exercised at a window SHORTER than the reminder
        ladder, which is the only place the clause can bind — at the shipped
        7d it never does, because a 7d-quiet incident is necessarily old
        enough for the ladder to have finished. Pinned so that shortening
        _AGE_OUT_DAYS cannot silently start retiring un-surfaced incidents."""
        i = self._inc("process:/bin/x", age_days=2, reminders=1)
        self.assertEqual(aegis._age_out_incidents(self.db, self.now, days=1), 0)
        self.assertEqual(self._status(i), "OPEN")
        self.db.execute("UPDATE incidents SET reminder_count=? WHERE id=?",
                        (len(aegis._REMINDER_DELAYS), i))
        self.assertEqual(aegis._age_out_incidents(self.db, self.now, days=1), 1)

    def test_a_stalled_reminder_pump_cannot_make_the_queue_immortal(self):
        """Reminders are claimed only on a scan that raised no new HIGH, so a
        machine noisy enough to raise one every scan never advances a
        reminder_count. Time the ladder should have taken stands in, or the
        gate would restore the unbounded queue under exactly the load that
        makes one unbearable."""
        i = self._inc("process:/bin/x", age_days=30, reminders=0)
        self.assertEqual(aegis._age_out_incidents(self.db, self.now), 1)
        self.assertEqual(self._status(i), "FALSE_POSITIVE")

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


class LegacyProgramIncidentsRetire(_DBCase):
    """Only unreachable version-keyed cases are superseded on upgrade."""

    def test_versioned_program_cases_retire_once(self):
        process = self._inc(
            "p", key="signal:process:/tmp/tool:unsigned:" + "a" * 64)
        beacon = self._inc(
            "b", key="signal:beacon:/opt/tool-2.1.0/bin/tool:1.2.3.4:443")
        self.assertEqual(
            aegis._retire_orphaned_program_incidents(self.db, self.now), 2)
        self.assertEqual(self._status(process), "FALSE_POSITIVE")
        self.assertEqual(self._status(beacon), "FALSE_POSITIVE")
        self.assertEqual(
            aegis._retire_orphaned_program_incidents(self.db, self.now), 0)

    def test_endpoint_version_does_not_retire_stable_program(self):
        stable = self._inc(
            "b", key="signal:beacon:/opt/tool/bin/tool:1.2.3.4:443")
        outbound = self._inc(
            "o", key="signal:outbound:/opt/tool/bin/tool:8.9.10.11:443")
        self.assertEqual(
            aegis._retire_orphaned_program_incidents(self.db, self.now), 0)
        self.assertEqual(self._status(stable), "OPEN")
        self.assertEqual(self._status(outbound), "OPEN")


class StoreMigrationsRunOnce(_DBCase):
    """The shared migration runner. Every incident-identity redesign used to
    ship its own recognizer + retire function + private meta key + call-site
    try/except; this pins the one runner that replaced that scaffold, and the
    properties each hand-rolled copy had to remember by itself."""

    def setUp(self):
        super().setUp()
        self.db.executescript(
            "CREATE TABLE incident_events(incident_id INT, event_id INT);")
        self.logged = []
        self._saved_log = aegis.log_run
        aegis.log_run = self.logged.append

    def tearDown(self):
        aegis.log_run = self._saved_log
        super().tearDown()

    def _stamps(self):
        return {r[0] for r in self.db.execute("SELECT key FROM meta")}

    def test_each_migration_runs_once_and_is_stamped(self):
        old = self._inc(
            "x", key="signal:agent-surface:newexec:/c.json:hooks.A[0]|node srv")
        self.assertEqual(aegis._run_store_migrations(self.db, self.now),
                         len(aegis._STORE_MIGRATIONS))
        self.assertEqual(self._status(old), "FALSE_POSITIVE")
        self.assertEqual(self._stamps(),
                         {k for k, _fn, _log in aegis._STORE_MIGRATIONS})
        # Second pass: nothing runs. The STAMP is the guard, not the data.
        self.assertEqual(aegis._run_store_migrations(self.db, self.now), 0)

    def test_a_store_stamped_under_the_old_per_shim_guards_does_not_rerun(self):
        """Live stores were stamped by the hand-rolled shims under these same
        keys; the runner must honour them or every upgrade re-migrates."""
        self.db.execute(
            "INSERT INTO meta VALUES('exec_identity_migrated','1')")
        old = self._inc(
            "x", key="signal:agent-surface:newexec:/c.json:hooks.A[0]|node srv")
        aegis._run_store_migrations(self.db, self.now)
        self.assertEqual(self._status(old), "OPEN")

    def test_a_failing_migration_is_not_stamped_and_blocks_nothing(self):
        def boom(db, now):
            raise RuntimeError("nope")
        saved = aegis._STORE_MIGRATIONS
        aegis._STORE_MIGRATIONS = (("m_boom", boom, "%d"),) + saved
        try:
            ran = aegis._run_store_migrations(self.db, self.now)
        finally:
            aegis._STORE_MIGRATIONS = saved
        self.assertEqual(ran, len(saved))
        self.assertNotIn("m_boom", self._stamps(),
                         "a failed migration must retry next scan")
        self.assertTrue({k for k, _fn, _log in saved} <= self._stamps())
        self.assertTrue(any("m_boom" in m for m in self.logged))

    def test_recognizers_are_frozen_not_the_live_patterns(self):
        """The orphaned-program migration once evaluated legacy keys through
        the LIVE beacon/version regexes, so its meaning moved whenever
        detection did. A migration's patterns are its own objects."""
        import inspect
        src = inspect.getsource(aegis._is_orphaned_program_key)
        self.assertNotRegex(src, r"(?<!_MIG)_BEACON_FP_RE")
        self.assertNotIn("_TOLERANCE_VERSION_RE", src)
        self.assertIn("_MIG_BEACON_FP_RE", src)


class RotatingEndpointsNeedEvidence(_DBCase):
    """Fix 2b — a rotating service generalizes only once rotation is
    demonstrated, and the shape of the evidence decides how far it generalizes."""

    def test_ipv6_is_parsed_from_the_right(self):
        """The defect real data exposed. A beacon fingerprint is
        `beacon:<path>:<ip>:<port>` and an IPv6 address contains colons, so
        splitting on ':' and taking [-2] silently folded 'fd7a:115c:a1e0::'
        into the PATH and read the empty tail as the address — no IPv6 beacon
        could ever generalize, and the class was polluted with the address."""
        self.assertEqual(
            aegis._beacon_parts("beacon:/opt/homebrew/opt/syncthing/bin/"
                                "syncthing:fd7a:115c:a1e0:::22000"),
            ("/opt/homebrew/opt/syncthing/bin/syncthing", "fd7a:115c:a1e0::",
             "22000"))

    def test_ipv4_and_version_churn(self):
        self.assertEqual(
            aegis._beacon_parts("beacon:/app-1.2.3/bin/x:1.2.3.4:443"),
            ("/app-#/bin/x", "1.2.3.4", "443"))

    def test_a_hostname_is_a_fact_and_never_generalizes(self):
        fp = "beacon:/bin/x:evil.example.com:443"
        self.assertIsNone(aegis._beacon_parts(fp))
        self.assertEqual(aegis._beacon_endpoint_classes(fp), [])

    def test_only_semantically_valid_ip_and_port_literals_generalize(self):
        """Shape-compatible garbage is not endpoint evidence. A tolerance
        class must be learned only from real IP literals on valid TCP ports."""
        invalid = (
            "beacon:/bin/x:999.999.999.999:443",
            "beacon:/bin/x:12345::1:443",
            "beacon:/bin/x:::443",
            "beacon:/bin/x:1.2.3.4:0",
            "beacon:/bin/x:1.2.3.4:65536",
        )
        for fp in invalid:
            self.assertIsNone(aegis._beacon_parts(fp), fp)

    def test_attack_defined_prefixes_never_generalize(self):
        for pre in ("decoy:", "latch:", "canary:"):
            self.assertIsNone(
                aegis._beacon_parts(pre + "beacon:/bin/x:1.2.3.4:443"))

    def test_the_narrow_class_keeps_the_port(self):
        a = aegis._beacon_endpoint_classes("beacon:/bin/x:1.2.3.4:443")[0][0]
        b = aegis._beacon_endpoint_classes("beacon:/bin/x:1.2.3.4:4444")[0][0]
        self.assertNotEqual(a, b)

    def _dismiss(self, endpoints, sev="HIGH"):
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS dismissals(id INTEGER PRIMARY KEY,"
            "incident_id INT, correlation_key TEXT, reason_code TEXT,"
            "category TEXT, dismissed_at INT)")
        for n, (ip, port) in enumerate(endpoints):
            key = "signal:beacon:/bin/app:%s:%s" % (ip, port)
            i = self._inc("b%d" % n, sev=sev, key=key)
            self.db.execute(
                "INSERT INTO dismissals(incident_id,correlation_key,reason_code,"
                "category,dismissed_at) VALUES(?,?,?,?,?)",
                (i, key, "benign-positive", "net-beacon", self.now))
        return aegis._rotating_endpoint_memory(self.db, self.now)

    def test_fixed_port_rotation_earns_only_the_narrow_class(self):
        mem = self._dismiss([("1.1.1.1", "443"), ("2.2.2.2", "443"),
                             ("3.3.3.3", "443")])
        self.assertIn("beacon:/bin/app:#ip:443", mem)
        self.assertNotIn("beacon:/bin/app:#ip:#port", mem,
                         "one port is not evidence of peer-to-peer")

    def test_peer_to_peer_breadth_earns_the_port_agnostic_class(self):
        """Syncthing's real shape: address AND port both vary, so the
        fixed-port class can never reach its threshold and the operator's
        verdicts would otherwise teach nothing."""
        mem = self._dismiss([("1.1.1.1", "22000"), ("2.2.2.2", "59217"),
                             ("3.3.3.3", "62124")])
        self.assertIn("beacon:/bin/app:#ip:#port", mem)

    def test_two_endpoints_earn_nothing(self):
        self.assertEqual(
            self._dismiss([("1.1.1.1", "443"), ("2.2.2.2", "443")]), {})

    def test_one_address_repeated_earns_nothing(self):
        """Repetition is not rotation — the exact-key reattach covers that."""
        self.assertEqual(
            self._dismiss([("1.1.1.1", "443")] * 3), {})


class SubjectIdentityIsStructured(_DBCase):
    """Identity is declared as FIELDS by the three sensors whose identity
    churned, rendered to the same strings the fingerprint parsers derive, and
    stored on the incident — so the operator's verdicts attach to what a
    finding is ABOUT rather than to how a sensor happened to spell it. The
    fingerprint regexes remain only as the fallback for rows that predate
    subjects."""

    @staticmethod
    def _beacon(path, ip, port):
        return aegis.finding(
            "HIGH", "net-beacon", "b", "d",
            "beacon:%s:%s:%s" % (aegis._program_subject(path), ip, port),
            subject=aegis._subject("beacon", path, ip=ip, port=port))

    @staticmethod
    def _process(comm, trust, sha):
        return aegis.finding(
            "HIGH", "process", "p", "d", "process:%s:%s:%s" % (comm, trust, sha),
            subject=aegis._subject("process", comm, trust=trust, content=sha))

    @staticmethod
    def _persist(path, content):
        return aegis.finding(
            "HIGH", "persistence", "Persistence item CHANGED", "d",
            "persistence:changed:%s:%s" % (path, content),
            subject=aegis._subject("persistence", path, content=content))

    def test_rendered_identity_agrees_with_the_string_derivation(self):
        """ONE memory: a row that carries a subject and a row that predates
        one must render the same identity for the same finding, or the
        operator's older verdicts stop counting the day this ships."""
        cases = [
            self._beacon("/opt/homebrew/opt/syncthing/bin/syncthing",
                         "fd7a:115c:a1e0::", "22000"),
            self._beacon("/app-1.2.3/bin/x", "1.2.3.4", "443"),
            self._process("/Users/me/.vscode/extensions/pub.tool-1.4.2/bin/tool",
                          SUSPICIOUS_TRUST, "a" * 64),
            self._process("/tmp/plain", "unsigned", "b" * 64),
            self._process("/tmp/nohash", "unsigned", None),
            self._persist("/L/app-2.0/x.plist", "c" * 12),
        ]
        for f in cases:
            fp = f["fingerprint"]
            self.assertEqual(aegis._finding_identity(f),
                             aegis._tolerance_identity(fp), fp)
            self.assertEqual(aegis._finding_endpoint_classes(f),
                             aegis._beacon_endpoint_classes(fp), fp)
        # and the no-hash, no-version process really has nothing to generalize
        self.assertIsNone(aegis._finding_identity(cases[4]))

    def test_a_hostname_endpoint_never_generalizes_from_fields(self):
        self.assertEqual(aegis._finding_endpoint_classes(
            self._beacon("/bin/x", "evil.example.com", "443")), [])
        self.assertEqual(aegis._subject_endpoint_classes(
            aegis._subject("beacon", "/bin/x", ip="1.2.3.4", port="70000")), [])

    def _stored(self, key, subject, sev="HIGH"):
        i = self._inc("s", sev=sev, key=key)
        self.db.execute("UPDATE incidents SET subject_json=? WHERE id=?",
                        (aegis.json.dumps(subject), i))
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS dismissals(id INTEGER PRIMARY KEY,"
            "incident_id INT, correlation_key TEXT, reason_code TEXT,"
            "category TEXT, dismissed_at INT)")
        self.db.execute(
            "INSERT INTO dismissals(incident_id,correlation_key,reason_code,"
            "category,dismissed_at) VALUES(?,?,?,?,?)",
            (i, key, "benign-positive", "x", self.now))
        return i

    def test_memory_is_built_from_the_stored_subject_not_the_key(self):
        """The string parsers are unreachable for a row that carries a
        subject: beacons and processes stored under deliberately UNPARSEABLE
        keys still generalize, and still count as disputed while open."""
        for n, ip in enumerate(("fd7a::1", "fd7a::2", "fd7a::3")):
            self._stored("signal:beacon:garbage-%d" % n,
                         aegis._subject("beacon", "/bin/app", ip=ip, port="443"))
        for n in range(3):
            i = self._stored("signal:process:garbage-%d" % n,
                             aegis._subject("process", "/bin/tool",
                                            trust=SUSPICIOUS_TRUST,
                                            content="%064x" % n))
            if n == 0:
                # Dispute is an ACT, so one of these is explicitly reopened —
                # otherwise an untriaged row would not be disputed and this
                # test could not tell a subject-built dispute set from an
                # empty one.
                self.db.execute(
                    "INSERT INTO events(occurred_at,observed_at,source,"
                    "event_type,incident_id,data_json) VALUES(?,?,?,?,?,?)",
                    (self.now, self.now, "incident", "incident.lifecycle", i,
                     aegis.json.dumps({"from": "FALSE_POSITIVE",
                                       "to": "OPEN"})))
        saved = (aegis._beacon_endpoint_classes, aegis._tolerance_identity)

        def boom(_fp):
            raise AssertionError("string parser reached")
        aegis._beacon_endpoint_classes = boom
        aegis._tolerance_identity = boom
        try:
            rot = aegis._rotating_endpoint_memory(self.db, self.now)
            tol = aegis._tolerance_memory(self.db, self.now)
            disputed = aegis._disputed_identities(self.db)
        finally:
            aegis._beacon_endpoint_classes, aegis._tolerance_identity = saved
        self.assertIn("beacon:/bin/app:#ip:443", rot)
        self.assertIn("process:/bin/tool:" + SUSPICIOUS_TRUST, tol)
        self.assertIn("process:/bin/tool:" + SUSPICIOUS_TRUST, disputed)

    def test_rows_that_predate_subjects_still_parse_from_the_key(self):
        row = {"correlation_key": "signal:beacon:/bin/x:1.2.3.4:443",
               "subject_json": None}
        ident, classes = aegis._incident_identity(row)
        self.assertIsNone(ident)
        self.assertEqual(classes[0][0], "beacon:/bin/x:#ip:443")

    def test_an_existing_store_gains_the_column(self):
        path = os.path.join(self.tmp, "old.db")
        con = sqlite3.connect(path)
        legacy = aegis._EVENT_SCHEMA_SQL.replace(",\n            subject_json TEXT", "")
        self.assertNotIn("subject_json", legacy)
        con.executescript(legacy)
        con.close()
        saved = (aegis.STATE_DIR, aegis.EVENT_DB)
        aegis.STATE_DIR, aegis.EVENT_DB = self.tmp, path
        try:
            db = aegis._event_connection()
            cols = {r[1] for r in db.execute("PRAGMA table_info(incidents)")}
            db.close()
        finally:
            aegis.STATE_DIR, aegis.EVENT_DB = saved
        self.assertIn("subject_json", cols)

    def test_the_subject_is_stored_and_a_legacy_row_is_backfilled(self):
        state = os.path.join(self.tmp, ".aegis")
        os.makedirs(state)
        saved = {k: getattr(aegis, k) for k in ("STATE_DIR", "EVENT_DB")}
        aegis.STATE_DIR = state
        aegis.EVENT_DB = os.path.join(state, "aegis.db")
        try:
            aegis.init_event_store()
            db = aegis._event_connection()
            with db:
                db.execute(
                    "INSERT INTO incidents(kind,correlation_key,title,severity,"
                    "status,created_at,first_seen,last_seen,updated_at) VALUES("
                    "'signal','signal:beacon:/bin/app:1.2.3.4:443','t','HIGH',"
                    "'OPEN',1,1,1,1)")
            db.close()
            aegis.record_security_state(
                [self._beacon("/bin/app", "1.2.3.4", "443")], now=1787000000)
            db = aegis._event_connection()
            rows = db.execute(
                "SELECT correlation_key, subject_json FROM incidents").fetchall()
            db.close()
        finally:
            for k, v in saved.items():
                setattr(aegis, k, v)
        self.assertEqual(len(rows), 1, "must reattach, not open a second case")
        sub = aegis.json.loads(rows[0]["subject_json"])
        self.assertEqual((sub["kind"], sub["ip"], sub["port"]),
                         ("beacon", "1.2.3.4", "443"))

    def test_the_sensors_declare_their_subjects(self):
        def rec(sha):
            return {"label": "com.x", "program": "/bin/bash",
                    "args": ["/bin/bash", "/r.sh"], "args_sha256": "0" * 64,
                    "sha256": sha, "trust": "unsigned", "run_at_load": True,
                    "authority": None, "env": None, "script_target": "/r.sh",
                    "target_sha": None}
        fs = [f for f in aegis.check_persistence({"/L/x.plist": rec("a" * 64)},
                                                 {"/L/x.plist": rec("b" * 64)})
              if f["title"] == "Persistence item CHANGED"]
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["subject"]["kind"], "persistence")
        self.assertEqual(aegis._finding_identity(fs[0]),
                         aegis._tolerance_identity(fs[0]["fingerprint"]))
        import inspect
        for fn in (aegis.check_processes, aegis._beacon_recurrence):
            self.assertIn("subject=_subject(", inspect.getsource(fn), fn.__name__)


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
