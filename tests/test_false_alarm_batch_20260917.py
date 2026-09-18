#!/usr/bin/env python3
"""The 2026-09-17 batch: 110 open incidents, four root causes, ~15 facts.

The live reference Mac held 110 OPEN incidents (104 HIGH, 2 CRITICAL, 4
MEDIUM) against 365 already adjudicated FALSE_POSITIVE. Counted by distinct
underlying fact rather than by row, the open set was roughly fifteen things.
Three clusters carried it, and each had its own cause:

  37  Persistence item CHANGED    all at ONE timestamp, 2026-09-15 22:51:48.
                                  Five facts: /bin/bash, /usr/bin/open,
                                  /usr/bin/python3, /bin/date, /usr/bin/ssh,
                                  replaced together by the macOS 27.0 update
                                  (identical mtime Sep 3 03:34). /bin/bash
                                  alone accounted for 29 incidents because 29
                                  launchd jobs invoke it.
  42  Suspicious running process  26 distinct binaries. One build of the
                                  operator's own app was byte-identical at
                                  /Applications, ~/Downloads and four agent
                                  worktree staging trees (sha f0dddc74…).
  22  Persistent outbound         17 endpoint keys, EVERY one resolving to
      connection (beacon shape)   ec2-*.compute-1.amazonaws.com -- one service
                                  behind rotating addresses. 13 of them were
                                  one binary.

Underneath sat a fourth cause that made the first cluster possible at all, and
it is the one worth remembering: `_classify_mac` identified Apple's own
binaries by `leaf == "Software Signing"`, an exact match on a string Apple
renames between major releases. From macOS 26 it is "macOS Software Signing",
so on upgrade day the `apple` trust tier emptied -- 109 of 123 /usr/bin
binaries carried the new string and not one classified `apple`. See
test_signature_corpus.py, which is the ratchet for that class of bug.

The shared shape of the three clusters is worth naming, because this monitor
has now re-solved it once per surface for a month: a finding's case was keyed
on WHERE something was seen rather than on WHAT was seen. A path, a plist, a
socket. So one fact observed at N places became N incidents, each demanding
its own adjudication. The fix is never suppression -- every cluster below
still reaches the report -- it is making the N places EVIDENCE on one case.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aegis  # noqa: E402
from conftest import SUSPICIOUS_TRUST  # noqa: E402


def plist(label, program, sha, path=None, trust=None):
    """A launchd record as the snapshot builds it.

    `trust` is a required-in-practice parameter with no default, so this
    module-level helper never hard-codes a macOS-only verdict -- the callers
    that need one are inside macOS-gated classes. See tests/conftest.py,
    NoTestHardCodesOneBodysTrustVocabulary.
    """
    return {
        "label": label, "program": program, "sha256": sha,
        "trust": trust, "env": None, "args": [program, "/tmp/x.sh"],
        "run_at_load": True,
        "path": path or ("/Users/x/Library/LaunchAgents/%s.plist" % label),
    }


class OneOsUpdateIsOneFinding(unittest.TestCase):
    """29 jobs invoking /bin/bash is still one /bin/bash."""

    def setUp(self):
        self._mac, self._sip = aegis.IS_MAC, aegis._SIP_STATE
        aegis.IS_MAC, aegis._SIP_STATE = True, True

    def tearDown(self):
        aegis.IS_MAC, aegis._SIP_STATE = self._mac, self._sip

    def _snaps(self, n=29, program="/bin/bash", trust="apple", tag=""):
        # trust="apple" is the premise: a bytes-only change to an Apple
        # platform binary under SIP. This class is registered macOS-only.
        base, cur = {}, {}
        for i in range(n):
            p = ("/Users/x/Library/LaunchAgents/com.example%s.job%d.plist"
                 % (tag, i))
            rec = plist("com.example%s.job%d" % (tag, i), program, "OLD", p,
                        trust=trust)
            rec["trust"] = trust
            base[p] = dict(rec)
            new = dict(rec, sha256="NEW")
            cur[p] = new
        return base, cur

    def test_twenty_nine_referrers_collapse_to_one(self):
        base, cur = self._snaps()
        out = aegis.check_persistence(base, cur)
        changed = [f for f in out if f["title"].startswith("Persistence item")]
        updates = [f for f in out if "OS program" in f["title"]]
        self.assertEqual(changed, [], "per-plist findings should be gone")
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0]["severity"], "LOW")

    def test_the_referrers_survive_as_evidence(self):
        """Collapsing must not destroy information. The single finding knows
        more than any of the 29 it replaces: all 29 referrers."""
        base, cur = self._snaps()
        f = [x for x in aegis.check_persistence(base, cur)
             if "OS program" in x["title"]][0]
        self.assertEqual(f["referrer_count"], 29)
        self.assertEqual(len(f["referrers"]), 29)
        self.assertEqual(f["path"], "/bin/bash")

    def test_distinct_programs_stay_distinct(self):
        """Five OS binaries updating is five facts, not one and not 37."""
        base, cur = {}, {}
        for prog in ("/bin/bash", "/usr/bin/open", "/usr/bin/python3",
                     "/bin/date", "/usr/bin/ssh"):
            b, c = self._snaps(n=4, program=prog, tag=prog.replace("/", "-"))
            base.update(b)
            cur.update(c)
        updates = [f for f in aegis.check_persistence(base, cur)
                   if "OS program" in f["title"]]
        self.assertEqual(sorted(f["path"] for f in updates),
                         ["/bin/bash", "/bin/date", "/usr/bin/open",
                          "/usr/bin/python3", "/usr/bin/ssh"])

    def test_next_update_is_not_a_silenced_recurrence(self):
        """The signal key carries the new sha, so a later update re-alerts."""
        base, cur = self._snaps(n=2)
        first = [f for f in aegis.check_persistence(base, cur)
                 if "OS program" in f["title"]][0]
        base2 = {k: dict(v, sha256="NEW") for k, v in base.items()}
        cur2 = {k: dict(v, sha256="NEWER") for k, v in cur.items()}
        second = [f for f in aegis.check_persistence(base2, cur2)
                  if "OS program" in f["title"]][0]
        self.assertNotEqual(first["fingerprint"], second["fingerprint"])
        self.assertEqual(first["case_fingerprint"], second["case_fingerprint"])


class TheGuardRefusesEverythingItShould(unittest.TestCase):
    """Each conjunct in _os_program_update, pinned by the attack it stops.

    A quieting rule is only as good as its refusals, so these are spelled out
    one per attack rather than folded into a table.
    """

    def setUp(self):
        self._mac, self._sip = aegis.IS_MAC, aegis._SIP_STATE
        aegis.IS_MAC, aegis._SIP_STATE = True, True

    def tearDown(self):
        aegis.IS_MAC, aegis._SIP_STATE = self._mac, self._sip

    @staticmethod
    def _p(label, program, sha, path=None):
        """Apple-platform-signed, which is the premise under test here."""
        return plist(label, program, sha, path, trust="apple")

    def _call(self, old, rec, **kw):
        flags = {"prog_changed": True, "env_changed": False,
                 "args_changed": False, "target_changed": False}
        flags.update(kw)
        return aegis._os_program_update(old, rec, **flags)

    def test_accepts_the_real_case(self):
        old = self._p("j", "/bin/bash", "OLD")
        self.assertEqual(self._call(old, dict(old, sha256="NEW")), "/bin/bash")

    def test_refuses_a_dylib_injection_riding_along(self):
        old = self._p("j", "/bin/bash", "OLD")
        rec = dict(old, sha256="NEW", env={"DYLD_INSERT_LIBRARIES": "/tmp/e.dylib"})
        self.assertIsNone(self._call(old, rec, env_changed=True))

    def test_refuses_a_rewritten_payload_riding_along(self):
        old = self._p("j", "/bin/bash", "OLD")
        self.assertIsNone(self._call(old, dict(old, sha256="NEW"),
                                     target_changed=True))
        self.assertIsNone(self._call(old, dict(old, sha256="NEW"),
                                     args_changed=True))

    def test_refuses_a_repointed_program(self):
        """The job now runs something else. That is the attack, not an update."""
        old = self._p("j", "/bin/bash", "OLD")
        rec = dict(old, program="/tmp/evil", sha256="NEW")
        self.assertIsNone(self._call(old, rec))

    def test_refuses_anything_off_the_sealed_system_volume(self):
        """The guard's premise is that nothing running as the operator can
        write where the program lives, so every operator-writable prefix must
        be refused.

        Derived from the live tuples rather than named literally, and that is
        the whole lesson of this test: `/opt/homebrew` is operator-writable on
        macOS and `/opt/` is a root-owned package root on Linux. simbody flips
        the IS_* flags but leaves RISKY_PREFIXES and TRUSTED_PREFIXES bound to
        the REAL host, so a literal here asserts a macOS fact on a Linux
        runner -- and CI runs the mac simbody leg on ubuntu. The first version
        of this test hard-coded `/opt/homebrew` and failed there while passing
        on every local Mac run, including the local `SIM_BODY=mac` one, which
        on a Mac is close to a no-op.
        """
        risky = [p for p in aegis.RISKY_PREFIXES
                 if not (p.rstrip("/") + "/").startswith(aegis.TRUSTED_PREFIXES)]
        self.assertTrue(risky, "no operator-writable prefix on this body")
        for prefix in risky:
            prog = os.path.join(prefix, "bin", "bash")
            old = self._p("j", prog, "OLD")
            self.assertIsNone(self._call(old, dict(old, sha256="NEW")), prog)

    def test_refuses_a_non_apple_signature(self):
        """A Developer-ID or adhoc binary sitting in /usr/bin is exactly the
        supply-chain swap the original rule was written for."""
        for trust in ("developer-id", "signed-other", "adhoc", "unsigned",
                      "broken", "app-store", None):
            old = self._p("j", "/usr/bin/open", "OLD")
            old["trust"] = trust
            self.assertIsNone(self._call(old, dict(old, sha256="NEW")), trust)

    def test_refuses_when_sip_is_off(self):
        """The whole argument is "nothing as the operator can write there".
        With SIP off that is false, so the guard must vanish."""
        aegis._SIP_STATE = False
        old = self._p("j", "/bin/bash", "OLD")
        self.assertIsNone(self._call(old, dict(old, sha256="NEW")))

    def test_sip_unknown_reads_as_off(self):
        """Fails closed: an unreadable csrutil keeps the alarm."""
        aegis._SIP_STATE = None
        real = aegis.run
        aegis.run = lambda *a, **k: ("", "csrutil: not found", 127)
        try:
            self.assertFalse(aegis._sip_enabled())
        finally:
            aegis.run = real
            aegis._SIP_STATE = True


class RotatingEndpointsAreOneRelationship(unittest.TestCase):
    """13 addresses on one port from one binary is one service, not 13 beacons.

    Every one of the 17 live endpoint keys resolved to
    ec2-*.compute-1.amazonaws.com. The sensor's premise is that a beacon's
    endpoint does NOT move, so a program spread across many addresses is
    evidence AGAINST the hypothesis the sensor is testing -- and it was being
    turned into the fan-out key, which multiplied both the incident count and
    the per-entity risk weight.
    """

    def _rows(self, n, path="/Users/x/app/staging/A.app/Contents/MacOS/a",
              port="443"):
        # The sensor's gate is `suspicious_sig(trust) or is_risky_location(path)`,
        # so naming a per-body suspicious verdict satisfies it everywhere and the
        # test needs no path shape at all. Hard-coding "adhoc" here made all six
        # of these pass on macOS and fail on Windows -- a verdict that does not
        # exist in the Authenticode vocabulary -- which is precisely the defect
        # class tests/simbody.py was written to catch, and it caught it.
        # Dispersion is platform-neutral logic, so this is gated to no body.
        return [(path, "203.0.113.%d" % (i + 1), port, SUSPICIOUS_TRUST)
                for i in range(n)]

    def _run(self, rows):
        now = 1_000_000
        stamps = tuple(now + i * 3600 for i in range(aegis.BEACON_MIN_SCANS + 2))
        sightings = {(r[0], r[1], r[2]): stamps for r in rows}
        return aegis._beacon_from_sightings(sightings, rows)

    def test_many_addresses_collapse_to_one_finding(self):
        out = self._run(self._rows(13))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["title"],
                         "Persistent outbound connection (rotating endpoints)")
        self.assertEqual(out[0]["endpoint_count"], 13)
        self.assertEqual(len(out[0]["endpoints"]), 13)

    def test_a_fixed_endpoint_keeps_the_full_alarm(self):
        """The real beacon shape must be untouched -- this is the detection."""
        out = self._run(self._rows(1))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["title"],
                         "Persistent outbound connection (beacon shape)")

    def test_a_short_fallback_list_keeps_the_full_alarm(self):
        """A C2 fallback list is characteristically 2-3 addresses. The
        threshold sits deliberately above it."""
        for n in (2, 3):
            out = self._run(self._rows(n))
            self.assertEqual(len(out), n, "%d addresses" % n)
            for f in out:
                self.assertEqual(
                    f["title"], "Persistent outbound connection (beacon shape)")

    def test_dispersion_demotes_exactly_one_step_and_is_not_dropped(self):
        out = self._run(self._rows(13))
        self.assertEqual(out[0]["severity"], "MEDIUM")  # one step from HIGH
        self.assertIn("every address is listed here", out[0]["detail"])

    def test_different_ports_stay_different_relationships(self):
        rows = self._rows(5, port="443") + self._rows(5, port="8443")
        out = self._run(rows)
        self.assertEqual(sorted(f["port"] for f in out), ["443", "8443"])

    def test_different_programs_stay_different(self):
        rows = (self._rows(5, path="/Users/x/a/staging/A.app/Contents/MacOS/a")
                + self._rows(5, path="/Users/x/b/staging/B.app/Contents/MacOS/b"))
        self.assertEqual(len(self._run(rows)), 2)


class BuildOutputIsARung(unittest.TestCase):
    """A generated artifact of the operator's own repo can finally be graded.

    `_grade_binary` asked exactly two questions -- is there a hand-signed
    vouch, is there a package receipt -- and a developer's machine answers no
    to both for everything it builds. This is the missing rung, not a missing
    wire.
    """

    def setUp(self):
        aegis._BUILD_OUTPUT_CACHE.clear()
        aegis._REPO_SELFNESS_CACHE.clear()
        aegis._REPO_ROOT_CACHE.clear()

    tearDown = setUp

    def test_the_os_update_finding_names_a_rung(self):
        """Every finding declares who authored its subject or says why it
        cannot (test_custody_roster.py). For an Apple platform binary under
        SIP the author is the OS vendor -- a real answer, not a gap."""
        self.assertIn("os-vendor", aegis._VOUCHED_CUSTODY)
        self.assertEqual(aegis._CUSTODY_FLOOR["os-vendor"], "LOW")
        self.assertIn("os-vendor", aegis._PROVENANCE_NOTE)
        self.assertEqual(aegis._RISK_CUSTODY_WEIGHT["os-vendor"], 0.25)
        # Never zero-weighted: 29 collapsed referrers must not be able to sum
        # into an interrupt, but an OS update is not proof of innocence.
        self.assertGreater(aegis._RISK_CUSTODY_WEIGHT["os-vendor"], 0.0)

    def test_it_is_weak_by_construction(self):
        """One step, never suppression, still corroborating at half weight."""
        self.assertIn("build-output", aegis._WEAK_CUSTODY)
        self.assertEqual(aegis._RISK_CUSTODY_WEIGHT["build-output"], 0.5)
        self.assertEqual(aegis._demote("HIGH", "build-output"), "MEDIUM")
        self.assertEqual(aegis._demote("CRITICAL", "build-output"), "HIGH")
        self.assertIn("build-output", aegis._PROVENANCE_NOTE)

    def test_attack_defined_evidence_is_never_graded_by_it(self):
        self.assertEqual(
            aegis._demote("HIGH", "build-output", attack_defined=True), "HIGH")

    def test_a_path_with_no_repo_gets_nothing(self):
        self.assertIsNone(aegis._build_output_rung("/tmp/nope/not-a-repo-bin"))
        self.assertIsNone(aegis._build_output_rung(""))
        self.assertIsNone(aegis._build_output_rung(None))

    def test_a_tracked_file_in_our_own_repo_gets_nothing(self):
        """The rung is "the repo says it GENERATES this", not "the repo knows
        about it". aegis.py is committed, so it must not qualify."""
        here = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "aegis.py")
        self.assertIsNone(aegis._build_output_rung(here))

    def test_the_question_is_asked_once_per_directory(self):
        """Not once per file. Three subprocesses per binary, re-run for every
        sibling in the same build tree, cost about 2.3 s on a scan grading ~40
        of them -- against a 1 % scan cost ceiling. The answer is identical for
        every file in a directory, so it is cached there.

        This also fixes the semantics rather than only the cost: `.gitignore`
        declares build output by DIRECTORY (`dist/`, `app/staging/`), and
        `git check-ignore` resolves ancestor patterns, so one call on the
        containing directory already answers for everything beside it.
        """
        d = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # The first file in a repo pays the fixed cost of identifying it:
        # rev-parse, then the HEAD-authorship probes, then check-ignore. What
        # must not scale is the PER-FILE cost, so measure the increment.
        aegis._build_output_rung(os.path.join(d, "aegis.py"))
        calls = []
        real = aegis.run

        def counting(cmd, *a, **k):
            calls.append(cmd[0] if cmd else "")
            return real(cmd, *a, **k)

        aegis.run = counting
        try:
            for name in ("README.md", "ARCHITECTURE.md", "ROADMAP.md"):
                aegis._build_output_rung(os.path.join(d, name))
        finally:
            aegis.run = real
        self.assertEqual(
            calls, [],
            "three more files in an ALREADY-ANSWERED directory asked git "
            "%d more times: %r" % (len(calls), calls))

    def test_a_repeat_path_costs_nothing(self):
        real = aegis.run
        d = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        aegis._build_output_rung(os.path.join(d, "aegis.py"))
        calls = []

        def counting(cmd, *a, **k):
            calls.append(cmd)
            return real(cmd, *a, **k)

        aegis.run = counting
        try:
            aegis._build_output_rung(os.path.join(d, "aegis.py"))
        finally:
            aegis.run = real
        self.assertEqual(calls, [])


class TheStoreIsBroughtToTheNewIdentities(unittest.TestCase):
    """A fix the operator cannot see is indistinguishable from no fix.

    Changing which key a NEW incident is minted under does nothing for the 110
    rows already sitting in the store, and those rows were the whole
    complaint. This is the migration that folds them, in the shape
    _STORE_MIGRATIONS documents.
    """

    def setUp(self):
        import sqlite3
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE incidents(id INTEGER PRIMARY KEY, kind TEXT,
              correlation_key TEXT, title TEXT, severity TEXT, status TEXT,
              created_at INT, first_seen INT, last_seen INT, updated_at INT,
              reminder_count INT DEFAULT 0, next_reminder_at INT,
              last_notified_at INT, resolution TEXT, subject_json TEXT,
              last_novel_at INT);
            CREATE TABLE events(id INTEGER PRIMARY KEY, incident_id INT,
              data_json TEXT);
            CREATE TABLE incident_events(incident_id INT, event_id INT);
        """)
        self.n = 0

    def tearDown(self):
        self.db.close()

    def _inc(self, key, data=None, title="t", status="OPEN"):
        self.n += 1
        i = self.n
        # created_at 0 < the migration's `now`: these are rows minted under
        # the OLD identity, which is the only population it may touch.
        self.db.execute(
            "INSERT INTO incidents(id,kind,correlation_key,title,severity,"
            "status,created_at,first_seen,last_seen,updated_at) "
            "VALUES(?,'signal',?,?,'HIGH',?,0,0,0,0)", (i, key, title, status))
        if data is not None:
            import json as _j
            self.db.execute("INSERT INTO events(id,incident_id,data_json) "
                            "VALUES(?,?,?)", (i, i, _j.dumps(data)))
            self.db.execute("INSERT INTO incident_events(incident_id,event_id)"
                            " VALUES(?,?)", (i, i))
        return i

    def _run(self):
        return aegis._merge_2026_09_case_identities(self.db, 1000)

    def _keys(self, status="OPEN"):
        return sorted(r["correlation_key"] for r in self.db.execute(
            "SELECT correlation_key FROM incidents WHERE status=?", (status,)))

    def test_same_bytes_at_seven_paths_become_one_case(self):
        for i in range(7):
            self._inc("signal:process:/p%d/app" % i,
                      {"sha256": "SHA1", "path": "/p%d/app" % i},
                      title="Suspicious running process")
        self._run()
        self.assertEqual(self._keys(), ["signal:process:sha:SHA1"])

    def test_different_bytes_stay_separate(self):
        self._inc("signal:process:/a/app", {"sha256": "SHA1"})
        self._inc("signal:process:/b/app", {"sha256": "SHA2"})
        self._run()
        self.assertEqual(self._keys(), ["signal:process:sha:SHA1",
                                        "signal:process:sha:SHA2"])

    def test_the_survivor_inherits_every_sibling_event(self):
        """Folding must not destroy evidence -- the point of folding rather
        than closing."""
        ids = [self._inc("signal:process:/p%d/app" % i, {"sha256": "SHA1"})
               for i in range(5)]
        self._run()
        keep = self.db.execute(
            "SELECT id FROM incidents WHERE status='OPEN'").fetchone()["id"]
        self.assertIn(keep, ids)
        n = self.db.execute("SELECT COUNT(*) c FROM incident_events WHERE "
                            "incident_id=?", (keep,)).fetchone()["c"]
        self.assertEqual(n, 5)

    def test_a_lone_process_incident_is_still_rekeyed(self):
        """Otherwise the next scan mints a SECOND case beside the old one."""
        self._inc("signal:process:/only/app", {"sha256": "SHA9"})
        self._run()
        self.assertEqual(self._keys(), ["signal:process:sha:SHA9"])

    def test_thirteen_addresses_become_one_relationship(self):
        for i in range(13):
            self._inc("signal:beacon:/A.app/MacOS/a:203.0.113.%d:443" % i)
        self._run()
        self.assertEqual(self._keys(),
                         ["signal:beacon:rotating:/A.app/MacOS/a:443"])

    def test_a_short_address_list_is_left_alone(self):
        """The migration must not fold what the forward fix would not."""
        for i in range(3):
            self._inc("signal:beacon:/A.app/MacOS/a:203.0.113.%d:443" % i)
        self._run()
        self.assertEqual(len(self._keys()), 3)

    def test_persistence_changed_cases_are_retired_not_folded(self):
        """They are orphaned: the case is the PROGRAM now, and which plist
        referenced it is no longer an identity."""
        for i in range(29):
            self._inc("signal:persistence:changed:/L/com.x.job%d.plist" % i,
                      {"detail": "com.x: program bytes aaaa -> bbbb",
                       "program": "/bin/bash"})
        self._run()
        self.assertEqual(self._keys(), [])
        row = self.db.execute("SELECT resolution FROM incidents LIMIT 1"
                              ).fetchone()
        self.assertIn("one case per program", row["resolution"])

    def test_a_live_config_change_incident_is_never_retired(self):
        """The key `changed:<plist>` is STILL what the code mints for a
        rewritten payload or a repointed job. Matching the shape alone -- the
        way the three earlier migrations could -- would close live, correct
        incidents. Each of these must survive.
        """
        self._inc("signal:persistence:changed:/L/a.plist",
                  {"detail": "a: args changed (watch -> scan)",
                   "program": "/bin/bash"})
        self._inc("signal:persistence:changed:/L/b.plist",
                  {"detail": "b: env changed (DYLD_INSERT_LIBRARIES)",
                   "program": "/bin/bash"})
        self._inc("signal:persistence:changed:/L/c.plist",
                  {"detail": "c: program bytes aaaa -> bbbb",
                   "program": "/Users/x/bin/tool"})  # not the system volume
        self._inc("signal:persistence:changed:/L/d.plist",
                  {"detail": "d: program /bin/bash -> /tmp/evil"},)
        self._run()
        self.assertEqual(len(self._keys()), 4, self._keys())

    def test_it_never_touches_an_incident_from_the_current_scan(self):
        """_run_store_migrations runs INSIDE record_security_state, after
        correlation -- so on its first run the store already contains the
        incidents this very scan just opened. Retiring or re-keying those
        would close a brand-new true positive in the same breath as raising
        it, and the first version of this migration did exactly that.
        """
        self.n = 10
        now = 1000
        for key, data in (
                ("signal:process:/fresh/app", {"sha256": "SHAX"}),
                ("signal:persistence:changed:/L/fresh.plist",
                 {"detail": "f: program bytes aaaa -> bbbb",
                  "program": "/bin/bash"})):
            self.n += 1
            i = self.n
            self.db.execute(
                "INSERT INTO incidents(id,kind,correlation_key,title,"
                "severity,status,created_at,first_seen,last_seen,updated_at) "
                "VALUES(?,'signal',?,'t','HIGH','OPEN',?,?,?,?)",
                (i, key, now, now, now, now))
            import json as _j
            self.db.execute("INSERT INTO events(id,incident_id,data_json) "
                            "VALUES(?,?,?)", (i, i, _j.dumps(data)))
            self.db.execute("INSERT INTO incident_events(incident_id,event_id)"
                            " VALUES(?,?)", (i, i))
        aegis._merge_2026_09_case_identities(self.db, now)
        self.assertEqual(
            self._keys(),
            ["signal:persistence:changed:/L/fresh.plist",
             "signal:process:/fresh/app"])

    def test_already_adjudicated_rows_are_untouched(self):
        """A migration may not reopen or rewrite a verdict the operator gave."""
        self._inc("signal:process:/p/app", {"sha256": "SHA1"},
                  status="FALSE_POSITIVE")
        self._inc("signal:persistence:changed:/L/x.plist", status="RESOLVED")
        self._run()
        self.assertEqual(self._keys("FALSE_POSITIVE"),
                         ["signal:process:/p/app"])
        self.assertEqual(self._keys("RESOLVED"),
                         ["signal:persistence:changed:/L/x.plist"])

    def test_it_never_violates_correlation_key_uniqueness(self):
        """If a new-scheme case already exists, the old rows fold INTO it."""
        self._inc("signal:process:sha:SHA1", {"sha256": "SHA1"})
        self._inc("signal:process:/p1/app", {"sha256": "SHA1"})
        self._inc("signal:process:/p2/app", {"sha256": "SHA1"})
        self._run()
        self.assertEqual(self._keys(), ["signal:process:sha:SHA1"])

    def test_an_incident_with_no_stored_sha_is_left_alone(self):
        """No evidence to re-key on, so no guess."""
        self._inc("signal:process:/p/app", {"path": "/p/app"})
        self._run()
        self.assertEqual(self._keys(), ["signal:process:/p/app"])

    def test_it_is_registered_to_run_once(self):
        keys = [row[0] for row in aegis._STORE_MIGRATIONS]
        self.assertIn("case_identity_2026_09_merged", keys)
        fns = {row[0]: row[1] for row in aegis._STORE_MIGRATIONS}
        self.assertIs(fns["case_identity_2026_09_merged"],
                      aegis._merge_2026_09_case_identities)


if __name__ == "__main__":
    unittest.main()
