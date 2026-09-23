#!/usr/bin/env python3
"""A verdict teaches at the width the custody ladder can VERIFY.

Measured on the live store, 2026-09-23: 72 hand verdicts across 45 classes,
and 109 new incidents opened in a class the operator had already judged.
Tolerance was keyed on `process:<path>:<trust>` (and, since #51, on the exact
bytes), so every rebuild, new worktree, runner self-update or translocated
copy arrived as a stranger. The ladder already knows more than the path: a
publisher's team id, a package receipt, the repo a build came out of, the
vouched program that started it. Each of those is a CLASS a verdict can
teach, and `_finding_classes` is the one place a class key is spelled.

Widths, and why they differ: a team id is anchored in a signing chain this
uid cannot mint, and a package receipt in an install transaction the
operator ran, so one verdict tolerates. A build repo or a supervisor is
derived from content the operator's own tools move, so it keeps the floor of
three.

Every tolerance guard still applies: never CRITICAL, never attack-defined,
never above the reviewed severity, never a disputed class. An interpreter
teaches no class at all -- its signature, receipt or repo says nothing about
what it runs.

Fully sandboxed: every state path is redirected into a tmp dir.
"""
import ast
import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402
from conftest import PUBLISHER_TRUST, SUSPICIOUS_TRUST  # noqa: E402

NOW = 1786600000  # > 2026-01-01 store floor
TEAM = "ABCDE12345"
AUTHORITY = "Developer ID Application: Example Scholarship Corp (%s)" % TEAM
REPO = "/Users/c/.ai/worktrees/zotero-ee606f08/claude-refactor"
SUPERVISOR_SHA = "5" * 64


def _sha(n):
    return hashlib.sha256(str(n).encode("ascii")).hexdigest()


def _proc(path, sha, trust=SUSPICIOUS_TRUST, severity="HIGH", **facts):
    """A process finding shaped as check_processes emits one, facts and all."""
    return aegis.finding(
        severity, "process", "Suspicious running process",
        "%s (%s) running from user-writable path" % (path, trust),
        "process:%s:%s:%s" % (path, trust, sha),
        case_fingerprint="process:sha:%s" % sha,
        subject=aegis._subject("process", path, trust=trust, content=sha),
        path=path, trust=trust, sha256=sha, **facts)


def _signed(path, sha, **kw):
    return _proc(path, sha, trust=PUBLISHER_TRUST, team=TEAM,
                 authority=AUTHORITY, **kw)


def _built(path, sha, **kw):
    return _proc(path, sha, custody="build-output", build_repo=REPO, **kw)


class TheClassesAFindingNames(unittest.TestCase):
    """Pure derivation: which classes does one finding carry?"""

    def test_a_publisher_signature_with_a_team_names_its_signer(self):
        f = _signed("/Users/c/w/one/Tool.app/Contents/MacOS/tool", _sha(1))
        self.assertIn(("signer:%s" % TEAM, "anchored"),
                      aegis._finding_classes(f))

    def test_an_adhoc_signature_names_no_signer_even_with_a_team_field(self):
        """Only a verdict the platform calls a publisher chain may name a
        team: an ad-hoc or broken signature vouches for nobody."""
        f = _proc("/Users/c/w/one/tool", _sha(1), team=TEAM,
                  authority=AUTHORITY)
        self.assertEqual(aegis._finding_classes(f), [])

    def test_a_malformed_team_names_nothing(self):
        for team in ("", "not set", "abcde12345", "ABCDE1234", "../../x"):
            f = _proc("/Users/c/w/tool", _sha(1), trust=PUBLISHER_TRUST,
                      team=team)
            self.assertEqual(aegis._finding_classes(f), [], team)

    def test_an_interpreter_teaches_no_class(self):
        """A signed interpreter beaconing is whatever script it runs; its
        signer, receipt and repo say nothing about that script."""
        for name in ("python3.13", "python3", "node", "bash", "pwsh",
                     "python.exe"):
            f = _signed("/Users/c/w/bin/%s" % name, _sha(1),
                        custody="package-managed", package="uv-python:cpython")
            self.assertEqual(aegis._finding_classes(f), [], name)

    def test_attack_defined_evidence_names_no_class(self):
        f = _signed("/Users/c/w/tool", _sha(1), attack_defined=True)
        self.assertEqual(aegis._finding_classes(f), [])

    def test_only_binary_subjects_carry_classes(self):
        f = dict(_signed("/Users/c/w/tool", _sha(1)), category="persistence")
        self.assertEqual(aegis._finding_classes(f), [])

    def test_a_package_receipt_names_its_package_without_the_version(self):
        a = _proc("/opt/homebrew/Cellar/jq/1.7.1/bin/jq", _sha(1),
                  custody="package-managed", package="homebrew:jq@1.7.1")
        b = _proc("/opt/homebrew/Cellar/jq/1.8.0/bin/jq", _sha(2),
                  custody="package-managed", package="homebrew:jq@1.8.0")
        self.assertEqual(aegis._finding_classes(a),
                         [("package:homebrew:jq", "anchored")])
        self.assertEqual(aegis._finding_classes(a), aegis._finding_classes(b))
        # A formula whose NAME carries a version stays that formula.
        c = _proc("/opt/homebrew/Cellar/x/bin/y", _sha(3),
                  custody="package-managed",
                  package="homebrew:python@3.14@3.14.6")
        self.assertEqual(aegis._finding_classes(c),
                         [("package:homebrew:python@3.14", "anchored")])

    def test_a_shim_names_no_package(self):
        f = _proc("/Users/c/AppData/Local/Microsoft/WinGet/Links/x.exe",
                  _sha(1), custody="package-managed", package="winget:link")
        self.assertEqual(aegis._finding_classes(f), [])

    def test_a_receipt_needs_the_package_managed_rung(self):
        f = _proc("/opt/x/bin/tool", _sha(1), package="homebrew:jq@1.7.1")
        self.assertEqual(aegis._finding_classes(f), [])

    def test_build_output_names_its_repo_at_content_width(self):
        f = _built("%s/app/staging/A.app/Contents/MacOS/a" % REPO, _sha(1))
        self.assertEqual(aegis._finding_classes(f),
                         [("buildrepo:%s" % REPO, "content")])

    def test_a_supervised_run_names_its_supervisor_bytes(self):
        f = _proc("/Users/c/runner/bin.2.337.0/Runner.Worker", _sha(1),
                  custody="supervised", supervisor=SUPERVISOR_SHA,
                  supervisor_path="/Users/c/runner/bin.2.337.0/Runner.Listener")
        self.assertEqual(aegis._finding_classes(f),
                         [("supervisor:%s" % SUPERVISOR_SHA, "content")])

    def test_signer_comes_first_then_custody(self):
        f = _signed("/Users/c/w/tool", _sha(1), custody="build-output",
                    build_repo=REPO)
        self.assertEqual([k for k, _w in aegis._finding_classes(f)],
                         ["signer:%s" % TEAM, "buildrepo:%s" % REPO])

    def test_a_finding_without_class_facts_names_nothing(self):
        """The store prefilter in _incident_classes relies on this: strip the
        fact fields and no class survives."""
        for f in (_signed("/Users/c/w/tool", _sha(1)),
                  _built("%s/dist/a" % REPO, _sha(2))):
            bare = {k: v for k, v in f.items()
                    if k not in aegis._CLASS_TRIGGER_KEYS}
            self.assertEqual(aegis._finding_classes(bare), [])


class TheFactsAnEmitterAttaches(unittest.TestCase):
    """_class_facts reads what the ladder just established; it never widens
    it and never raises."""

    def setUp(self):
        self._stubs = {}

    def tearDown(self):
        for k, v in self._stubs.items():
            setattr(aegis, k, v)

    def stub(self, name, value):
        self._stubs.setdefault(name, getattr(aegis, name))
        setattr(aegis, name, value)

    def test_team_is_read_only_under_a_publisher_verdict(self):
        self.stub("classify_signature", lambda p: {
            "trust": PUBLISHER_TRUST, "team": TEAM, "authority": AUTHORITY})
        self.assertEqual(aegis._class_facts("/x/tool", PUBLISHER_TRUST, None),
                         {"team": TEAM, "authority": AUTHORITY})
        self.assertEqual(aegis._class_facts("/x/tool", SUSPICIOUS_TRUST, None),
                         {})

    def test_a_classifier_that_disagrees_with_the_sensor_attaches_nothing(self):
        self.stub("classify_signature", lambda p: {
            "trust": SUSPICIOUS_TRUST, "team": TEAM, "authority": AUTHORITY})
        self.assertEqual(aegis._class_facts("/x/tool", PUBLISHER_TRUST, None),
                         {})

    def test_the_receipt_rides_on_the_package_rung(self):
        self.stub("_package_receipt", lambda p: "homebrew:jq@1.7.1")
        self.assertEqual(
            aegis._class_facts("/x/jq", SUSPICIOUS_TRUST, "package-managed"),
            {"package": "homebrew:jq@1.7.1"})

    def test_the_repo_root_rides_on_the_build_output_rung(self):
        path = "%s/app/staging/A.app/Contents/MacOS/a" % REPO
        self.stub("_git_bin", lambda: "git")
        self.stub("_repo_is_self_committed", lambda git, d: (REPO, True))
        self.assertEqual(
            aegis._class_facts(path, SUSPICIOUS_TRUST, "build-output"),
            {"build_repo": REPO})
        # A non-answer from git is never an answer.
        self.stub("_repo_is_self_committed", lambda git, d: (REPO, None))
        self.assertEqual(
            aegis._class_facts(path, SUSPICIOUS_TRUST, "build-output"), {})

    def test_the_supervisor_bytes_ride_on_the_supervised_rung(self):
        parent = "/Users/c/runner/bin.2.337.0/Runner.Listener"
        self.stub("_supervising_parent", lambda p, parents: parent)
        self.stub("_graded_sha", lambda p: SUPERVISOR_SHA)
        self.assertEqual(
            aegis._class_facts("/Users/c/runner/bin.2.337.0/Runner.Worker",
                               SUSPICIOUS_TRUST, "supervised", [parent]),
            {"supervisor": SUPERVISOR_SHA, "supervisor_path": parent})

    def test_a_failing_probe_costs_the_fact_never_the_scan(self):
        def boom(*_a, **_k):
            raise OSError("probe down")
        self.stub("_package_receipt", boom)
        self.assertEqual(
            aegis._class_facts("/x/jq", SUSPICIOUS_TRUST, "package-managed"),
            {})

    def test_check_processes_attaches_the_facts(self):
        path = ("C:\\Users\\c\\w\\tool.exe" if aegis.IS_WIN
                else "/Users/c/w/tool")
        self.stub("_iter_processes", lambda: iter([("42", "501", path, "t")]))
        self.stub("warm_signature_cache", lambda paths: None)
        self.stub("_is_trusted_prefix", lambda p: False)
        self.stub("_typosquats_apple_daemon", lambda name: None)
        self.stub("load_vouches", lambda *a, **k: ([], None))
        self.stub("classify_signature", lambda p: {
            "trust": PUBLISHER_TRUST, "team": TEAM, "authority": AUTHORITY})
        self.stub("_exec_alert", lambda p, t: ("HIGH", "runs from x"))
        self.stub("sha256", lambda p: _sha(1))
        self.stub("_grade_binary",
                  lambda sev, p, **k: ("MEDIUM", "build-output", None))
        self.stub("_git_bin", lambda: "git")
        self.stub("_repo_is_self_committed", lambda git, d: (REPO, True))
        got = aegis.check_processes()
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["team"], TEAM)
        self.assertEqual(got[0]["build_repo"], REPO)
        self.assertEqual([k for k, _w in aegis._finding_classes(got[0])],
                         ["signer:%s" % TEAM, "buildrepo:%s" % REPO])

    def test_a_beacon_carries_its_signer(self):
        path = "/Users/c/.vscode/extensions/vendor.tool-2.1.228/bin/tool"
        self.stub("classify_signature", lambda p: {
            "trust": PUBLISHER_TRUST, "team": TEAM, "authority": AUTHORITY})
        self.stub("is_risky_location", lambda p: True)
        self.stub("_is_trusted_prefix", lambda p: False)
        self.stub("_grade_binary", lambda sev, p, **k: (sev, None, None))
        self.stub("_vouch_endpoint_deviation", lambda p, e: (None, None))
        rows = [(path, "203.0.113.9", "443", PUBLISHER_TRUST)]
        stamps = tuple(NOW + i * 3600
                       for i in range(aegis.BEACON_MIN_SCANS + 2))
        got = aegis._beacon_from_sightings(
            {(path, "203.0.113.9", "443"): stamps}, rows)
        self.assertEqual(len(got), 1)
        self.assertEqual(aegis._finding_classes(got[0]),
                         [("signer:%s" % TEAM, "anchored")])


class _Sandbox(unittest.TestCase):
    PATHS = ("STATE_DIR", "EVENT_DB", "SEEN", "ALLOWLIST", "FINDINGS_LOG",
             "BASELINE", "SELFSTATE", "RUN_LOG", "LATEST_JSON", "SIGCACHE",
             "CUSTODY_FILE", "VOUCH_FILE", "VOUCH_SIGNERS", "INTENT_FILE",
             "ACTION_LOG", "ASSAY_FILE")

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_class_")
        state = os.path.join(self.tmp, ".aegis")
        os.makedirs(state)
        self._saved = {k: getattr(aegis, k) for k in self.PATHS}
        for k in self.PATHS:
            if k == "STATE_DIR":
                aegis.STATE_DIR = state
            elif k == "EVENT_DB":
                aegis.EVENT_DB = os.path.join(state, "aegis.db")
            else:
                setattr(aegis, k, os.path.join(
                    state, os.path.basename(self._saved[k])))
        aegis.save_json(aegis.BASELINE, {"learning_until": 0})
        aegis.init_event_store()
        self._stubs = {}

    def tearDown(self):
        for k, v in self._stubs.items():
            setattr(aegis, k, v)
        for k, v in self._saved.items():
            setattr(aegis, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def stub(self, name, value):
        self._stubs.setdefault(name, getattr(aegis, name))
        setattr(aegis, name, value)

    def ingest(self, f, at):
        """Record `f` and correlate it; returns the incident it landed in."""
        db = aegis._event_connection()
        try:
            with db:
                cur = db.execute(
                    "INSERT INTO events(occurred_at,observed_at,source,"
                    "event_type,data_json) VALUES(?,?,?,?,?)",
                    (at, at, f["category"], "observation.finding",
                     json.dumps(f, sort_keys=True)))
                aegis._apply_correlations(db, [(cur.lastrowid, f)], at,
                                          initially_notified=True)
            row = db.execute(
                "SELECT * FROM incidents ORDER BY id DESC LIMIT 1").fetchone()
            return dict(row)
        finally:
            db.close()

    def judge(self, f, at, code="benign-positive"):
        incident = self.ingest(f, at)
        self.assertEqual(incident["status"], "OPEN", incident)
        self.assertTrue(aegis.transition_incident(
            incident["id"], "FALSE_POSITIVE", now=at + 30, reason_code=code))
        return incident["id"]

    def seed_verdict(self, f, at):
        """A judged incident written straight into the store: its evidence
        event, the incident at the finding's own severity, the dismissal."""
        db = aegis._event_connection()
        try:
            with db:
                ev = db.execute(
                    "INSERT INTO events(occurred_at,observed_at,source,"
                    "event_type,data_json) VALUES(?,?,?,?,?)",
                    (at, at, f["category"], "observation.finding",
                     json.dumps(f, sort_keys=True))).lastrowid
                key = "signal:" + f["case_fingerprint"]
                iid = db.execute(
                    "INSERT INTO incidents(kind,correlation_key,title,"
                    "severity,status,created_at,first_seen,last_seen,"
                    "updated_at,resolution) VALUES('signal',?,?,?,"
                    "'FALSE_POSITIVE',?,?,?,?,'benign-positive')",
                    (key, f["title"], f["severity"], at, at, at, at)
                ).lastrowid
                db.execute("INSERT INTO incident_events(incident_id,event_id)"
                           " VALUES(?,?)", (iid, ev))
                db.execute(
                    "INSERT INTO dismissals(incident_id,correlation_key,"
                    "reason_code,category,dismissed_at) VALUES(?,?,?,?,?)",
                    (iid, key, "benign-positive", f["category"], at))
            return iid
        finally:
            db.close()

    def memory(self, at):
        db = aegis._event_connection()
        try:
            return aegis._suppression_memory(db, at)
        finally:
            db.close()

    def decide(self, f, at):
        return aegis._signal_decision(f, self.memory(at))


class ASignerVerdictTeachesAtWidthOne(_Sandbox):

    def test_one_verdict_tolerates_the_team_at_a_different_path(self):
        self.judge(_signed("/Users/c/w/one/Tool.app/Contents/MacOS/tool",
                           _sha(1)), NOW)
        classes = self.memory(NOW + 600)[5]
        self.assertEqual(classes.get("signer:%s" % TEAM),
                         (1, aegis.SEV_ORDER["HIGH"]))
        other = _signed("/Users/c/Downloads/Other.app/Contents/MacOS/other",
                        _sha(2))
        self.assertEqual(self.decide(other, NOW + 600), ("tolerated", 1))

    def test_an_adhoc_binary_at_that_path_is_not_covered(self):
        self.judge(_signed("/Users/c/w/one/tool", _sha(1)), NOW)
        adhoc = _proc("/Users/c/w/two/tool", _sha(2))
        self.assertEqual(aegis._finding_classes(adhoc), [])
        self.assertEqual(self.decide(adhoc, NOW + 600), (None, 0))

    def test_another_team_is_a_stranger(self):
        self.judge(_signed("/Users/c/w/one/tool", _sha(1)), NOW)
        other = _proc("/Users/c/w/two/tool", _sha(2), trust=PUBLISHER_TRUST,
                      team="ZZZZZ99999")
        self.assertEqual(self.decide(other, NOW + 600), (None, 0))

    def test_critical_is_never_tolerated_by_a_class(self):
        self.judge(_signed("/Users/c/w/one/tool", _sha(1)), NOW)
        crit = _signed("/Users/c/w/two/tool", _sha(2), severity="CRITICAL")
        self.assertEqual(self.decide(crit, NOW + 600), (None, 0))

    def test_attack_defined_is_never_tolerated_by_a_class(self):
        self.judge(_signed("/Users/c/w/one/tool", _sha(1)), NOW)
        hostile = _signed("/Users/c/w/two/tool", _sha(2), attack_defined=True)
        self.assertEqual(self.decide(hostile, NOW + 600), (None, 0))

    def test_never_above_the_severity_the_operator_reviewed(self):
        # A MEDIUM finding opens no signal incident of its own, so the
        # reviewed MEDIUM case is seeded the way the store holds one.
        self.seed_verdict(_signed("/Users/c/w/one/tool", _sha(1),
                                  severity="MEDIUM"), NOW)
        higher = _signed("/Users/c/w/two/tool", _sha(2), severity="HIGH")
        self.assertEqual(self.decide(higher, NOW + 600), (None, 0))
        same = _signed("/Users/c/w/three/tool", _sha(3), severity="MEDIUM")
        self.assertEqual(self.decide(same, NOW + 600), ("tolerated", 1))

    def test_a_false_positive_teaches_no_class(self):
        """false-positive is a complaint about the RULE, not a statement
        about the subject, exactly as for every other tolerance tier."""
        self.judge(_signed("/Users/c/w/one/tool", _sha(1)), NOW,
                   code="false-positive")
        self.assertEqual(self.memory(NOW + 600)[5], {})
        other = _signed("/Users/c/w/two/tool", _sha(2))
        self.assertEqual(self.decide(other, NOW + 600), (None, 0))

    def test_the_next_incident_in_the_class_opens_pre_closed(self):
        self.judge(_signed("/Users/c/w/one/tool", _sha(1)), NOW)
        later = self.ingest(_signed("/Users/c/w/two/tool", _sha(2)),
                            NOW + 600)
        self.assertEqual(later["status"], "FALSE_POSITIVE")
        self.assertEqual(later["resolution"], "auto-tolerated")


class ABuildRepoNeedsThreeVerdicts(_Sandbox):

    def _staging(self, n):
        return _built("%s/app/staging/A%d.app/Contents/MacOS/a" % (REPO, n),
                      _sha(n))

    def test_two_verdicts_are_not_enough(self):
        for n in (1, 2):
            self.judge(self._staging(n), NOW + n * 600)
        self.assertNotIn("buildrepo:%s" % REPO, self.memory(NOW + 3000)[5])
        self.assertEqual(self.decide(self._staging(9), NOW + 3000), (None, 0))

    def test_three_verdicts_tolerate_the_next_build(self):
        for n in (1, 2, 3):
            self.judge(self._staging(n), NOW + n * 600)
        self.assertEqual(self.decide(self._staging(9), NOW + 3000),
                         ("tolerated", 3))

    def test_a_build_of_another_repo_is_a_stranger(self):
        for n in (1, 2, 3):
            self.judge(self._staging(n), NOW + n * 600)
        other = _proc("/Users/c/elsewhere/dist/a", _sha(9),
                      custody="build-output", build_repo="/Users/c/elsewhere")
        self.assertEqual(self.decide(other, NOW + 3000), (None, 0))


class ADisputeRevokesTheClass(_Sandbox):

    def test_a_reopen_on_one_incident_revokes_the_class_for_the_rest(self):
        """The verdict on A stands; B was auto-tolerated under the class it
        taught. The operator reopening B is a dispute about the CLASS, so C
        -- a third binary signed by the same team -- must alert again even
        though A's verdict is still on the books."""
        self.judge(_signed("/Users/c/w/a/tool", _sha(1)), NOW)
        b = self.ingest(_signed("/Users/c/w/b/tool", _sha(2)), NOW + 600)
        self.assertEqual(b["resolution"], "auto-tolerated")
        self.assertTrue(aegis.transition_incident(b["id"], "OPEN",
                                                  now=NOW + 900))
        memory = self.memory(NOW + 1200)
        self.assertIn("signer:%s" % TEAM, memory[5])
        self.assertIn("signer:%s" % TEAM, memory[2])
        c = _signed("/Users/c/w/c/tool", _sha(3))
        self.assertEqual(aegis._signal_decision(c, memory), (None, 0))

    def test_a_dispute_on_a_build_repo_reaches_the_class(self):
        for n in (1, 2):
            self.judge(_built("%s/dist/a%d" % (REPO, n), _sha(n)),
                       NOW + n * 600)
        disputed = self.ingest(_built("%s/dist/d" % REPO, _sha(7)),
                               NOW + 1500)
        self.assertTrue(aegis.transition_incident(
            disputed["id"], "INVESTIGATING", now=NOW + 1530))
        self.judge(_built("%s/dist/a3" % REPO, _sha(3)), NOW + 1800)
        memory = self.memory(NOW + 2400)
        self.assertIn("buildrepo:%s" % REPO, memory[5])
        self.assertIn("buildrepo:%s" % REPO, memory[2])
        self.assertEqual(aegis._signal_decision(
            _built("%s/dist/a9" % REPO, _sha(9)), memory), (None, 0))


class FindingClassesIsTheOnlySpelling(_Sandbox):
    """A verdict and a lookup can never disagree on a class key, because both
    are computed by _finding_classes and nothing else."""

    def test_memory_and_decision_both_route_through_it(self):
        """Mutation test: replace _finding_classes with a probe that renders
        a key no real class has. If the memory builder or the decision spelled
        a key any other way, the probe key could not connect them."""
        def probe(f):
            if isinstance(f, dict) and f.get("category") == "process":
                return [("probe:%s" % f.get("custody"), "anchored")]
            return []
        self.stub("_finding_classes", probe)
        self.judge(_built("%s/dist/a" % REPO, _sha(1)), NOW)
        memory = self.memory(NOW + 600)
        self.assertEqual(set(memory[5]), {"probe:build-output"})
        # Unrelated in every fact a real class reads, same probe key.
        other = _proc("/Users/c/nowhere/x", _sha(2), custody="build-output",
                      build_repo="/Users/c/nowhere")
        self.assertEqual(aegis._signal_decision(other, memory),
                         ("tolerated", 1))

    def test_no_other_function_spells_a_class_key(self):
        """AST, not grep: aegis.py embeds code templates as string literals,
        so a grep can count a key that is never executed."""
        src_path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "aegis.py")
        with open(src_path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        spellers = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Constant) and isinstance(sub.value, str)
                        and sub.value.startswith(("signer:%", "package:%",
                                                  "buildrepo:%",
                                                  "supervisor:%"))):
                    spellers.add(node.name)
        self.assertEqual(spellers, {"_finding_classes"})


class AVerdictSaysWhatItLearned(_Sandbox):

    def cli(self, fn, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = fn(*args)
        return rc, out.getvalue()

    def test_a_signer_lesson_is_printed_with_its_width(self):
        incident = self.ingest(_signed("/Users/c/w/a/tool", _sha(1)), NOW)
        rc, out = self.cli(aegis.cmd_incident, incident["id"],
                           "benign-positive")
        self.assertEqual(rc, 0, out)
        self.assertIn(
            "Learned: anything signed by team %s (Example Scholarship Corp) "
            "— wherever it runs (1 verdict, tolerates now)" % TEAM, out)

    def test_a_build_repo_lesson_counts_toward_its_floor(self):
        incident = self.ingest(_built("%s/dist/a" % REPO, _sha(1)), NOW)
        rc, out = self.cli(aegis.cmd_incident, incident["id"],
                           "benign-positive")
        self.assertEqual(rc, 0, out)
        self.assertIn("Learned: build output of %s (1 of 3 verdicts)" % REPO,
                      out)

    def test_a_false_positive_prints_no_lesson(self):
        incident = self.ingest(_signed("/Users/c/w/a/tool", _sha(1)), NOW)
        rc, out = self.cli(aegis.cmd_incident, incident["id"],
                           "false-positive")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("Learned:", out)

    def test_crossing_a_floor_is_written_to_the_action_log(self):
        incident = self.ingest(_signed("/Users/c/w/a/tool", _sha(1)), NOW)
        self.cli(aegis.cmd_incident, incident["id"], "benign-positive")
        with open(aegis.ACTION_LOG, encoding="utf-8") as fh:
            actions = [json.loads(ln) for ln in fh if ln.strip()]
        granted = [a for a in actions
                   if a["action"] == "class-tolerance-granted"]
        self.assertEqual([a["target"] for a in granted],
                         ["signer:%s" % TEAM])

    def test_families_show_the_class_they_would_teach(self):
        self.ingest(_signed("/Users/c/w/a/tool", _sha(1)), NOW)
        rc, out = self.cli(aegis.cmd_families)
        self.assertEqual(rc, 0, out)
        self.assertIn("would teach: anything signed by team %s (Example "
                      "Scholarship Corp) — wherever it runs" % TEAM, out)

    def test_a_family_verdict_prints_what_it_learned(self):
        self.ingest(_built("%s/dist/a" % REPO, _sha(1)), NOW)
        rc, out = self.cli(aegis.cmd_family, "1", "benign-positive")
        self.assertEqual(rc, 0, out)
        self.assertIn("Learned: build output of %s (1 of 3 verdicts)" % REPO,
                      out)


class TheReplaySeesClassMemory(_Sandbox):

    def test_the_teaching_line_counts_classes(self):
        self.judge(_signed("/Users/c/w/a/tool", _sha(1)), NOW - 86400)
        self.stub("_assay_lanes", lambda: [])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            aegis.cmd_backtest_replay(now=NOW)
        self.assertIn("1 class(es) taught", out.getvalue())


if __name__ == "__main__":
    unittest.main()
