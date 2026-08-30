"""The provenance tier: one toolkit registering another job is one fact.

Measured cause, on this machine, 2026-08-29: 27 open incidents, every one of
them the operator's own infrastructure, and not one true positive lifetime
across 308 incidents. Six of the open HIGHs were six launchd jobs written by
the same scheduler kit — same launcher binary, same payload script, differing
only in the job name they pass as an argument. Nothing generalized over them
because acquired tolerance is antigen-specific to the PATH, so each new job
was a genuinely novel identity and the operator's verdicts on its siblings
could never apply.

Two supporting fixes have their own classes here, because the tier is inert
without them: a runner subcommand hid the payload that identifies a producer,
and an untriaged backlog counted as a dispute that stood tolerance down.

Every class pins one behaviour AND the safety property that stops it becoming
a blind spot — the same discipline as test_noise_reduction.py, for the same
reason: everything below suppresses something.
"""
import os
import sys
import sqlite3
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402
from conftest import SUSPICIOUS_TRUST  # noqa: E402

AIKIT_UV = "/Users/me/.local/bin/uv"
AIKIT_RUN = "/Users/me/Ai/Universe/tools/aikit/schedule/run.py"
UV_SHA = "94" + "1" * 62


def _job(name, program=AIKIT_UV, sha=UV_SHA, target=AIKIT_RUN, trust=None):
    """A launchd record for one job of a scheduler kit. The trust class comes
    from conftest, not from a macOS literal: "adhoc" is not suspicious on
    every body, so hard-coding it made these severity assertions pass here by
    construction and fail on the Windows leg."""
    trust = SUSPICIOUS_TRUST if trust is None else trust
    return "/Users/me/Library/LaunchAgents/com.kit.%s.plist" % name, {
        "label": "com.kit." + name, "program": program, "sha256": sha,
        "trust": trust, "args": [program, "run", target, name]}


class RunnerSubcommandsDoNotHideThePayload(unittest.TestCase):
    """`uv run app.py` is an interpreter driving a payload, and until now the
    payload was invisible: _script_target took the first argument after the
    binary, got the subcommand `run`, and returned None. That is a detection
    gap before it is a noise one — target_sha is what the CHANGED sensor
    diffs, so a swapped payload under an unchanged plist said nothing."""

    def test_the_payload_behind_a_runner_is_found(self):
        for argv, want in (
                ([AIKIT_UV, "run", AIKIT_RUN, "job"], AIKIT_RUN),
                ([AIKIT_UV, "run", "--quiet", "/tmp/payload.py"],
                 "/tmp/payload.py"),
                (["/opt/bin/npx", "/opt/tool/cli.js"], "/opt/tool/cli.js"),
                (["/opt/bin/poetry", "run", "/opt/x/main.py"], "/opt/x/main.py")):
            self.assertEqual(_script_target(argv), want, argv)

    def test_a_volatile_payload_behind_a_runner_scores_volatile(self):
        """The reason this is a security fix and not a cosmetic one: the
        launcher sits in a trusted path while the payload is the malware."""
        _p, rec = _job("evil", target="/tmp/payload.py")
        self.assertEqual(aegis._script_target(rec["args"], rec["program"]),
                         "/tmp/payload.py")

    def test_an_ordinary_interpreter_is_not_over_skipped(self):
        """The safety half. Only a subcommand the runner actually declares is
        consumed, so no interpreter's real first argument is ever skipped."""
        self.assertIsNone(_script_target(["/usr/bin/python3", "run", "thing"]))
        self.assertEqual(_script_target(["/usr/bin/python3", "/opt/x/a.py"]),
                         "/opt/x/a.py")
        # `tool` is not a declared uv subcommand, so nothing is consumed and
        # the non-absolute argument still refuses to resolve.
        self.assertIsNone(_script_target([AIKIT_UV, "tool", "pkg"]))


def _script_target(argv):
    return aegis._script_target(argv, argv[0])


class DisputeIsAnAct(unittest.TestCase):
    """An operator's silence is not an objection. Treating every active
    incident as disputed meant a noisy identity was suppressed by its own
    untriaged backlog, so verdicts on it could never take effect — tolerance
    engaged only where it was not needed. On the reference machine this put
    all 27 open incidents in dispute and left the dispute set covering every
    identity that mattered."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_prov_")
        self.db = sqlite3.connect(os.path.join(self.tmp, "t.db"))
        self.db.row_factory = sqlite3.Row
        self.now = 1_700_000_000
        self.db.executescript("""
            CREATE TABLE incidents(id INTEGER PRIMARY KEY, correlation_key TEXT,
              title TEXT, severity TEXT, kind TEXT, status TEXT,
              resolution TEXT, created_at INT, updated_at INT,
              next_reminder_at INT, reminder_count INT DEFAULT 0,
              last_notified_at INT, subject_json TEXT, last_novel_at INT);
            CREATE TABLE events(id INTEGER PRIMARY KEY, occurred_at INT,
              observed_at INT, source TEXT, event_type TEXT, signal_id INT,
              incident_id INT, data_json TEXT);
        """)

    def tearDown(self):
        self.db.close()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _inc(self, status="OPEN", key="signal:beacon:/bin/x:1.2.3.4:443"):
        self.db.execute(
            "INSERT INTO incidents(correlation_key,title,severity,kind,status,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (key, "t", "HIGH", "signal", status, self.now, self.now))
        return self.db.execute("SELECT last_insert_rowid()").fetchone()[0]

    def _reopen(self, i, frm="FALSE_POSITIVE"):
        self.db.execute(
            "INSERT INTO events(occurred_at,observed_at,source,event_type,"
            "incident_id,data_json) VALUES(?,?,?,?,?,?)",
            (self.now, self.now, "incident", "incident.lifecycle", i,
             aegis.json.dumps({"from": frm, "to": "OPEN"})))

    def test_an_untriaged_incident_is_a_backlog_item_not_an_objection(self):
        self._inc()
        self.assertEqual(aegis._disputed_identities(self.db), set())

    def test_an_explicit_reopen_still_disputes(self):
        """The safety half, and the documented contract: `reopen` is how an
        operator revokes tolerance, and it must keep working exactly."""
        self._reopen(self._inc())
        self.assertIn("beacon:/bin/x:#ip:443",
                      aegis._disputed_identities(self.db))

    def test_a_status_the_operator_moved_it_to_disputes(self):
        for status in ("ACK", "INVESTIGATING", "CONTAINED", "MONITORING"):
            self.db.execute("DELETE FROM incidents")
            self._inc(status=status)
            self.assertIn("beacon:/bin/x:#ip:443",
                          aegis._disputed_identities(self.db), status)


class ProducerTolerance(unittest.TestCase):
    """A toolkit's Nth job is the same fact as its first three."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_prod_")
        self.db = sqlite3.connect(os.path.join(self.tmp, "t.db"))
        self.db.row_factory = sqlite3.Row
        self.now = 1_700_000_000
        self.db.executescript("""
            CREATE TABLE incidents(id INTEGER PRIMARY KEY, correlation_key TEXT,
              title TEXT, severity TEXT, kind TEXT, status TEXT,
              resolution TEXT, created_at INT, updated_at INT,
              next_reminder_at INT, reminder_count INT DEFAULT 0,
              last_notified_at INT, subject_json TEXT, last_novel_at INT);
            CREATE TABLE events(id INTEGER PRIMARY KEY, occurred_at INT,
              observed_at INT, source TEXT, event_type TEXT, signal_id INT,
              incident_id INT, data_json TEXT);
            CREATE TABLE dismissals(id INTEGER PRIMARY KEY, incident_id INT,
              correlation_key TEXT, reason_code TEXT, category TEXT,
              dismissed_at INT);
        """)

    def tearDown(self):
        self.db.close()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def _finding(name, **kw):
        path, rec = _job(name, **kw)
        found = aegis.check_persistence({}, {path: rec})
        return [f for f in found if f["title"] == "New persistence item"][0]

    def _dismiss(self, name, code="benign-positive", sev="HIGH", **kw):
        f = self._finding(name, **kw)
        key = "signal:" + f["fingerprint"]
        self.db.execute(
            "INSERT INTO incidents(correlation_key,title,severity,kind,status,"
            "created_at,updated_at,subject_json) VALUES(?,?,?,?,?,?,?,?)",
            (key, "t", sev, "signal", "FALSE_POSITIVE", self.now, self.now,
             aegis.json.dumps(f["subject"])))
        i = self.db.execute("SELECT last_insert_rowid()").fetchone()[0]
        self.db.execute(
            "INSERT INTO dismissals(incident_id,correlation_key,reason_code,"
            "category,dismissed_at) VALUES(?,?,?,?,?)",
            (i, key, code, "persistence", self.now))
        return i

    def _decide(self, f):
        return aegis._signal_decision(f, aegis._suppression_memory(self.db,
                                                                   self.now))

    def _reviewed(self, *names, **kw):
        for n in names:
            self._dismiss(n, **kw)

    def test_the_fourth_job_of_a_reviewed_kit_is_tolerated(self):
        self._reviewed("alpha", "bravo", "charlie")
        self.assertEqual(self._decide(self._finding("delta")),
                         ("tolerated", 3))

    def test_two_verdicts_are_not_enough(self):
        """Repeated exposure, not one hasty dismissal: the same floor the
        rest of the tolerance layer holds."""
        self._reviewed("alpha", "bravo")
        self.assertEqual(self._decide(self._finding("charlie")), (None, 0))

    def test_a_different_launcher_is_a_different_producer(self):
        """The class names the launcher by its BYTES. A swapped binary at the
        same path inherits nothing."""
        self._reviewed("alpha", "bravo", "charlie")
        other = self._finding("delta", sha="ff" + "1" * 62)
        self.assertEqual(self._decide(other), (None, 0))

    def test_a_different_payload_is_a_different_producer(self):
        """`uv` alone generalizes nothing — an unrelated kit that happens to
        use the same runner is unrelated."""
        self._reviewed("alpha", "bravo", "charlie")
        other = self._finding("delta", target="/Users/me/other/kit/run.py")
        self.assertEqual(self._decide(other), (None, 0))

    def test_a_different_trust_class_is_a_different_producer(self):
        self._reviewed("alpha", "bravo", "charlie")
        other = "signed" if SUSPICIOUS_TRUST != "signed" else "unsigned"
        self.assertEqual(self._decide(self._finding("delta", trust=other)),
                         (None, 0))

    def test_a_job_with_no_payload_generalizes_nothing(self):
        """A launcher with no script target — a plain binary, or a runner
        whose subcommand we do not model — has no producer to belong to, so
        `/bin/bash` can never become a tolerated producer of anything."""
        path, rec = _job("plain")
        rec["args"] = ["/bin/bash"]
        rec["program"] = "/bin/bash"
        f = [x for x in aegis.check_persistence({}, {path: rec})
             if x["title"] == "New persistence item"][0]
        self.assertEqual(aegis._finding_producer_classes(f), [])

    def test_only_the_operators_own_verdicts_teach(self):
        """A machine closure must never build a trust root. Age-out writes no
        dismissal at all; a false-positive verdict tunes the rule instead."""
        self._reviewed("alpha", "bravo", "charlie", code="false-positive")
        self.assertEqual(self._decide(self._finding("delta")), (None, 0))

    def test_a_disputed_producer_stands_down(self):
        self._reviewed("alpha", "bravo", "charlie")
        f = self._finding("delta")
        key = "signal:" + f["fingerprint"]
        self.db.execute(
            "INSERT INTO incidents(correlation_key,title,severity,kind,status,"
            "created_at,updated_at,subject_json) VALUES(?,?,?,?,?,?,?,?)",
            (key, "t", "HIGH", "signal", "ACK", self.now, self.now,
             aegis.json.dumps(f["subject"])))
        self.assertEqual(self._decide(self._finding("echo")), (None, 0))

    def test_never_above_the_severity_actually_reviewed(self):
        self._reviewed("alpha", "bravo", "charlie", sev="MEDIUM")
        f = self._finding("delta")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(self._decide(f), (None, 0))

    def test_critical_is_never_tolerated(self):
        self._reviewed("alpha", "bravo", "charlie", sev="CRITICAL")
        f = dict(self._finding("delta"), severity="CRITICAL")
        self.assertEqual(self._decide(f), (None, 0))

    def test_a_changed_job_is_a_different_fact(self):
        """Only `new` generalizes. An existing job MUTATING is the shape a
        payload swap presents as, and keeps its own identity."""
        sub = aegis._subject("persistence", "/L/x.plist", op="changed",
                             content="ab" * 6, program_sha=UV_SHA,
                             target=AIKIT_RUN, trust=SUSPICIOUS_TRUST)
        self.assertEqual(aegis._subject_producer_classes(sub), [])

    def test_a_payload_swap_under_an_approved_producer_still_alerts(self):
        """The compensating control, and the reason the trade is sound. The
        tier tolerates another job from a reviewed kit, so the honest question
        is what an attacker who mimics that kit gains — and the answer is that
        they must write the reviewed payload, which is now a CHANGED finding
        on every job that runs it. Before the runner fix that swap produced no
        script target at all and so was invisible; the tier is only defensible
        because the same change made it visible."""
        path, rec = _job("alpha")
        rec["script_target"] = AIKIT_RUN
        rec["target_sha"] = "a" * 64
        swapped = dict(rec, target_sha="b" * 64)
        changed = [f for f in aegis.check_persistence({path: rec},
                                                      {path: swapped})
                   if f["title"] == "Persistence item CHANGED"]
        self.assertEqual(len(changed), 1)
        self._reviewed("alpha", "bravo", "charlie")
        # ...and a reviewed PRODUCER never tolerates that changed fact, whose
        # identity is its own and is not a producer class at all.
        self.assertEqual(aegis._finding_producer_classes(changed[0]), [])
        self.assertEqual(self._decide(changed[0]), (None, 0))

    def test_tolerated_is_recorded_not_invisible(self):
        """The incident is still created with its full evidence and closed
        citing precedent — the operator can always audit what was quieted."""
        self._reviewed("alpha", "bravo", "charlie")
        decision, verdicts = self._decide(self._finding("delta"))
        self.assertEqual(decision, "tolerated")
        self.assertGreaterEqual(verdicts, aegis._PRODUCER_MIN_SIBLINGS)


class BlessedFactsDoNotManufactureChains(unittest.TestCase):
    """Chains are built from events, so they were blind to the routing gate:
    a reviewed scheduler kit correlated with its own scheduled execution into
    a permanent CRITICAL, and chains are neither tolerated nor aged out. The
    quieting is on the TRIGGER set only — the safety tests below are the
    point of the change, not a caveat on it."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_chain_")
        self.saved = (aegis.STATE_DIR, aegis.EVENT_DB)
        aegis.STATE_DIR = self.tmp
        aegis.EVENT_DB = os.path.join(self.tmp, "t.db")
        self.now = 1_700_000_000

    def tearDown(self):
        aegis.STATE_DIR, aegis.EVENT_DB = self.saved
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, findings, routing):
        db = aegis._event_connection()
        new_events = []
        with db:
            for f in findings:
                cur = db.execute(
                    "INSERT INTO events(occurred_at,observed_at,source,"
                    "event_type,data_json) VALUES(?,?,?,?,?)",
                    (self.now, self.now, f["category"],
                     "observation.finding", aegis.json.dumps(f)))
                new_events.append((cur.lastrowid, f))
            aegis._apply_correlations(db, new_events, self.now, routing=routing)
        n = db.execute("SELECT COUNT(*) FROM incidents WHERE kind='correlation'"
                       ).fetchone()[0]
        db.close()
        return n

    @staticmethod
    def _pair():
        path = "/Users/me/Library/LaunchAgents/com.kit.job.plist"
        return [
            aegis.finding("HIGH", "persistence", "New persistence item", "d",
                          "persistence:new:%s:%s" % (path, "a" * 64),
                          path=path, program=AIKIT_UV),
            aegis.finding("HIGH", "process", "Suspicious running process", "d",
                          "process:%s:x:%s" % (AIKIT_UV, "b" * 64),
                          path=path, program=AIKIT_UV),
        ]

    @staticmethod
    def _routing(findings, decisions):
        return {f["fingerprint"]: {"route": aegis.ROUTE_DIGEST, "why": "t",
                                   "decision": d, "verdicts": 3}
                for f, d in zip(findings, decisions)}

    def test_two_blessed_legs_no_longer_manufacture_a_critical(self):
        fs = self._pair()
        self.assertEqual(
            self._run(fs, self._routing(fs, ["tolerated", "tolerated"])), 0)

    def test_a_genuinely_new_execution_still_chains(self):
        """The safety half. A tolerated persistence item is still available as
        the other leg, so an unreviewed process executing from it is still a
        CRITICAL chain — which is the whole reason the rule exists."""
        fs = self._pair()
        self.assertEqual(
            self._run(fs, self._routing(fs, ["tolerated", None])), 1)

    def test_an_unreviewed_pair_still_chains(self):
        fs = self._pair()
        self.assertEqual(self._run(fs, self._routing(fs, [None, None])), 1)

    def test_the_learning_period_never_quiets_a_chain(self):
        """Documented promise: CRITICAL chains and tripped decoys alert
        throughout the learning period."""
        fs = self._pair()
        self.assertEqual(
            self._run(fs, self._routing(fs, ["learning", "learning"])), 1)


if __name__ == "__main__":
    unittest.main()
