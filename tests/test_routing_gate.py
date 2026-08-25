"""The routing gate — one verdict per finding, consulted by BOTH tiers.

The interrupt tier (emit: allowlist, seen-ledger, adoption, notify floor,
confidence) and the incident tier (acquired tolerance, the learning period)
were disjoint state machines coupled by one per-scan boolean. Measured
consequences, each pinned below: acquired tolerance never muted the desktop
notification; the learning period never muted it either; an allowlisted
fingerprint still opened and refreshed incidents and drove reminders; and one
genuine new HIGH marked every incident created that scan as already-notified.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402
from conftest import SUSPICIOUS_TRUST  # noqa: E402

NOW = 1_787_000_000


class GateSandbox(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_gate_")
        state = os.path.join(self.tmp, ".aegis")
        os.makedirs(state)
        self._saved = {}
        for k in ("STATE_DIR", "EVENT_DB", "SEEN", "ALLOWLIST", "FINDINGS_LOG",
                  "BASELINE", "SELFSTATE", "RUN_LOG", "LATEST_JSON"):
            self._saved[k] = getattr(aegis, k)
        aegis.STATE_DIR = state
        aegis.EVENT_DB = os.path.join(state, "aegis.db")
        aegis.SEEN = os.path.join(state, "seen.json")
        aegis.ALLOWLIST = os.path.join(state, "allowlist.json")
        aegis.FINDINGS_LOG = os.path.join(state, "findings.jsonl")
        aegis.BASELINE = os.path.join(state, "baseline.json")
        aegis.SELFSTATE = os.path.join(state, "selfstate.json")
        aegis.RUN_LOG = os.path.join(state, "run.log")
        aegis.LATEST_JSON = os.path.join(state, "latest.json")
        aegis.save_json(aegis.BASELINE, {"learning_until": 0})
        aegis.init_event_store()
        self.notified = []
        self._notify = aegis.notify
        aegis.notify = lambda title, msg: self.notified.append((title, msg))

    def tearDown(self):
        aegis.notify = self._notify
        for k, v in self._saved.items():
            setattr(aegis, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- fixtures ---------------------------------------------------------
    @staticmethod
    def process(comm, sha, **extra):
        return aegis.finding(
            "HIGH", "process", "Suspicious running process", "d",
            "process:%s:%s:%s" % (comm, SUSPICIOUS_TRUST, sha),
            case_fingerprint="process:%s" % aegis._program_subject(comm),
            subject=aegis._subject("process", comm, trust=SUSPICIOUS_TRUST,
                                   content=sha),
            path=comm, **extra)

    def teach(self, comm, n=3):
        """n human benign-positive verdicts on the identity of `comm`."""
        db = aegis._event_connection()
        with db:
            for i in range(n):
                key = "signal:process:%s:%s:%064x" % (comm, SUSPICIOUS_TRUST, i)
                cur = db.execute(
                    "INSERT INTO incidents(kind,correlation_key,title,severity,"
                    "status,created_at,first_seen,last_seen,updated_at) VALUES("
                    "'signal',?,'t','HIGH','FALSE_POSITIVE',?,?,?,?)",
                    (key, NOW - 86400, NOW - 86400, NOW - 86400, NOW - 86400))
                db.execute(
                    "INSERT INTO dismissals(incident_id,correlation_key,"
                    "reason_code,category,dismissed_at) VALUES(?,?,?,?,?)",
                    (cur.lastrowid, key, "benign-positive", "process",
                     NOW - 86400))
        db.close()

    def incidents(self):
        db = aegis._event_connection()
        try:
            return [dict(r) for r in db.execute(
                "SELECT * FROM incidents ORDER BY id").fetchall()]
        finally:
            db.close()

    def scan_path(self, findings, first_run=False):
        """The composition _cmd_scan_locked performs, without the sensors."""
        routing = aegis._route_for_scan(findings, first_run, set(), now=NOW)
        new_high = aegis.emit(findings, first_run, routing=routing)
        aegis.record_security_state(findings, now=NOW,
                                    initially_notified=bool(new_high),
                                    routing=routing)
        return routing, new_high


class TestToleranceReachesTheInterruptTier(GateSandbox):
    def test_a_tolerated_identity_does_not_interrupt(self):
        """The most sophisticated suppression model in the file did not touch
        the tier alert fatigue lives in: a tolerated identity with a new
        content hash interrupted FIRST, then opened pre-closed."""
        self.teach("/opt/tool-1.0/bin/tool")
        f = self.process("/opt/tool-1.1/bin/tool", "f" * 64)
        routing, new_high = self.scan_path([f])
        self.assertEqual(routing[f["fingerprint"]]["why"], "tolerated")
        self.assertEqual(new_high, [])
        self.assertEqual(self.notified, [])
        opened = [i for i in self.incidents()
                  if i["correlation_key"] == "signal:" + f["case_fingerprint"]]
        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0]["status"], "FALSE_POSITIVE")
        self.assertEqual(opened[0]["resolution"], "auto-tolerated")
        # still logged, still in the seen ledger — digest, not erasure
        self.assertIn(f["fingerprint"], aegis.load_json(aegis.SEEN, {}))
        with open(aegis.FINDINGS_LOG, encoding="utf-8") as log:
            self.assertIn(f["fingerprint"], log.read())

    def test_an_untaught_identity_still_interrupts(self):
        f = self.process("/opt/other/bin/x", "e" * 64)
        routing, new_high = self.scan_path([f])
        self.assertEqual(routing[f["fingerprint"]]["route"], "interrupt")
        self.assertEqual(len(new_high), 1)
        self.assertEqual(len(self.notified), 1)

    def test_legacy_callers_without_a_routing_still_tolerate(self):
        """replay and direct callers decide in place with the same function
        over the same memory — one decision procedure, two entry points."""
        self.teach("/opt/tool-1.0/bin/tool")
        f = self.process("/opt/tool-1.1/bin/tool", "d" * 64)
        aegis.record_security_state([f], now=NOW)
        opened = [i for i in self.incidents()
                  if i["correlation_key"] == "signal:" + f["case_fingerprint"]]
        self.assertEqual(opened[0]["resolution"], "auto-tolerated")


class TestLearningPeriodReachesTheInterruptTier(GateSandbox):
    def test_learning_mutes_a_new_high_but_never_a_critical(self):
        aegis.save_json(aegis.BASELINE, {"learning_until": NOW + 86400})
        hi = self.process("/opt/new/bin/x", "a" * 64)
        crit = aegis.finding("CRITICAL", "decoy", "Decoy read", "d",
                             "decoy:/home/x/.aws/credentials")
        routing, new_high = self.scan_path([hi, crit])
        self.assertEqual(routing[hi["fingerprint"]]["why"], "learning")
        self.assertEqual(routing[crit["fingerprint"]]["route"], "interrupt")
        self.assertEqual([f["fingerprint"] for f in new_high],
                         [crit["fingerprint"]])
        by_key = {i["correlation_key"]: i for i in self.incidents()}
        self.assertEqual(by_key["signal:" + hi["case_fingerprint"]]["resolution"],
                         "learning-period")
        self.assertEqual(by_key["signal:" + crit["fingerprint"]]["status"],
                         "OPEN")


class TestAllowlistReachesTheIncidentTier(GateSandbox):
    def test_an_allowlisted_fingerprint_closes_its_incident(self):
        """emit skipped an allowlisted fingerprint while every finding still
        flowed into the incident tier untouched — so it kept opening,
        refreshing, and reminding."""
        f = self.process("/opt/ci/bin/runner", "b" * 64)
        self.scan_path([f])                      # opens the incident
        before = self.incidents()
        self.assertEqual(before[0]["status"], "OPEN")
        aegis.save_json(aegis.ALLOWLIST, [f["fingerprint"]])
        self.notified.clear()
        routing, new_high = self.scan_path([f])
        self.assertEqual(routing[f["fingerprint"]]["route"], "silent")
        self.assertEqual(new_high, [])
        after = self.incidents()
        self.assertEqual(len(after), 1, "must not open a second case")
        self.assertEqual(after[0]["status"], "FALSE_POSITIVE")
        self.assertEqual(after[0]["resolution"], "allowlisted")
        self.assertIsNone(after[0]["next_reminder_at"])
        self.assertEqual(aegis.claim_due_incident_reminders(NOW + 7200), [])
        # writes no dismissal row: an allowlist entry has no typed reason
        db = aegis._event_connection()
        n = db.execute("SELECT COUNT(*) FROM dismissals").fetchone()[0]
        db.close()
        self.assertEqual(n, 0)


class TestNotifiedIsPerFinding(GateSandbox):
    def test_a_digest_routed_signal_still_gets_its_reminder(self):
        """initially_notified was bool(new_high) for the whole scan: one
        genuine new HIGH marked every incident created that scan as already
        notified, so a low-confidence HIGH routed to the digest never got the
        reminder that was its only path to a human."""
        loud = self.process("/opt/a/bin/a", "1" * 64)
        quiet = self.process("/opt/b/bin/b", "2" * 64, confidence="low")
        routing, new_high = self.scan_path([loud, quiet])
        self.assertEqual([f["fingerprint"] for f in new_high],
                         [loud["fingerprint"]])
        by_key = {i["correlation_key"]: i for i in self.incidents()}
        self.assertIsNotNone(
            by_key["signal:" + loud["case_fingerprint"]]["last_notified_at"])
        self.assertIsNone(
            by_key["signal:" + quiet["case_fingerprint"]]["last_notified_at"])
        # Reminders are scheduled for every OPEN incident; the difference the
        # gate makes is that the quiet one is not falsely recorded as told.
        due = aegis.claim_due_incident_reminders(NOW + 7200)
        self.assertIn("signal:" + quiet["case_fingerprint"],
                      [i["correlation_key"] for i in due])


class TestRoutePrecedence(GateSandbox):
    def test_the_order_is_written_down(self):
        f = self.process("/opt/x/bin/x", "3" * 64)
        fp = f["fingerprint"]
        self.assertEqual(aegis.route_findings([f])[fp]["why"], "new")
        low = dict(f, confidence="low")
        self.assertEqual(aegis.route_findings([low])[fp]["why"],
                         "low-confidence")
        med = dict(f, severity="MEDIUM")
        self.assertEqual(aegis.route_findings([med])[fp]["why"], "below-floor")
        self.assertEqual(
            aegis.route_findings([f], adopt={"process"})[fp]["why"], "adopted")
        aegis.save_json(aegis.SEEN, {fp: "t"})
        self.assertEqual(aegis.route_findings([f])[fp]["route"], "seen")
        aegis.save_json(aegis.ALLOWLIST, [fp])
        self.assertEqual(aegis.route_findings([f])[fp]["route"], "silent")

    def test_attack_defined_evidence_is_never_quieted(self):
        memory = ({}, {}, frozenset(), True)      # learning period ON
        for pre in ("decoy:", "latch:", "canary:"):
            f = aegis.finding("HIGH", "persistence", "t", "d", pre + "x")
            self.assertEqual(aegis._signal_decision(f, memory), (None, 0), pre)
        crit = aegis.finding("CRITICAL", "process", "t", "d", "process:x:y:z")
        self.assertEqual(aegis._signal_decision(crit, memory), (None, 0))


if __name__ == "__main__":
    unittest.main()
