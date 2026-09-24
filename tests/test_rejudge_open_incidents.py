"""Current code re-judges what it already opened.

An incident opened under old code stays OPEN after the code that opened it is
fixed, because nothing asks again unless the same subject is re-observed: it
waits out the seven-day age-out. On the reference Mac, 2026-09-23: #527 was a
Spotify risk case built from listener findings recorded `unsigned` while the
codesign probe was not answering (Spotify is Developer ID), and #537 a staging
plugin-container the current code grades MEDIUM on its build-output rung.

`backtest replay --reobserve` already re-derives recorded evidence with the
current code. _rejudge_open_incidents uses the same `_reobserve` path to heal:
an incident closes only when EVERY finding it holds re-derives (none replayed
as recorded, none gone) and the current code would no longer raise it — each
finding dropped or routed below the interrupt tier (signal), the pile-up
below the threshold (risk), the chain no longer formed (correlation). It is a
machine exit like re-grade and re-verify: FALSE_POSITIVE with a resolution
that says why, no dismissals row, reopened by new evidence.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aegis  # noqa: E402
from conftest import SUSPICIOUS_TRUST  # noqa: E402
from test_backtest_replay import NOW, ReplaySandbox  # noqa: E402


class RejudgeSandbox(ReplaySandbox):
    """A sandboxed store holding incidents opened by findings about binaries
    in the sandbox. The process gate is held open and the rungs ahead of the
    receipt are pinned: those are platform-shaped and not under test. Whether
    the binary now has a package receipt is the one thing a test flips."""

    def setUp(self):
        super().setUp()
        self.receipt = None
        self.stub("classify_signature", lambda path: {
            "trust": SUSPICIOUS_TRUST, "team": None, "authority": None})
        self.stub("_exec_alert", lambda path, trust: (
            "HIGH", "running from user-writable path"))
        self.stub("_package_receipt", lambda path: self.receipt)
        self.stub("_build_output_rung", lambda path: None)
        self.bin = self.binary("tool")

    def binary(self, name):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as f:
            f.write(name.encode() + b"\x00" * 16)
        return path

    def db(self):
        return aegis._event_connection()

    def record(self, findings, kind="signal", key=None, created=NOW - 86400,
               severity="HIGH"):
        """An OPEN incident holding `findings` as evidence."""
        db = self.db()
        with db:
            ids = [self.event(db, f, created) for f in findings]
            key = key or "signal:" + (findings[0].get("case_fingerprint")
                                      or findings[0]["fingerprint"])
            iid = db.execute(
                "INSERT INTO incidents(kind,correlation_key,title,severity,"
                "status,created_at,first_seen,last_seen,updated_at) "
                "VALUES(?,?,'t',?,'OPEN',?,?,?,?)",
                (kind, key, severity, created, created, created,
                 created)).lastrowid
            for ev in ids:
                db.execute("INSERT INTO incident_events(incident_id,event_id) "
                           "VALUES(?,?)", (iid, ev))
        db.close()
        return iid

    def rejudge(self, now=NOW):
        db = self.db()
        try:
            with db:
                return aegis._rejudge_open_incidents(db, now)
        finally:
            db.close()

    def status(self, iid):
        db = self.db()
        try:
            row = db.execute("SELECT status, resolution FROM incidents "
                             "WHERE id=?", (iid,)).fetchone()
            return row["status"], row["resolution"]
        finally:
            db.close()

    def dismissals(self):
        db = self.db()
        try:
            return db.execute("SELECT COUNT(*) FROM dismissals").fetchone()[0]
        finally:
            db.close()


class ASignalIncidentCurrentCodeWouldNotRaise(RejudgeSandbox):
    def test_closes_when_every_finding_re_derives_below_the_interrupt_tier(self):
        """Recorded HIGH with no rung. The binary now has a package receipt:
        the grader demotes it and the provenance gate routes it to the
        digest, so the current code would not have raised this."""
        iid = self.record([self.process(self.bin, "a" * 64)])
        self.receipt = "brew:tool"
        self.assertEqual(1, self.rejudge())
        status, resolution = self.status(iid)
        self.assertEqual("FALSE_POSITIVE", status)
        self.assertTrue(resolution.startswith("re-judged by current code"),
                        resolution)
        self.assertIn("tool", resolution)
        self.assertIn("package-managed", resolution)
        self.assertIn("reopens on new evidence", resolution)
        self.assertIn("logic %d" % aegis._REJUDGE_LOGIC_VERSION, resolution)
        self.assertEqual(0, self.dismissals())

    def test_stays_while_the_current_code_still_interrupts(self):
        iid = self.record([self.process(self.bin, "a" * 64)])
        self.assertEqual(0, self.rejudge())
        self.assertEqual("OPEN", self.status(iid)[0])

    def test_stays_when_any_finding_is_replayed_as_recorded(self):
        """A subject gone from disk cannot be asked again, so nothing says
        the current code would not raise it: conservative, it stays."""
        gone = os.path.join(self.tmp, "gone-tool")
        iid = self.record([self.process(self.bin, "a" * 64),
                           self.process(gone, "b" * 64)])
        self.receipt = "brew:tool"
        self.assertEqual(0, self.rejudge())
        self.assertEqual("OPEN", self.status(iid)[0])

    def test_stays_on_critical_evidence(self):
        f = dict(self.process(self.bin, "a" * 64), severity="CRITICAL")
        iid = self.record([f], severity="CRITICAL")
        self.receipt = "brew:tool"
        self.rejudge()
        self.assertEqual("OPEN", self.status(iid)[0])

    def test_stays_on_attack_defined_evidence(self):
        f = dict(self.process(self.bin, "a" * 64), attack_defined=True)
        iid = self.record([f])
        self.receipt = "brew:tool"
        self.rejudge()
        self.assertEqual("OPEN", self.status(iid)[0])

    def test_stays_on_a_never_tolerate_fingerprint(self):
        f = aegis.finding("HIGH", "decoy", "A process read a decoy", "d",
                          "decoy:read:%s" % self.bin, path=self.bin)
        iid = self.record([f])
        self.receipt = "brew:tool"
        self.rejudge()
        self.assertEqual("OPEN", self.status(iid)[0])

    def test_stays_when_opened_by_this_scan(self):
        iid = self.record([self.process(self.bin, "a" * 64)], created=NOW)
        self.receipt = "brew:tool"
        self.assertEqual(0, self.rejudge())
        self.assertEqual("OPEN", self.status(iid)[0])

    def test_a_new_interrupting_finding_reopens_the_case(self):
        f = self.process(self.bin, "a" * 64)
        iid = self.record([f])
        self.receipt = "brew:tool"
        self.assertEqual(1, self.rejudge())
        # The receipt is gone again and the binary changed: new evidence on
        # the same case, and it interrupts.
        self.receipt = None
        fresh = self.process(self.bin, "c" * 64)
        fresh["case_fingerprint"] = f["case_fingerprint"]
        aegis.record_security_state([fresh], now=NOW + 60)
        db = self.db()
        try:
            active = db.execute(
                "SELECT id FROM incidents WHERE correlation_key=? AND status "
                "IN ('OPEN','ACK')", ("signal:" + f["case_fingerprint"],)
            ).fetchall()
        finally:
            db.close()
        self.assertEqual(1, len(active))
        self.assertEqual("FALSE_POSITIVE", self.status(iid)[0])


class ARiskIncidentIsRescored(RejudgeSandbox):
    """Three sensors on one binary, recorded with no rung, pile past the
    threshold. Re-derived, the pile is scored again with the current weights
    (a vouched rung weighs nothing)."""

    def pile(self):
        sha = "d" * 64
        findings = [
            self.process(self.bin, sha),
            aegis.finding(
                "HIGH", "net-beacon",
                "Persistent outbound connection (beacon shape)", "d",
                "beacon:%s:203.0.113.7:443" % self.bin, path=self.bin,
                program=self.bin, trust=SUSPICIOUS_TRUST,
                remote="203.0.113.7", port=443),
            aegis.finding(
                "MEDIUM", "net-listener", "New network listener", "d",
                "listener:%s:4444" % self.bin, path=self.bin,
                program=self.bin, trust=SUSPICIOUS_TRUST, port=4444),
        ]
        db = self.db()
        with db:
            ids = [self.event(db, f, NOW - 86400) for f in findings]
            aegis._accumulate_risk(db, NOW - 86400, set(ids))
            row = db.execute("SELECT id FROM incidents WHERE kind='risk'"
                             ).fetchone()
        db.close()
        self.assertIsNotNone(row, "the pile did not open a risk incident")
        return row[0]

    def test_closes_once_it_no_longer_crosses_the_threshold(self):
        iid = self.pile()
        self.receipt = "brew:tool"
        self.assertEqual(1, self.rejudge())
        status, resolution = self.status(iid)
        self.assertEqual("FALSE_POSITIVE", status)
        self.assertIn("threshold", resolution)
        self.assertEqual(0, self.dismissals())

    def test_stays_while_it_still_crosses(self):
        iid = self.pile()
        self.assertEqual(0, self.rejudge())
        self.assertEqual("OPEN", self.status(iid)[0])


class AChainIsAskedWhetherTheJoinRulesWouldFormIt(RejudgeSandbox):
    """Two legs on one binary, recorded with no rung. Once custody explains
    every leg, the current join rules would not form the chain
    (_unjoinable_chain_resolution, the rule the chain-leg migration uses)."""

    def chain(self):
        legs = [self.process(self.bin, "a" * 64),
                aegis.finding(
                    "HIGH", "net-beacon",
                    "Persistent outbound connection (beacon shape)", "d",
                    "beacon:%s:203.0.113.7:443" % self.bin, path=self.bin,
                    program=self.bin, trust=SUSPICIOUS_TRUST,
                    remote="203.0.113.7", port=443)]
        entity = aegis.hashlib.sha256(aegis._canon_entity_path(
            self.bin).encode("utf-8", "replace")).hexdigest()[:16]
        return self.record(legs, kind="correlation",
                           key="chain:persistence-execution:%s" % entity)

    def test_closes_once_every_leg_is_explained(self):
        iid = self.chain()
        self.receipt = "brew:tool"
        self.assertEqual(1, self.rejudge())
        status, resolution = self.status(iid)
        self.assertEqual("FALSE_POSITIVE", status)
        self.assertIn("provenance-explained", resolution)

    def test_stays_while_a_leg_is_unexplained(self):
        iid = self.chain()
        self.assertEqual(0, self.rejudge())
        self.assertEqual("OPEN", self.status(iid)[0])


class ItRunsHourlyAndOnANewLogic(RejudgeSandbox):
    def test_throttled_to_once_an_hour_unless_the_logic_changed(self):
        first = self.record([self.process(self.bin, "a" * 64)])
        self.receipt = "brew:tool"
        self.assertEqual(1, self.rejudge(NOW))
        self.assertEqual("FALSE_POSITIVE", self.status(first)[0])
        second = self.record([self.process(self.bin, "e" * 64)])
        self.assertIsNone(self.rejudge(NOW + 60))            # throttled
        self.assertEqual("OPEN", self.status(second)[0])
        self.stub("_REJUDGE_LOGIC_VERSION",
                  aegis._REJUDGE_LOGIC_VERSION + 1)
        self.assertEqual(1, self.rejudge(NOW + 120))         # new logic
        self.assertEqual("FALSE_POSITIVE", self.status(second)[0])
        third = self.record([self.process(self.bin, "f" * 64)])
        self.assertIsNone(self.rejudge(NOW + 180))
        self.assertEqual(1, self.rejudge(NOW + 120 + 3600))  # an hour on
        self.assertEqual("FALSE_POSITIVE", self.status(third)[0])

    def test_a_run_is_capped_and_says_what_it_left(self):
        self.stub("_REJUDGE_MAX_INCIDENTS", 1)
        ids = [self.record([self.process(self.bin, c * 64)]) for c in "ab"]
        self.receipt = "brew:tool"
        self.assertEqual(1, self.rejudge(NOW))
        self.assertEqual(["FALSE_POSITIVE", "OPEN"],
                         [self.status(i)[0] for i in ids])
        with open(aegis.RUN_LOG, encoding="utf-8") as f:
            log = f.read()
        self.assertIn("re-judge", log)
        self.assertIn("1 left for the next run", log)
        # The next run picks up where this one stopped.
        self.assertEqual(1, self.rejudge(NOW + 3600))
        self.assertEqual("FALSE_POSITIVE", self.status(ids[1])[0])


class TheScanRunsIt(RejudgeSandbox):
    def test_record_security_state_closes_what_the_current_code_would_not_raise(self):
        iid = self.record([self.process(self.bin, "a" * 64)])
        self.receipt = "brew:tool"
        aegis.record_security_state([], now=NOW)
        self.assertEqual("FALSE_POSITIVE", self.status(iid)[0])
        with open(aegis.RUN_LOG, encoding="utf-8") as f:
            self.assertIn("re-judged", f.read())

    def test_it_writes_no_custody_ledger_row(self):
        """Re-judging asks the ladder; it must not teach it."""
        self.record([self.process(self.bin, "a" * 64)])
        self.receipt = "brew:tool"
        self.rejudge()
        self.assertFalse(os.path.exists(aegis.CUSTODY_FILE))


if __name__ == "__main__":
    unittest.main()
