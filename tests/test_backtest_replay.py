"""`backtest replay` — the ground-truth harness.

Six false-alarm batches were each measured by silence: "the queue got
shorter", which is also exactly what broken detection looks like. The store
already holds the answer key — every finding the sensors recorded, and every
incident the operator closed as noise — and nothing ever re-ran the one
through the current pipeline and scored it against the other.

These tests pin the harness itself, on a synthetic store small enough to
reason about by hand:

  A  a noise-labelled incident whose evidence the current code still
     interrupts on                                   -> re-opens
  B  a noise-labelled incident whose identity the operator has taught
     (three benign-positive verdicts)                -> does not re-open
  C  an attack-defined finding no incident holds     -> a new interrupt

and the properties a measurement must have to be believed: it never writes
the store it measures, it treats the learning period as OFF, it asserts its
own counts against the store (a failed assertion printed at the TOP), and a
classifier change is visible to it under --reobserve.
"""
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

NOW = 1_790_000_000


class ReplaySandbox(unittest.TestCase):
    """A sandboxed LIVE store, seeded by hand. The replay reads it the way it
    reads ~/.aegis/aegis.db on the operator's machine."""

    PATHS = ("STATE_DIR", "EVENT_DB", "SEEN", "ALLOWLIST", "FINDINGS_LOG",
             "BASELINE", "SELFSTATE", "RUN_LOG", "LATEST_JSON", "SIGCACHE",
             "CUSTODY_FILE", "VOUCH_FILE", "VOUCH_SIGNERS", "INTENT_FILE",
             "ACTION_LOG", "ASSAY_FILE")

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_replay_")
        self.state = os.path.join(self.tmp, ".aegis")
        os.makedirs(self.state)
        self._saved = {k: getattr(aegis, k) for k in self.PATHS}
        for k in self.PATHS:
            if k == "STATE_DIR":
                aegis.STATE_DIR = self.state
            elif k == "EVENT_DB":
                aegis.EVENT_DB = os.path.join(self.state, "aegis.db")
            else:
                setattr(aegis, k, os.path.join(
                    self.state, os.path.basename(self._saved[k])))
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

    # -- fixtures ---------------------------------------------------------
    @staticmethod
    def process(comm, sha, **extra):
        return aegis.finding(
            "HIGH", "process", "Suspicious running process", "d",
            "process:%s:%s:%s" % (comm, SUSPICIOUS_TRUST, sha),
            case_fingerprint="process:%s" % aegis._program_subject(comm),
            subject=aegis._subject("process", comm, trust=SUSPICIOUS_TRUST,
                                   content=sha),
            path=comm, trust=SUSPICIOUS_TRUST, **extra)

    @staticmethod
    def event(db, f, at):
        return db.execute(
            "INSERT INTO events(occurred_at,observed_at,source,event_type,"
            "data_json) VALUES(?,?,?,?,?)",
            (at, at, f["category"], "observation.finding",
             json.dumps(f, sort_keys=True))).lastrowid

    @staticmethod
    def incident(db, key, status, resolution, evidence, severity="HIGH",
                 dismissed=None):
        at = NOW - 86400
        iid = db.execute(
            "INSERT INTO incidents(kind,correlation_key,title,severity,status,"
            "created_at,first_seen,last_seen,updated_at,resolution) "
            "VALUES('signal',?,'t',?,?,?,?,?,?,?)",
            (key, severity, status, at, at, at, at, resolution)).lastrowid
        for ev in evidence:
            db.execute("INSERT INTO incident_events(incident_id,event_id) "
                       "VALUES(?,?)", (iid, ev))
        if dismissed:
            db.execute(
                "INSERT INTO dismissals(incident_id,correlation_key,"
                "reason_code,category,dismissed_at) VALUES(?,?,?,?,?)",
                (iid, key, dismissed, "process", at))
        return iid

    def seed(self):
        """A, B and C from the module docstring. A and C share one scan (one
        observed_at), B is the next scan."""
        self.comm_a = "/opt/replay-a/tool"
        self.comm_b = "/opt/replay-b/tool"
        db = aegis._event_connection()
        with db:
            a = self.process(self.comm_a, "a" * 64)
            ev_a = self.event(db, a, NOW - 7200)
            self.inc_a = self.incident(
                db, "signal:" + a["case_fingerprint"], "FALSE_POSITIVE",
                "benign-positive", [ev_a], dismissed="benign-positive")
            c = aegis.finding(
                "CRITICAL", "decoy", "A process is reading a credential decoy",
                "d", "decoy:read:/opt/replay-decoy", path="/opt/replay-decoy")
            self.event(db, c, NOW - 7200)
            b = self.process(self.comm_b, "b" * 64)
            ev_b = self.event(db, b, NOW - 3600)
            # B's identity carries three human benign-positive verdicts, the
            # acquired-tolerance floor; only the first holds in-window evidence.
            for i in range(3):
                key = "signal:process:%s:%s:%064x" % (
                    self.comm_b, SUSPICIOUS_TRUST, i)
                iid = self.incident(db, key, "FALSE_POSITIVE",
                                    "benign-positive",
                                    [ev_b] if i == 0 else [],
                                    dismissed="benign-positive")
                if i == 0:
                    self.inc_b = iid
        db.close()

    def replay(self, **kw):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = aegis.cmd_backtest_replay(now=NOW, **kw)
        return rc, out.getvalue()


class TheCorpusIsScoredAgainstTheLabels(ReplaySandbox):
    def test_noise_that_still_interrupts_is_named_and_counted(self):
        self.seed()
        rc, out = self.replay()
        self.assertEqual(0, rc, out)
        self.assertIn("noise re-opened: 1 of 2", out)
        self.assertIn("new interrupts from corpus: 1", out)
        # ...and the new one is named, so a later step can say what it was.
        self.assertRegex(out, r"signal\s+CRITICAL\s+A process is reading a "
                              r"credential decoy")
        # A is listed by id, with the finding's title and path; B is not.
        self.assertRegex(out, r"#%d\b.*Suspicious running process.*%s"
                         % (self.inc_a, self.comm_a))
        self.assertNotRegex(out, r"#%d\b" % self.inc_b)

    def test_per_category_counts_route_each_finding_once(self):
        self.seed()
        r = aegis._backtest_replay(now=NOW)
        self.assertEqual(3, r["loaded"])
        self.assertEqual(2, r["batches"])
        self.assertEqual({"interrupt": 1, "digest": 1},
                         {k: v for k, v in r["routes"]["process"].items() if v})
        self.assertEqual({"interrupt": 1},
                         {k: v for k, v in r["routes"]["decoy"].items() if v})
        self.assertEqual([self.inc_a], sorted(r["reopened"]))
        self.assertEqual({self.inc_a, self.inc_b}, set(r["noise"]))

    def test_the_learning_period_is_off_for_a_replay(self):
        """A live store inside its learning window closes every non-attack
        signal as `learning`, which would make the baseline read zero for a
        reason that has nothing to do with the code under test."""
        self.seed()
        aegis.save_json(aegis.BASELINE, {"learning_until": NOW + 30 * 86400})
        self.assertTrue(aegis._in_learning_period(NOW))
        _rc, out = self.replay()
        self.assertIn("noise re-opened: 1 of 2", out)

    def test_an_empty_window_says_so(self):
        _rc, out = self.replay()
        self.assertIn("noise re-opened: 0 of 0", out)
        self.assertIn("0 recorded finding", out)


class AMeasurementNeverWritesWhatItMeasures(ReplaySandbox):
    def test_the_live_store_bytes_do_not_change(self):
        self.seed()

        def digest():
            with open(aegis.EVENT_DB, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()

        before = digest()
        self.replay(reobserve=True)
        self.assertEqual(before, digest())
        for ledger in (aegis.SEEN, aegis.CUSTODY_FILE, aegis.FINDINGS_LOG,
                       aegis.SIGCACHE):
            self.assertFalse(os.path.exists(ledger), ledger)

    def test_a_rung_awarded_during_reobserve_is_not_recorded(self):
        """_grade_binary appends every rung it awards to the custody ledger,
        which later grading reads back. Re-observing history must not teach
        the live ladder anything."""
        comm = os.path.join(self.tmp, "replay-pkg-bin")
        with open(comm, "wb") as f:
            f.write(b"\x00" * 16)
        db = aegis._event_connection()
        with db:
            self.event(db, self.process(comm, "e" * 64), NOW - 3600)
        db.close()
        self.stub("classify_signature", lambda path: {
            "trust": SUSPICIOUS_TRUST, "team": None, "authority": None})
        # The gate is not under test here and is platform-shaped (a temp dir
        # is risky by a different rule on each body): hold it open.
        self.stub("_exec_alert", lambda path, trust: (
            "HIGH", "running from user-writable path"))
        self.stub("_package_receipt", lambda path: "brew:replay-pkg")
        r = aegis._backtest_replay(now=NOW, reobserve=True)
        self.assertEqual(1, r["reobserve"]["reobserved"])
        self.assertEqual(1, r["reobserve"]["custody_changed"])
        self.assertFalse(os.path.exists(aegis.CUSTODY_FILE))


class TheSummaryAssertsItselfAgainstTheStore(ReplaySandbox):
    def test_a_clean_run_says_what_it_verified(self):
        self.seed()
        _rc, out = self.replay()
        self.assertNotIn("SELF-CHECK FAILED", out)
        self.assertIn("_Self-check:", out)

    def test_a_dropped_row_is_reported_at_the_top(self):
        """Rule 17: the loader losing a row must be the FIRST thing read."""
        self.seed()
        real = aegis._replay_load_corpus

        def lossy(live, since):
            rows = real(live, since)
            return rows[1:]

        self.stub("_replay_load_corpus", lossy)
        _rc, out = self.replay()
        head = "\n".join(out.splitlines()[:3])
        self.assertIn("SELF-CHECK FAILED", head)
        self.assertIn("2 finding row(s) loaded but the store holds 3", head)


class ReobserveMakesAClassifierFixScoreable(ReplaySandbox):
    def test_a_trust_verdict_that_changed_is_patched_before_routing(self):
        """A binary still on disk is asked again. Here the classifier now
        vouches for it: the process sensor's own gate decides whether it
        would be emitted at all, and the noise it caused no longer re-opens
        (on a body whose gate keys on the signature)."""
        comm = os.path.join(self.tmp, "replay-bin")
        with open(comm, "wb") as f:
            f.write(b"\x00" * 16)
        db = aegis._event_connection()
        with db:
            d = self.process(comm, "d" * 64)
            ev = self.event(db, d, NOW - 3600)
            inc = self.incident(db, "signal:" + d["case_fingerprint"],
                                "FALSE_POSITIVE", "false-positive", [ev],
                                dismissed="false-positive")
        db.close()

        _rc, plain = self.replay()
        self.assertIn("noise re-opened: 1 of 1", plain)

        self.stub("classify_signature", lambda path: {
            "trust": PUBLISHER_TRUST, "team": None, "authority": None})
        r = aegis._backtest_replay(now=NOW, reobserve=True)
        stats = r["reobserve"]
        self.assertEqual(1, stats["reobserved"])
        self.assertEqual(1, stats["trust_changed"])
        gate_closed = aegis._exec_alert(comm, PUBLISHER_TRUST) is None
        self.assertEqual(1 if gate_closed else 0, stats["no_longer_emitted"])
        self.assertEqual([] if gate_closed else [inc], sorted(r["reopened"]))

    def test_a_subject_gone_from_disk_is_counted_not_guessed(self):
        self.seed()
        r = aegis._backtest_replay(now=NOW, reobserve=True)
        self.assertEqual(0, r["reobserve"]["reobserved"])
        self.assertEqual(2, r["reobserve"]["gone"])


class AssayRecallRunsThroughTheSameGate(ReplaySandbox):
    def test_every_lane_is_accounted_for(self):
        r = aegis._backtest_replay(now=NOW)
        lanes = {row["lane"]: row for row in r["assay"]}
        self.assertEqual({lid for lid, _d, _f in aegis._assay_lanes()},
                         set(lanes))
        # The one lane that writes live state is refused, and says why.
        self.assertEqual("not run", lanes["quarantine-roundtrip"]["status"])
        # A CRITICAL attack finding reaches the interrupt tier.
        self.assertEqual("interrupt", lanes["session-theft"]["status"])
        _rc, out = self.replay()
        n = sum(1 for row in r["assay"] if row["status"] == "interrupt")
        self.assertIn("assay recall: %d/%d interrupt" % (n, len(lanes)), out)


if __name__ == "__main__":
    unittest.main()
