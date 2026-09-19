#!/usr/bin/env python3
"""Custody survives the operator's own pipeline — and the boundaries it crosses.

Live batch, 2026-09-19: 49 open incidents, about ten facts. Roughly thirty of
them were one program's build seen at several stops on its way out of the tree:

    build-output   ~/.ai/worktrees/<wt>/app/staging/App.app/.../mainexe
    None           ~/src/<project>/release/App.app/.../mainexe
    None           ~/Downloads/App.app/.../mainexe
    None           /Applications/App.app/.../mainexe

One sha256 at every stop. Aegis had ALREADY proven they were the same bytes —
that hash is the incident key for #501, #417, #420 and #421 — graded them once,
and opened three more ungraded HIGH incidents about the file it had just
explained. Every rung in the ladder asks a question about a DIRECTORY
(`_build_output_rung` asks the repo that owns it, `_package_receipt` asks the
installer database for the path, `_vouch_covers` matches path and endpoint), so
all three go blind the moment a build artifact is copied or moved.

Three more boundaries lost the same way, each its own class below:

  * the hot-dir sensor consulted no rung AT ALL, grading solely on the
    quarantine xattr that a locally-built binary never carries;
  * `benign-positive` on a CHAIN incident promoted nothing into the baseline,
    because the acceptance path only understood `signal:` keys — two CRITICAL
    chains had accumulated 1,065 and 770 evidence events with no verdict the
    operator could give that would end either;
  * two chain rules reading one event produced two CRITICALs (#511 and #517,
    same entity key, one's evidence a subset of the other's).

Every class pins one behaviour AND the safety property that stops it becoming
a blind spot — the discipline of test_noise_reduction.py and
test_provenance_tier.py, for the same reason: everything here quiets something.
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402
from test_provenance_tier import _baseline_shaped, _job  # noqa: E402


class CarrySandbox(unittest.TestCase):
    """Isolate the ledger and the in-process memos it reads through."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_carry_")
        self.state = os.path.join(self.tmp, ".aegis")
        os.makedirs(self.state)
        self._saved = {}
        for k, v in (("STATE_DIR", self.state),
                     ("CUSTODY_FILE", os.path.join(self.state,
                                                   "custody.jsonl")),
                     ("HMAC_KEY_FILE", os.path.join(self.state, "hmac.key")),
                     ("RUN_LOG", os.path.join(self.state, "run.log"))):
            self._saved[k] = getattr(aegis, k)
            setattr(aegis, k, v)
        aegis._CUSTODY_CARRY_CACHE.clear()
        aegis._GRADED_SHA_CACHE.clear()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(aegis, k, v)
        aegis._CUSTODY_CARRY_CACHE.clear()
        aegis._GRADED_SHA_CACHE.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _binary(self, name, body=b"MACH-O-ish payload " * 64):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as f:
            f.write(body)
        return path


class CustodyFollowsTheBytes(CarrySandbox):
    """A rung earned at one path is inherited by the same bytes at any other."""

    def test_a_copy_of_graded_bytes_is_graded(self):
        built = self._binary("zotero")
        sha = aegis.sha256(built)
        moved = self._binary("moved_zotero")   # identical content
        self.assertEqual(aegis.sha256(moved), sha)

        self.assertEqual(aegis._grade_binary("HIGH", moved, sha=sha)[:2],
                         ("HIGH", None),
                         "bytes nothing has ever graded must stay ungraded")

        aegis._custody_remember(sha, "build-output", built)
        sev, rung, note = aegis._grade_binary("HIGH", moved, sha=sha)
        self.assertEqual(rung, "copy-of-graded")
        self.assertEqual(sev, "MEDIUM", "one step down, never straight to LOW")
        self.assertIn("build-output", note,
                      "the note must name the rung that was actually earned")
        self.assertIn(built, note,
                      "and where, or the operator cannot check the claim")

    def test_one_changed_byte_carries_nothing(self):
        built = self._binary("zotero")
        aegis._custody_remember(aegis.sha256(built), "build-output", built)
        mutated = self._binary("mutated", b"MACH-O-ish payload " * 64 + b"!")
        self.assertEqual(
            aegis._grade_binary("HIGH", mutated,
                                sha=aegis.sha256(mutated))[:2],
            ("HIGH", None),
            "this grades COPIES, never versions — a modified binary is a "
            "different sha and inherits nothing")

    def test_carrying_never_re_confers_the_rung_it_found(self):
        """The property that stops a vouch widening.

        A vouch binds to one path and, for outbound, one endpoint. Carrying it
        as ITSELF would silently grant 'may live anywhere, may talk to
        anywhere', so carrying only ever yields the weakest rung there is."""
        built = self._binary("vouched")
        sha = aegis.sha256(built)
        aegis._custody_remember(sha, "operator-vouched", built)
        copy = self._binary("copy_of_vouched")
        sev, rung, _note = aegis._grade_binary("HIGH", copy, sha=sha)
        self.assertEqual(rung, "copy-of-graded")
        self.assertEqual(sev, "MEDIUM",
                         "a carried vouch must not deliver the vouch's LOW")

    def test_attack_defined_evidence_is_never_carried_down(self):
        built = self._binary("zotero")
        sha = aegis.sha256(built)
        aegis._custody_remember(sha, "build-output", built)
        copy = self._binary("copy")
        self.assertEqual(
            aegis._grade_binary("HIGH", copy, attack_defined=True,
                                sha=sha)[:2],
            ("HIGH", None),
            "a timestomped or otherwise attack-defined finding keeps its "
            "severity whoever built the file")

    def test_a_forged_ledger_line_does_not_verify(self):
        aegis._custody_remember(aegis.sha256(self._binary("real")),
                                "build-output", "/x")
        with open(aegis.CUSTODY_FILE, "a", encoding="utf-8") as f:
            f.write('{"ts":"2099-01-01T00:00:00","sha256":"deadbeef",'
                    '"rung":"operator-vouched","path":"/evil","mac":"00"}\n')
        aegis._CUSTODY_CARRY_CACHE.clear()
        self.assertIsNone(aegis._custody_carried("deadbeef"),
                          "a record whose MAC does not verify is a non-match, "
                          "never a grading")

    def test_a_stale_record_ages_out_of_grading(self):
        built = self._binary("old")
        sha = aegis.sha256(built)
        aegis._custody_remember(sha, "build-output", built)
        old = aegis._epoch() - (aegis._CUSTODY_MAX_AGE_DAYS + 1) * 86400
        stale_ts = aegis.datetime.fromtimestamp(old).isoformat()
        rec = {"ts": stale_ts, "sha256": sha, "rung": "build-output",
               "path": built}
        rec["mac"] = aegis._custody_mac(stale_ts, sha, "build-output", built)
        with open(aegis.CUSTODY_FILE, "w", encoding="utf-8") as f:
            f.write(aegis.json.dumps(rec) + "\n")
        aegis._CUSTODY_CARRY_CACHE.clear()
        self.assertIsNone(aegis._custody_carried(sha),
                          "past the retention window a record stops grading")

    def test_a_carried_rung_never_satisfies_an_endpoint_scoped_vouch(self):
        """The network sensors pass an endpoint, and a vouch must list that
        exact endpoint or say nothing — that is what stops an identity vouch
        wildcarding an exfil destination. Carrying must not become a way
        around it: the carried rung is the weak one, which is endpoint-blind
        exactly as `build-output` already is at the build path, and it can
        never deliver the vouch's LOW to an unvouched endpoint."""
        built = self._binary("beaconer")
        sha = aegis.sha256(built)
        aegis._custody_remember(sha, "operator-vouched", built)
        copy = self._binary("beaconer_copy")
        sev, rung, _note = aegis._grade_binary(
            "HIGH", copy, endpoint="203.0.113.9:443", sha=sha)
        self.assertEqual(rung, "copy-of-graded",
                         "not the vouch, whatever the vouch covered")
        self.assertEqual(sev, "MEDIUM",
                         "still in the report, still accumulating risk — a "
                         "beacon is never graded away")

    def test_a_carried_rung_is_not_itself_carriable(self):
        self.assertFalse(aegis._custody_remember("a" * 64, "copy-of-graded",
                                                 "/x"),
                         "carrying a carry would launder a rung through an "
                         "unbounded chain of copies")

    def test_the_ledger_is_never_required_for_a_scan_to_finish(self):
        aegis.CUSTODY_FILE = os.path.join(self.tmp, "nope", "custody.jsonl")
        aegis._CUSTODY_CARRY_CACHE.clear()
        self.assertIsNone(aegis._custody_carried("b" * 64))
        self.assertFalse(aegis._custody_remember("b" * 64, "build-output",
                                                 "/x"))


class CarriedRungKeepsItsTier(unittest.TestCase):
    """`copy-of-graded` inherits the weak tier's arithmetic rather than
    scoring 1.0 by omission — the reason the tiers build _RISK_CUSTODY_WEIGHT
    instead of listing rungs by hand."""

    def test_it_is_weak_everywhere_the_ladder_is_consulted(self):
        self.assertIn("copy-of-graded", aegis._WEAK_CUSTODY)
        self.assertEqual(aegis._RISK_CUSTODY_WEIGHT["copy-of-graded"], 0.5)
        self.assertEqual(aegis._demote("HIGH", "copy-of-graded"), "MEDIUM")
        self.assertEqual(aegis._demote("HIGH", "copy-of-graded",
                                       attack_defined=True), "HIGH")
        self.assertTrue(aegis._PROVENANCE_NOTE.get("copy-of-graded"),
                        "an ungrounded rung in a report teaches nothing")


class ChainRulesDoNotDoubleCount(unittest.TestCase):
    """#511 (11 events) and #517 (3 events) carried entity key
    b1fd29aea4dad2af, and #517's evidence was wholly inside #511's. Two of the
    four open CRITICALs were one event, read twice."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_chain_")
        self._saved = tuple(getattr(aegis, n) for n in
                            ("STATE_DIR", "EVENT_DB", "RUN_LOG"))
        aegis.STATE_DIR = self.tmp
        aegis.EVENT_DB = os.path.join(self.tmp, "t.db")
        aegis.RUN_LOG = os.path.join(self.tmp, "run.log")
        self.now = aegis._epoch()
        self.db = aegis._event_connection()
        # Real rows: incident_events carries a FOREIGN KEY, so a chain built on
        # invented ids proves nothing about the one the scan builds.
        self.ev = {}
        with self.db:
            for n in (1, 2, 3):
                cur = self.db.execute(
                    "INSERT INTO events(occurred_at,observed_at,source,"
                    "event_type,data_json) VALUES(?,?,?,?,?)",
                    (self.now, self.now, "persistence", "observation.finding",
                     aegis.json.dumps({"fingerprint": "f%d" % n})))
                self.ev[n] = cur.lastrowid

    def tearDown(self):
        self.db.close()
        for name, value in zip(("STATE_DIR", "EVENT_DB", "RUN_LOG"),
                               self._saved):
            setattr(aegis, name, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _ids(self, *ns):
        return frozenset(self.ev[n] for n in ns)

    def _chain(self, key, events):
        with self.db:
            return aegis._upsert_incident(
                self.db, key, "t", "CRITICAL", "correlation", self.now,
                sorted(events), False)

    def _status(self, inc_id):
        return self.db.execute("SELECT status FROM incidents WHERE id=?",
                               (inc_id,)).fetchone()[0]

    def test_a_strict_subset_is_closed_naming_its_survivor(self):
        big = self._chain("chain:persistence-execution:e1", self._ids(1, 2, 3))
        small = self._chain("chain:clickfix:e1", self._ids(1, 2))
        closed = aegis._dedupe_chain_incidents(
            self.db, [("e1", big, self._ids(1, 2, 3)),
                      ("e1", small, self._ids(1, 2))], self.now)
        self.assertEqual(closed, 1)
        self.assertEqual(self._status(small), "RESOLVED")
        self.assertEqual(self._status(big), "OPEN",
                         "the fuller reading survives")
        res = self.db.execute(
            "SELECT resolution FROM incidents WHERE id=?",
            (small,)).fetchone()[0]
        self.assertIn(str(big), res,
                      "a collapse the operator cannot trace is a deletion")

    def test_partly_overlapping_chains_are_both_kept(self):
        """The safety property. Two rules matching DIFFERENT evidence on one
        entity are two readings, not a duplicate — a remote-access chain
        beside a credential-capture chain is worse than either alone."""
        a = self._chain("chain:remote-access:e1", self._ids(1, 2))
        b = self._chain("chain:credential-capture:e1", self._ids(2, 3))
        closed = aegis._dedupe_chain_incidents(
            self.db, [("e1", a, self._ids(1, 2)),
                      ("e1", b, self._ids(2, 3))], self.now)
        self.assertEqual(closed, 0)
        self.assertEqual(self._status(a), "OPEN")
        self.assertEqual(self._status(b), "OPEN")

    def test_identical_evidence_sets_are_both_kept(self):
        a = self._chain("chain:remote-access:e1", self._ids(1, 2))
        b = self._chain("chain:clickfix:e1", self._ids(1, 2))
        self.assertEqual(aegis._dedupe_chain_incidents(
            self.db, [("e1", a, self._ids(1, 2)),
                      ("e1", b, self._ids(1, 2))], self.now), 0,
            "neither is strictly smaller, so there is no reason to pick")

    def test_it_judges_full_evidence_not_this_scans_matches(self):
        """A chain accruing evidence for days can match one new event in a
        single scan. Judged on that alone it would be 'the smaller one' and be
        closed by a chain it actually outweighs, which is the opposite of what
        this is for — so the comparison reads each incident's whole set back
        from the store."""
        broad = self._chain("chain:remote-access:e1", self._ids(1, 2, 3))
        narrow = self._chain("chain:clickfix:e1", self._ids(1, 2))
        # `broad` matched only event 1 THIS scan; `narrow` matched two.
        closed = aegis._dedupe_chain_incidents(
            self.db, [("e1", broad, self._ids(1)),
                      ("e1", narrow, self._ids(1, 2))], self.now)
        self.assertEqual(closed, 1)
        self.assertEqual(self._status(broad), "OPEN",
                         "the incident with the wider record survives")
        self.assertEqual(self._status(narrow), "RESOLVED")

    def test_a_subset_on_a_DIFFERENT_entity_is_untouched(self):
        a = self._chain("chain:persistence-execution:e1", self._ids(1, 2, 3))
        b = self._chain("chain:clickfix:e2", self._ids(1, 2))
        self.assertEqual(aegis._dedupe_chain_incidents(
            self.db, [("e1", a, self._ids(1, 2, 3)),
                      ("e2", b, self._ids(1, 2))], self.now), 0,
            "two subjects sharing evidence is a correlation, not a duplicate")


class AChainVerdictReachesTheBaseline(unittest.TestCase):
    """`benign-positive` on a chain used to promote nothing.

    `_accept_into_baseline` built its wanted-set only from `signal:` keys, and
    a chain's key is `chain:<rule>:<entity>` — a correlation, not a fact, so
    it never appears in a surface diff. The verdict closed the row, the
    persistence item underneath never reached the baseline, the next scan
    re-emitted it as new and the chain re-opened. On the live store that was
    1,065 and 770 evidence events on two CRITICALs, one of them aegis's own
    menu-bar host, with no verdict that could end either."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_chainaccept_")
        self.saved = tuple(getattr(aegis, n) for n in
                           ("STATE_DIR", "EVENT_DB", "BASELINE", "SELFSTATE",
                            "RUN_LOG"))
        aegis.STATE_DIR = self.tmp
        for name, fn in (("EVENT_DB", "t.db"), ("BASELINE", "baseline.json"),
                         ("SELFSTATE", "selfstate.json"),
                         ("RUN_LOG", "run.log")):
            setattr(aegis, name, os.path.join(self.tmp, fn))
        self.now = aegis._epoch()
        self.path, rec = _job("xbar")
        self.live = {self.path: _baseline_shaped(rec)}
        aegis.save_json(aegis.BASELINE, {"persistence": {}, "created": "x"})
        self._real_snapshot = aegis.snapshot_persistence
        aegis.snapshot_persistence = lambda: self.live

    def tearDown(self):
        aegis.snapshot_persistence = self._real_snapshot
        for name, value in zip(("STATE_DIR", "EVENT_DB", "BASELINE",
                                "SELFSTATE", "RUN_LOG"), self.saved):
            setattr(aegis, name, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _findings(self):
        base = aegis.load_baseline()[0].get("persistence") or {}
        return aegis.check_persistence(base, aegis.snapshot_persistence())

    def _chain_incident(self, finding):
        db = aegis._event_connection()
        with db:
            cur = db.execute(
                "INSERT INTO events(occurred_at,observed_at,source,event_type,"
                "data_json) VALUES(?,?,?,?,?)",
                (self.now, self.now, "persistence", "observation.finding",
                 aegis.json.dumps(finding)))
            i = aegis._upsert_incident(
                db, "chain:supply-chain:a688cb46868f1d19",
                "Background-item execution chain", "CRITICAL", "correlation",
                self.now, [cur.lastrowid], False)
        db.close()
        return i

    def test_accepting_a_chain_stops_the_fact_being_re_asserted(self):
        f = self._findings()[0]
        self.assertEqual(f["title"], "New persistence item")
        i = self._chain_incident(f)
        self.assertEqual(aegis._accept_into_baseline([i]), [self.path],
                         "the fact under a chain must be promotable")
        self.assertEqual(self._findings(), [],
                         "an accepted item stops being reported at all, "
                         "rather than being reported and then muted")

    def test_the_accepted_bytes_are_what_lands(self):
        """The guard that makes it safe: accepting a job does not accept its
        next mutation."""
        f = self._findings()[0]
        aegis._accept_into_baseline([self._chain_incident(f)])
        mutated = dict(self.live[self.path])
        mutated["sha256"] = "f" * 64
        self.live = {self.path: _baseline_shaped(mutated)}
        self.assertTrue(self._findings(),
                        "a changed job after acceptance is its own fact")

    def test_a_chain_whose_fact_has_already_changed_promotes_nothing(self):
        f = self._findings()[0]
        i = self._chain_incident(f)
        mutated = dict(self.live[self.path])
        mutated["sha256"] = "e" * 64
        self.live = {self.path: _baseline_shaped(mutated)}
        self.assertEqual(aegis._accept_into_baseline([i]), [],
                         "the fingerprint the operator reviewed is gone, so "
                         "the change stands as its own unreviewed fact")


if __name__ == "__main__":
    unittest.main()
