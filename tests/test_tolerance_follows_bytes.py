#!/usr/bin/env python3
"""Tolerance keys on the BYTES as well as the path.

The live queue is what these pin. Twenty-seven open incidents on the reference
Mac were eighteen "Suspicious running process" rows, and the operator had
already ruled benign-positive on several of the exact binaries underneath them
— three times on one uv-managed CPython alone. None of those verdicts counted,
because a process verdict accumulated under `process:<path>:<trust>` and this
machine reproduces one binary into venvs, uv build tmpdirs, pipx envs, agent
worktrees, staging and release dirs and DMG scratch mounts. Thirty verdicts
spread over twenty-eight identities, every one below the floor of three: the
process sensor had learned nothing at all.

So content becomes a SECOND identity a verdict accumulates under, never a
replacement — a vendor app updating in place keeps stable paths and churning
bytes, the operator's own build output does the exact reverse, and dropping
either identity strands one of those populations forever.

The same pass closes a hole the content-keyed correlation key opened:
`process:sha:<sha>` fed to the hash-stripper yields `process:sha`, one bucket
shared by every content-keyed process incident on the machine.

Fully sandboxed: STATE_DIR/EVENT_DB are redirected into a tmp dir.
"""
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
SHA = "d22a09ce45166ee066022909e071bba239c263ba090ed8f0884f7f21ae922ac3"
OTHER_SHA = "b8014caecb1f334bbc67e99b74d9f5fa6e3519c6567c98a890940b31ffeffa32"
# The eight paths #505 actually observed, trimmed to the three shapes that
# matter: a venv, a uv build tmpdir, and a bundled copy inside an .app.
PATHS = (
    "/Users/c/Life OS/cadence/prebrief/.venv/bin/python3",
    "/Users/c/.cache/uv/builds-v0/.tmpXAmJp2/bin/python",
    "/Users/c/w/staging/bioREADr.app/Contents/Resources/python/bin/python3",
)


def _process_finding(path, sha=SHA, severity="HIGH", trust=SUSPICIOUS_TRUST):
    """A process finding shaped exactly as check_processes emits one."""
    return {
        "fingerprint": "process:sha:%s" % sha,
        "severity": severity, "category": "process",
        "title": "Suspicious running process",
        "detail": "%s (%s) running from user-writable path" % (path, trust),
        "confidence": "medium",
        "subject": aegis._subject("process", path, trust=trust, content=sha),
    }


class TestContentIdentity(unittest.TestCase):
    """Pure derivation: what identity does a subject or fingerprint render?"""

    def test_same_bytes_at_different_paths_share_one_content_identity(self):
        idents = {aegis._finding_content_identity(_process_finding(p))
                  for p in PATHS}
        self.assertEqual(len(idents), 1, idents)
        self.assertEqual(idents.pop(), "process:content:%s" % SHA)

    def test_different_bytes_never_share_a_content_identity(self):
        self.assertNotEqual(
            aegis._finding_content_identity(_process_finding(PATHS[0])),
            aegis._finding_content_identity(
                _process_finding(PATHS[0], sha=OTHER_SHA)))

    def test_path_identity_is_preserved_alongside_it(self):
        """Additive, not a replacement: the path-keyed identity a vendor app
        updating in place accumulates under must keep rendering unchanged, or
        the fix orphans every verdict it was supposed to rescue."""
        f = _process_finding(PATHS[0])
        self.assertEqual(aegis._finding_identity(f),
                         "process:%s:%s" % (PATHS[0], SUSPICIOUS_TRUST))

    def test_trust_churn_does_not_move_the_content_identity(self):
        """The same uv binary graded 'broken' when the operator dismissed it
        and 'adhoc' when it reopened as #514, so trust is churn of its own."""
        self.assertEqual(
            aegis._finding_content_identity(
                _process_finding(PATHS[0], trust=PUBLISHER_TRUST)),
            aegis._finding_content_identity(
                _process_finding(PATHS[0], trust=SUSPICIOUS_TRUST)))

    def test_old_path_keyed_fingerprint_yields_the_content_identity_too(self):
        """Verdicts given before the key shape changed must carry forward on
        their own — no migration, no one-time closer."""
        self.assertEqual(
            aegis._fingerprint_content_identity(
                "process:%s:%s:%s" % (PATHS[0], SUSPICIOUS_TRUST, SHA)),
            "process:content:%s" % SHA)

    def test_short_or_absent_hashes_claim_nothing(self):
        for fp in ("process:%s:%s:None" % (PATHS[0], SUSPICIOUS_TRUST),
                   "process:%s:%s:9ac24874dddaa414" % (PATHS[0],
                                                       SUSPICIOUS_TRUST),
                   "persistence:changed:/L/x.plist:%s" % SHA,
                   "behavior:bash:hdiutil-nobrowse:9ac24874dddaa414"):
            self.assertIsNone(aegis._fingerprint_content_identity(fp), fp)


class TestSubjectlessProcessKeyIsNotAnIdentity(unittest.TestCase):
    """`process:sha:<sha>` must never strip to the subject-less `process:sha`.

    That string names no antigen: it is shared by every content-keyed process
    incident on the machine, so three benign-positive verdicts on three
    UNRELATED binaries would have tolerized the whole sensor.
    """

    def test_content_keyed_key_does_not_strip_to_a_shared_bucket(self):
        self.assertIsNone(aegis._tolerance_identity("process:sha:%s" % SHA))

    def test_two_unrelated_binaries_do_not_share_a_stripped_identity(self):
        a = aegis._tolerance_identity("process:sha:%s" % SHA)
        b = aegis._tolerance_identity("process:sha:%s" % OTHER_SHA)
        self.assertFalse(a is not None and a == b, (a, b))

    def test_subject_bearing_identities_still_generalize(self):
        """The floor that closes the hole must not take real identities with
        it — each of these still names what it is about."""
        for fp, expect in (
                ("persistence:changed:/L/x.plist:4ecbaeb7c89892df",
                 "persistence:changed:/L/x.plist"),
                ("process:/usr/local/bin/x:%s:%s" % (SUSPICIOUS_TRUST, SHA),
                 "process:/usr/local/bin/x:%s" % SUSPICIOUS_TRUST),
                ("behavior:bash:hdiutil-nobrowse:9ac24874dddaa414",
                 "behavior:bash:hdiutil-nobrowse")):
            self.assertEqual(aegis._tolerance_identity(fp), expect, fp)


class TestBeaconGateUnchanged(unittest.TestCase):
    """The beacon subject now carries content so its bytes can be named. That
    must not flip on the PATH-keyed beacon generalization, which
    _tolerance_identity still refuses for a never-normalized path (a binary
    replaced in place at a reused endpoint would inherit the verdicts)."""

    def _beacon(self, path, content=None):
        return aegis._subject("beacon", path, ip="1.2.3.4", port="443",
                              content=content)

    def test_content_does_not_qualify_the_path_keyed_identity(self):
        path = "/Applications/bioREADr.app/Contents/MacOS/zotero"
        self.assertIsNone(aegis._subject_identity(self._beacon(path)))
        self.assertIsNone(
            aegis._subject_identity(self._beacon(path, content=SHA)))

    def test_versioned_path_still_generalizes(self):
        sub = self._beacon("/x/extensions/vendor.tool-2.1.226-arm64/bin/tool",
                           content=SHA)
        self.assertEqual(aegis._subject_identity(sub),
                         aegis._subject_identity(self._beacon(
                             "/x/extensions/vendor.tool-2.1.228-arm64/bin/tool",
                             content=SHA)))

    def test_beacon_bytes_get_their_own_identity(self):
        path = "/Applications/bioREADr.app/Contents/MacOS/zotero"
        self.assertEqual(
            aegis._subject_content_identity(self._beacon(path, content=SHA)),
            "beacon:content:%s:1.2.3.4:443" % SHA)
        # The endpoint stays a fact: a new address is a new identity.
        moved = aegis._subject("beacon", path, ip="5.6.7.8", port="443",
                               content=SHA)
        self.assertNotEqual(
            aegis._subject_content_identity(moved),
            aegis._subject_content_identity(self._beacon(path, content=SHA)))


class _Sandbox(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_bytes_")
        state = os.path.join(self.tmp, ".aegis")
        os.makedirs(state)
        self._saved = {}
        for k, v in (("STATE_DIR", state),
                     ("EVENT_DB", os.path.join(state, "aegis.db"))):
            self._saved[k] = getattr(aegis, k)
            setattr(aegis, k, v)
        aegis.init_event_store()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(aegis, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _ingest(self, f, at):
        db = aegis._event_connection()
        try:
            with db:
                cur = db.execute(
                    "INSERT INTO events(occurred_at,observed_at,source,"
                    "event_type,data_json) VALUES(?,?,?,?,?)",
                    (at, at, f["category"], "observation.finding",
                     json.dumps(f)))
                aegis._apply_correlations(db, [(cur.lastrowid, f)], at,
                                          initially_notified=True)
        finally:
            db.close()

    def _latest_incident(self):
        db = aegis._event_connection()
        try:
            row = db.execute(
                "SELECT * FROM incidents ORDER BY id DESC LIMIT 1").fetchone()
            return dict(row) if row else None
        finally:
            db.close()

    def _dismiss(self, incident_id, at, code="benign-positive"):
        self.assertTrue(aegis.transition_incident(
            incident_id, "FALSE_POSITIVE", now=at, reason_code=code))

    def _memory(self, at):
        db = aegis._event_connection()
        try:
            return aegis._suppression_memory(db, at)
        finally:
            db.close()


class TestVerdictsConvergeAcrossPaths(_Sandbox):
    """The end-to-end claim: a verdict on one binary covers the same bytes
    wherever they are next seen.

    Before #51, thirty verdicts spread over twenty-eight path buckets taught
    nothing. #51 gave the bytes their own identity at the path floor of
    three; S6 (2026-09-23) moved the exact bytes to a floor of ONE
    (_TOLERANCE_FLOOR["exact"]), because an exact-bytes identity generalizes
    to nothing the operator did not judge — asking three times about one
    fact was the teaching evaporating in its purest form. Every other guard
    is unchanged, and the path identity keeps three."""

    def _teach_one(self, sha=SHA, code="benign-positive", path=PATHS[0],
                   at=NOW):
        """One verdict on `sha` at `path`; returns the incident id."""
        f = _process_finding(path, sha=sha)
        f["fingerprint"] = "process:sha:%s:%s" % (sha, path)
        self._ingest(f, at)
        incident = self._latest_incident()
        self.assertEqual(incident["status"], "OPEN")
        self._dismiss(incident["id"], at + 30, code=code)
        return incident["id"]

    def test_one_verdict_reaches_the_floor(self):
        self._teach_one()
        tolerance = self._memory(NOW + 9000)[0]
        self.assertIn("process:content:%s" % SHA, tolerance)
        self.assertEqual(tolerance["process:content:%s" % SHA][0],
                         aegis._TOLERANCE_FLOOR["exact"])

    def test_the_copies_at_the_other_paths_open_pre_closed(self):
        """Each path is its own case, exactly as the live store recorded
        them; after one verdict the rest are the same bytes and close as
        auto-tolerated instead of asking again."""
        self._teach_one()
        for i, path in enumerate(PATHS[1:], 1):
            f = _process_finding(path)
            f["fingerprint"] = "process:sha:%s:%d" % (SHA, i)
            self._ingest(f, NOW + i * 600)
            incident = self._latest_incident()
            self.assertEqual((incident["status"], incident["resolution"]),
                             ("FALSE_POSITIVE", "auto-tolerated"), path)

    def test_the_next_sighting_at_a_fourth_path_is_tolerated(self):
        self._teach_one()
        memory = self._memory(NOW + 9000)
        fresh = _process_finding("/Users/c/somewhere/else/.venv/bin/python3")
        decision, verdicts = aegis._signal_decision(fresh, memory)
        self.assertEqual(decision, "tolerated")
        self.assertGreaterEqual(verdicts, aegis._TOLERANCE_FLOOR["exact"])

    def test_different_bytes_at_a_taught_path_still_alert(self):
        """Antigen specificity, and the direction that matters: tolerance
        earned on one binary must never cover a DIFFERENT one, even at a path
        the operator has already blessed."""
        self._teach_one()
        memory = self._memory(NOW + 9000)
        impostor = _process_finding(PATHS[0], sha=OTHER_SHA)
        self.assertEqual(aegis._signal_decision(impostor, memory)[0], None)

    def test_the_path_identity_still_needs_three(self):
        """Only the exact bytes moved to one. Two verdicts on two different
        binaries at one path leave the path identity below its floor, so a
        third binary there still alerts."""
        self._teach_one(sha=SHA, at=NOW)
        self._teach_one(sha=OTHER_SHA, at=NOW + 600)
        memory = self._memory(NOW + 9000)
        third = _process_finding(PATHS[0], sha="c" * 64)
        self.assertEqual(aegis._signal_decision(third, memory)[0], None)

    def test_false_positive_verdicts_teach_nothing_here(self):
        """Only benign-positive is a statement about the subject; a
        false-positive says the RULE was wrong."""
        self._teach_one(code="false-positive")
        tolerance = self._memory(NOW + 9000)[0]
        self.assertNotIn("process:content:%s" % SHA, tolerance)

    def test_critical_is_never_tolerated(self):
        self._teach_one()
        memory = self._memory(NOW + 9000)
        crit = _process_finding(PATHS[0], severity="CRITICAL")
        self.assertEqual(aegis._signal_decision(crit, memory)[0], None)

    def test_a_dispute_reaches_the_content_identity(self):
        """A dispute must revoke BOTH identities the subject accumulated
        under, or tolerance keeps closing the very incidents disputed.

        The dispute here is INVESTIGATING on a still-open copy, because that
        is the form that leaves the verdict standing: a reopen of the judged
        incident deletes the dismissal row the count is built on, so it would
        drop the identity below the floor and never consult the disputed set
        at all — the test would pass while proving nothing. The disputed copy
        is opened BEFORE the verdict, because once tolerance engages no
        further copy stays OPEN long enough to be moved.
        """
        f = _process_finding("/Users/c/fourth/.venv/bin/python3")
        f["fingerprint"] = "process:sha:%s:disputed" % SHA
        self._ingest(f, NOW)
        self.assertTrue(aegis.transition_incident(
            self._latest_incident()["id"], "INVESTIGATING", now=NOW + 30))
        self._teach_one(at=NOW + 600)

        tolerance, _rot, disputed = self._memory(NOW + 9000)[:3]
        self.assertIn("process:content:%s" % SHA, tolerance)
        self.assertIn("process:content:%s" % SHA, disputed)
        fresh = _process_finding("/Users/c/yet/another/.venv/bin/python3")
        self.assertEqual(
            aegis._signal_decision(fresh, self._memory(NOW + 9000))[0], None)


class TestEvidenceRowsShowWhatDiffers(unittest.TestCase):
    """An evidence list that reprints the incident's TITLE per row shows the
    operator nothing: the title is constant by construction — it is part of
    what groups the rows. #505 printed "Suspicious running process" twenty
    times while eight distinct interpreter paths sat in the stored events."""

    def _rows(self, details):
        return [{"data_json": json.dumps({"title": "Suspicious running process",
                                          "detail": d}),
                 "event_type": "observation.finding", "source": "process",
                 "observed_at": NOW + i * 60}
                for i, d in enumerate(details)]

    def test_distinct_observations_are_each_named(self, ):
        import io
        import contextlib
        rows = self._rows(["%s (%s) running from user-writable path"
                           % (p, SUSPICIOUS_TRUST) for p in PATHS])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            aegis._evidence_rows(rows)
        out = buf.getvalue()
        for path in PATHS:
            self.assertIn(path, out, out)

    def test_repeats_of_one_fact_fold_into_a_count(self):
        import io
        import contextlib
        same = "%s (%s) running from user-writable path" % (PATHS[0],
                                                            SUSPICIOUS_TRUST)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            aegis._evidence_rows(self._rows([same] * 5))
        out = buf.getvalue()
        self.assertEqual(out.count(PATHS[0]), 1, out)
        self.assertIn("5x", out)

    def test_descriptor_falls_back_to_the_title_without_detail(self):
        self.assertEqual(
            aegis._evidence_descriptor({"title": "Only a title"}, "x"),
            "Only a title")

    def test_multiline_detail_uses_only_its_first_line(self):
        desc = aegis._evidence_descriptor(
            {"title": "t", "detail": "the fact\nthe custody explanation"}, "x")
        self.assertEqual(desc, "the fact")


if __name__ == "__main__":
    unittest.main()
