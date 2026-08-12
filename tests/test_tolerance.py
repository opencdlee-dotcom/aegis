#!/usr/bin/env python3
"""Acquired tolerance — identity-level immune memory over typed dismissals.

The exact-fingerprint reattach tolerates identical re-observations; these tests
pin the layer above it: >= _TOLERANCE_MIN_VERDICTS distinct HUMAN
benign-positive verdicts on one hash-stripped identity auto-close the next
hash-churned re-observation (evidence kept, no alert), and every immunology
guard holds — repeated exposure required, antigen-specific, inflammation
overrides, machine verdicts teach nothing, one reopen disputes the tolerance.

Fully sandboxed: every test redirects STATE_DIR/EVENT_DB into a tmp dir.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

NOW = 1786600000  # > 2026-01-01 store floor
PLIST = "/Library/LaunchAgents/com.vendor.updater.plist"


def _finding(fp, severity="HIGH", category="persistence", title="Persistence item CHANGED"):
    return {"fingerprint": fp, "severity": severity, "category": category,
            "title": title, "detail": "test", "confidence": "medium"}


class _Sandbox(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_tol_")
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
        """One finding event -> correlation pass, as the scan pipeline would."""
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

    def _incident_for(self, fp):
        db = aegis._event_connection()
        try:
            row = db.execute(
                "SELECT * FROM incidents WHERE correlation_key=? "
                "ORDER BY id DESC LIMIT 1", ("signal:" + fp,)).fetchone()
            return dict(row) if row else None
        finally:
            db.close()

    def _teach(self, n, severity="HIGH", base=NOW):
        """n distinct incidents on PLIST (hash churn), each dismissed
        benign-positive by the 'operator'. Returns the taught identity."""
        for i in range(n):
            fp = "persistence:changed:%s:%016x" % (PLIST, i)
            self._ingest(_finding(fp, severity=severity), base + i * 60)
            incident = self._incident_for(fp)
            self.assertEqual(incident["status"], "OPEN")
            self.assertTrue(aegis.transition_incident(
                incident["id"], "FALSE_POSITIVE", now=base + i * 60 + 30,
                reason_code="benign-positive"))
        return "persistence:changed:" + PLIST


class TestToleranceIdentity(unittest.TestCase):
    def test_trailing_content_hash_is_stripped(self):
        self.assertEqual(
            aegis._tolerance_identity(
                "persistence:changed:%s:4ecbaeb7c89892df" % PLIST),
            "persistence:changed:" + PLIST)
        self.assertEqual(
            aegis._tolerance_identity("process:/usr/local/bin/x:adhoc:" + "a" * 64),
            "process:/usr/local/bin/x:adhoc")

    def test_non_hash_suffixes_do_not_generalize(self):
        # A port, a 'None' sha, a bare word: all facts, none of them churn.
        for fp in ("beacon:/Applications/App.app/Contents/MacOS/app:1.2.3.4:443",
                   "process:/var/folders/9n/:unsigned:None",
                   "short:ab"):
            self.assertIsNone(aegis._tolerance_identity(fp), fp)

    def test_attack_defined_prefixes_never_tolerize(self):
        for fp in ("decoy:read:/home/x/.aws/credentials:" + "b" * 16,
                   "latch:cleared:/Library/LaunchAgents:" + "c" * 16,
                   "canary:touched:/home/x/canary.docx:" + "d" * 16):
            self.assertIsNone(aegis._tolerance_identity(fp), fp)


class TestAcquiredTolerance(_Sandbox):
    def test_three_verdicts_confer_tolerance(self):
        self._teach(3)
        fp = "persistence:changed:%s:%016x" % (PLIST, 99)
        self._ingest(_finding(fp), NOW + 3600)
        incident = self._incident_for(fp)
        self.assertEqual(incident["status"], "FALSE_POSITIVE")
        self.assertEqual(incident["resolution"], "auto-tolerated")
        self.assertIsNone(incident["next_reminder_at"])
        # The evidence is kept and the machine verdict is on the record.
        db = aegis._event_connection()
        try:
            kept = db.execute(
                "SELECT COUNT(*) FROM incident_events WHERE incident_id=?",
                (incident["id"],)).fetchone()[0]
            lifecycle = db.execute(
                "SELECT data_json FROM events WHERE incident_id=? AND "
                "event_type='incident.lifecycle' ORDER BY id DESC LIMIT 1",
                (incident["id"],)).fetchone()[0]
        finally:
            db.close()
        self.assertGreaterEqual(kept, 1)
        record = json.loads(lifecycle)
        self.assertEqual(record["reason_code"], "auto-tolerated")
        self.assertEqual(record["prior_verdicts"], 3)

    def test_repeated_exposure_is_required(self):
        self._teach(2)  # one short of the floor
        fp = "persistence:changed:%s:%016x" % (PLIST, 99)
        self._ingest(_finding(fp), NOW + 3600)
        self.assertEqual(self._incident_for(fp)["status"], "OPEN")

    def test_machine_verdicts_teach_nothing(self):
        # 3 human verdicts + 1 auto-tolerated close must still count as 3:
        # a fingerprint on a DIFFERENT identity with 2 human verdicts plus
        # dismissal rows written by the machine would otherwise cascade.
        self._teach(3)
        fp = "persistence:changed:%s:%016x" % (PLIST, 99)
        self._ingest(_finding(fp), NOW + 3600)
        db = aegis._event_connection()
        try:
            machine_rows = db.execute(
                "SELECT COUNT(*) FROM dismissals WHERE incident_id=?",
                (self._incident_for(fp)["id"],)).fetchone()[0]
        finally:
            db.close()
        self.assertEqual(machine_rows, 0)

    def test_false_positive_labels_do_not_teach(self):
        # false-positive = broken rule -> tune the rule, never tolerize events.
        for i in range(3):
            fp = "persistence:changed:%s:%016x" % (PLIST, i)
            self._ingest(_finding(fp), NOW + i * 60)
            aegis.transition_incident(
                self._incident_for(fp)["id"], "FALSE_POSITIVE",
                now=NOW + i * 60 + 30, reason_code="false-positive")
        fp = "persistence:changed:%s:%016x" % (PLIST, 99)
        self._ingest(_finding(fp), NOW + 3600)
        self.assertEqual(self._incident_for(fp)["status"], "OPEN")

    def test_severity_escalation_breaks_tolerance(self):
        self._teach(3, severity="HIGH")
        fp = "persistence:changed:%s:%016x" % (PLIST, 99)
        self._ingest(_finding(fp, severity="CRITICAL"), NOW + 3600)
        self.assertEqual(self._incident_for(fp)["status"], "OPEN")

    def test_category_outside_allowlist_is_not_tolerated(self):
        ip_fp = "net-outbound:/usr/bin/nc:%s" % ("e" * 16)
        for i in range(3):
            fp = "net-outbound:/usr/bin/nc:%016x" % i
            self._ingest(_finding(fp, category="net-outbound",
                                  title="Outbound connection"), NOW + i * 60)
            aegis.transition_incident(
                self._incident_for(fp)["id"], "FALSE_POSITIVE",
                now=NOW + i * 60 + 30, reason_code="benign-positive")
        self._ingest(_finding(ip_fp, category="net-outbound",
                              title="Outbound connection"), NOW + 3600)
        self.assertEqual(self._incident_for(ip_fp)["status"], "OPEN")

    def test_reopen_disputes_and_revokes(self):
        ident_fps = self._teach(3)
        self.assertTrue(ident_fps)
        # Tolerance is live; one close happens...
        fp1 = "persistence:changed:%s:%016x" % (PLIST, 90)
        self._ingest(_finding(fp1), NOW + 3600)
        tolerated = self._incident_for(fp1)
        self.assertEqual(tolerated["resolution"], "auto-tolerated")
        # ...the operator disputes it. The reopened incident is active on the
        # identity, so the NEXT churn must open normally and alert.
        self.assertTrue(aegis.transition_incident(
            tolerated["id"], "OPEN", now=NOW + 3700))
        fp2 = "persistence:changed:%s:%016x" % (PLIST, 91)
        self._ingest(_finding(fp2), NOW + 4000)
        self.assertEqual(self._incident_for(fp2)["status"], "OPEN")

    def test_stale_verdicts_expire(self):
        old = NOW - aegis._TOLERANCE_WINDOW - 86400
        self._teach(3, base=old)
        fp = "persistence:changed:%s:%016x" % (PLIST, 99)
        self._ingest(_finding(fp), NOW)
        self.assertEqual(self._incident_for(fp)["status"], "OPEN")

    def test_tolerated_incident_is_visible_and_counted(self):
        self._teach(3)
        fp = "persistence:changed:%s:%016x" % (PLIST, 99)
        self._ingest(_finding(fp), NOW + 3600)
        # It appears in the complete history...
        everything = aegis.list_incidents(active_only=False)
        self.assertIn("auto-tolerated",
                      [i.get("resolution") for i in everything])
        # ...and never in the active queue.
        active = aegis.list_incidents(active_only=True)
        self.assertNotIn("signal:" + fp,
                         [i["correlation_key"] for i in active])


if __name__ == "__main__":
    unittest.main()
