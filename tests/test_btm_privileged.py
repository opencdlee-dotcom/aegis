#!/usr/bin/env python3
"""The BTM privileged-surface fix — macOS 26 moved `sfltool dumpbtm` behind
system.privilege.admin, and until this fix the sensor reported the permanent
OS-imposed wall as a broken sensor: DEGRADED on every scan (540+ consecutive
failures) feeding one immortal HIGH coverage-degraded incident.

Pinned here:
  1. The authorization signature returns SURFACE_PRIVILEGED; a generic failure
     still returns None (the transient path keeps escalating — that alarm is
     for sensors that SHOULD be answering).
  2. PRIVILEGED health never escalates to an incident, resets the failure
     counter, never forges last_ok_at, and RESOLVES an existing degraded
     incident with the honest privileged-only resolution.
  3. _scan_surfaces treats the sentinel like a non-answer for diffing: no
     findings fabricated, nothing adopted into the baseline.

Fully sandboxed: durable-state tests redirect STATE_DIR/EVENT_DB to a tmp dir.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

NOW = 1786700000  # > 2026-01-01 store floor

# Verbatim shape of the real macOS 26 refusal (captured live 2026-08-12).
_AUTH_STDERR = (
    "2026-08-12 07:54:45.948 sfltool[70850:6343723] Error obtaining right "
    "system.privilege.admin: Error Domain=NSOSStatusErrorDomain Code=-60006 "
    '"errAuthorizationCanceled: The authorization was cancelled by the user."\n'
    "2026-08-12 07:54:45.949 sfltool[70850:6343723] authorization failed")

_DUMP_OK = """#1:
  UUID: AAAA-BBBB
  Name: Helper
  Type: login item
  Identifier: com.vendor.helper
  URL: file:///Applications/Vendor.app/
"""


class TestSnapshotBtmOutcomes(unittest.TestCase):
    def setUp(self):
        self._run = aegis.run

    def tearDown(self):
        aegis.run = self._run

    def test_authorization_refusal_is_privileged(self):
        aegis.run = lambda cmd, timeout=15, extra_env=None: ("", _AUTH_STDERR, 1)
        self.assertIs(aegis.snapshot_btm(), aegis.SURFACE_PRIVILEGED)

    def test_generic_failure_is_still_a_transient_none(self):
        # A timeout/flake must keep the old contract: None -> DEGRADED -> the
        # coverage alarm still exists for sensors that should be answering.
        aegis.run = lambda cmd, timeout=15, extra_env=None: ("", "boom", 1)
        self.assertIsNone(aegis.snapshot_btm())
        aegis.run = lambda cmd, timeout=15, extra_env=None: ("", "", 0)
        self.assertIsNone(aegis.snapshot_btm())  # empty output = non-answer

    def test_success_still_parses(self):
        aegis.run = lambda cmd, timeout=15, extra_env=None: (_DUMP_OK, "", 0)
        snap = aegis.snapshot_btm()
        self.assertIn("com.vendor.helper", snap)


class _Sandbox(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_btm_")
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

    def _health_pass(self, status, at, detail="d"):
        db = aegis._event_connection()
        try:
            with db:
                aegis._record_health(
                    db, [{"sensor_id": "surface.btm", "status": status,
                          "detail": detail}], at)
        finally:
            db.close()

    def _sensor_row(self):
        db = aegis._event_connection()
        try:
            return dict(db.execute(
                "SELECT * FROM sensor_status WHERE sensor_id='surface.btm'"
            ).fetchone())
        finally:
            db.close()

    def _sensor_incident(self):
        db = aegis._event_connection()
        try:
            row = db.execute(
                "SELECT * FROM incidents WHERE correlation_key="
                "'sensor:surface.btm' ORDER BY id DESC LIMIT 1").fetchone()
            return dict(row) if row else None
        finally:
            db.close()


class TestPrivilegedHealth(_Sandbox):
    def test_privileged_never_escalates_to_an_incident(self):
        for i in range(5):
            self._health_pass("PRIVILEGED", NOW + i * 3600)
        self.assertIsNone(self._sensor_incident())
        row = self._sensor_row()
        self.assertEqual(row["status"], "PRIVILEGED")
        self.assertEqual(row["consecutive_failures"], 0)
        self.assertIsNone(row["last_ok_at"])  # the surface did NOT answer

    def test_degraded_still_escalates(self):
        for i in range(3):
            self._health_pass("DEGRADED", NOW + i * 3600)
        incident = self._sensor_incident()
        self.assertIsNotNone(incident)
        self.assertEqual(incident["severity"], "HIGH")
        self.assertEqual(self._sensor_row()["consecutive_failures"], 3)

    def test_privileged_resolves_the_degraded_incident_honestly(self):
        # The pre-fix world: an incident accumulated by DEGRADED scans, then
        # acknowledged by the operator (incident #26's exact state).
        for i in range(3):
            self._health_pass("DEGRADED", NOW + i * 3600)
        incident = self._sensor_incident()
        self.assertTrue(aegis.transition_incident(
            incident["id"], "ACK", now=NOW + 4 * 3600))
        # First post-fix scan identifies the wall and closes the case.
        self._health_pass("PRIVILEGED", NOW + 5 * 3600)
        incident = self._sensor_incident()
        self.assertEqual(incident["status"], "RESOLVED")
        self.assertIn("privileged-only", incident["resolution"])

    def test_ok_recovery_resolution_is_unchanged(self):
        for i in range(3):
            self._health_pass("DEGRADED", NOW + i * 3600)
        self._health_pass("OK", NOW + 4 * 3600)
        incident = self._sensor_incident()
        self.assertEqual(incident["status"], "RESOLVED")
        self.assertEqual(incident["resolution"], "sensor recovered")
        self.assertEqual(self._sensor_row()["last_ok_at"], NOW + 4 * 3600)


class TestScanSurfacesSentinel(_Sandbox):
    def test_privileged_surface_yields_no_findings_and_no_adoption(self):
        saved = aegis.SURFACES
        aegis.SURFACES = [
            ("btm", lambda: aegis.SURFACE_PRIVILEGED,
             lambda prior, cur: [aegis.finding(
                 "HIGH", "btm", "fabricated", "must never appear", "btm:x")])]
        try:
            health = []
            findings, baseline = aegis._scan_surfaces(
                {}, corrupt=False, first_run=False, health=health)
        finally:
            aegis.SURFACES = saved
        self.assertEqual(findings, [])
        self.assertNotIn("btm", baseline)  # never adopted
        self.assertEqual(len(health), 1)
        self.assertEqual(health[0]["status"], "PRIVILEGED")
        self.assertIn("admin authorization", health[0]["detail"])


if __name__ == "__main__":
    unittest.main()
