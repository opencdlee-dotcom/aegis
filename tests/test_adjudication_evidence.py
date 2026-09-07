#!/usr/bin/env python3
"""An incident an operator cannot close on evidence stays open forever.

`behavior` and `shell-history` deliberately store a command sha256 and never
the argv, so once the process exits the command text is gone by design. Before
this change the incident card printed only the finding title, which meant those
incidents could not be adjudicated by ANYONE from stored state -- not a wrong
detection, a permanent one, and the most expensive false-alarm class there is.
Verified against live incident #347 (opened 2026-09-04, still OPEN 2026-09-06)
whose command matched no line in either shell history, because an argv-sensor
hit is a spawned /bin/bash, never an interactive history entry.

The evidence needed was already recorded on every finding -- the human-presence
regime, idle seconds, lock state, program and pid -- and was simply discarded
at render time. These tests pin that it reaches the operator, and that it stays
EVIDENCE rather than becoming a verdict.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling import
import aegis  # noqa: E402
from test_regression import Sandbox  # noqa: E402


class TestAdjudicationEvidence(Sandbox):
    def _incident(self, **attrs):
        """One incident per presence regime, looked up by its OWN key.

        list_incidents()[0] is not necessarily the newest case, so reusing it
        across regimes silently re-reads the first incident and makes the
        discrimination test pass against identical inputs."""
        fingerprint = "adj-%s" % attrs.get("presence", "none")
        aegis.record_security_state([aegis.finding(
            "HIGH", "behavior", "Suspicious process behavior", "d",
            fingerprint, path="/Users/Shared/t.bin", **attrs)])
        db = aegis._event_connection()
        try:
            return db.execute("SELECT id FROM incidents WHERE correlation_key=?",
                              ("signal:%s" % fingerprint,)).fetchone()["id"]
        finally:
            db.close()

    def test_presence_evidence_reaches_the_incident_card(self):
        inc = self._incident(presence="PRESENT-ACTIVE", idle_secs=0,
                             screen_locked=False, program="/bin/bash",
                             pid="97501")
        notes = aegis._adjudication_notes(aegis.incident_detail(inc))
        self.assertTrue(notes, "presence evidence was recorded but not rendered")
        joined = " ".join(notes)
        self.assertIn("keyboard", joined)
        self.assertIn("idle 0s", joined)
        self.assertIn("unlocked", joined)
        self.assertIn("97501", joined)

    def test_unattended_regime_reads_differently_from_attended(self):
        """The whole point is discrimination: 'nobody was there' must not
        render the same as 'I was sitting right here'."""
        attended = aegis._adjudication_notes(aegis.incident_detail(
            self._incident(presence="PRESENT-ACTIVE", idle_secs=0)))
        absent = aegis._adjudication_notes(aegis.incident_detail(
            self._incident(presence="ABSENT", idle_secs=3600)))
        self.assertTrue(attended and absent)
        self.assertNotEqual(attended[0], absent[0])
        self.assertIn("NO ONE", absent[0])

    def test_locked_screen_is_stated_as_such(self):
        notes = aegis._adjudication_notes(aegis.incident_detail(
            self._incident(presence="LOCKED", screen_locked=True)))
        self.assertIn("LOCKED", notes[0])

    def test_no_presence_recorded_renders_nothing(self):
        """A finding with no presence stamp must not invent one -- an absent
        probe answer is never rendered as a regime."""
        self.assertEqual(
            aegis._adjudication_notes(aegis.incident_detail(self._incident())),
            [])

    def test_unknown_regime_is_reported_verbatim_not_guessed(self):
        notes = aegis._adjudication_notes(aegis.incident_detail(
            self._incident(presence="unknown")))
        self.assertTrue(notes)
        self.assertIn("unknown", notes[0])
        for claim in ("someone was at the keyboard", "NO ONE"):
            self.assertNotIn(claim, notes[0])

    def test_evidence_never_becomes_a_verdict(self):
        """Presence may enrich the card and must never move the incident.
        Same-uid code can forge idle time (`caffeinate -u`), so a rendering
        that decided severity or status would be a remote control."""
        for regime in ("PRESENT-ACTIVE", "ABSENT", "LOCKED"):
            with self.subTest(regime=regime):
                inc = self._incident(presence=regime, idle_secs=0)
                detail = aegis.incident_detail(inc)
                before = (detail["severity"], detail["status"])
                aegis._adjudication_notes(detail)
                after = aegis.incident_detail(inc)
                self.assertEqual((after["severity"], after["status"]), before)


if __name__ == "__main__":
    unittest.main()
