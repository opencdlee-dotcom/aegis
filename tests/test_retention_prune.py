"""The retention prune must not revoke the operator's verdicts.

Found live: the 50,000-event cap (`record_security_state`) deletes raw
observations — and `incident_events.event_id REFERENCES events(id) ON DELETE
CASCADE` with `PRAGMA foreign_keys=ON` means it deletes each old incident's
EVIDENCE with them. `_incident_identities` reads an incident's memory through
an INNER JOIN on `events`, so a stripped incident remembers nothing;
`_carries_new_evidence(anything, ∅)` answered True; and that True forced the
FALSE_POSITIVE reattach guard to refuse, re-opening the judged case as a fresh
HIGH. The deadlock is permanent: reattach is the only path back into a
dismissed incident, and `held` stays empty forever. On the reference store the
cascade had already stripped 59 adjudicated incidents (ids 30112..80111 were
all that survived of 80111 events, with zero dangling links — arithmetic proof
the cascade fired rather than orphaning).

The comment on the prune states its own contract — "Bound raw observations
while retaining materialized signals/incidents" — and evidence attached to an
incident is materialized state, not a raw observation.

Platform-independent by construction: pure SQLite through the real schema and
the real scan entry point; no platform vocabulary anywhere.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import aegis                                    # noqa: E402
from test_regression import Sandbox                           # noqa: E402

P = "/Users/Shared/prunable"
T0 = 1_700_000_000


def _three_sensor_pile(ip="10.0.0.1"):
    """Three distinct sensors on one entity — the shape risk accumulation
    exists for, borrowed from test_recurrence_identity."""
    return [
        aegis.finding("MEDIUM", "net-beacon", "periodic connection", "d",
                      "beacon:%s:%s:443" % (P, ip), path=P,
                      confidence="medium",
                      subject=aegis._subject("beacon", P, ip=ip, port="443")),
        aegis.finding("MEDIUM", "process", "exec", "d",
                      "process:%s:adhoc:aaa" % P, path=P),
        aegis.finding("MEDIUM", "net-outbound", "out", "d",
                      "outbound:%s" % P, path=P),
    ]


def _flood_events(db, n, start_at):
    """Raw unreferenced observations — the traffic the cap exists to bound."""
    with db:
        db.executemany(
            "INSERT INTO events(occurred_at,observed_at,source,event_type,"
            "data_json) VALUES(?,?,?,?,?)",
            [(start_at + i, start_at + i, "filler", "observation", "{}")
             for i in range(n)])


class EmptyMemoryIsNotNovelty(unittest.TestCase):
    def test_empty_held_is_not_read_as_new_evidence(self):
        """'I have no idea what I have seen' must decline to reopen a judged
        case (and must not refresh last_novel_at forever). The existing suite
        tests empty INCOMING; this is empty HELD, which is what a pruned
        incident presents."""
        self.assertFalse(
            aegis._carries_new_evidence({"signal:x"}, set()),
            "an incident stripped of its memory claimed everything is novel")


class PrunedEvidenceDoesNotRevokeAVerdict(Sandbox):
    def _active_risk(self):
        return [i for i in aegis.list_incidents()
                if i["title"].startswith("Accumulated risk")
                and i.get("status") != "FALSE_POSITIVE"]

    def test_a_dismissed_incident_survives_the_retention_prune(self):
        # 1. A real incident, judged by the operator.
        aegis.record_security_state(_three_sensor_pile(), now=T0)
        risk = self._active_risk()
        self.assertEqual(1, len(risk), "setup: three sensors should escalate")
        iid = risk[0]["id"]
        aegis.transition_incident(iid, "FALSE_POSITIVE",
                                  reason_code="benign-positive")

        # 2. 50k raw observations later, the cap fires (inside the real scan
        #    recording path, exactly where production runs it).
        db = aegis._event_connection()
        try:
            _flood_events(db, 50_001, T0 + 100)
        finally:
            db.close()
        aegis.record_security_state([], now=T0 + 60_000)

        # 3. The judged incident must still remember what it judged.
        db = aegis._event_connection()
        try:
            held = aegis._incident_identities(db, iid)
        finally:
            db.close()
        # BEFORE THE FIX: ∅ — the FK cascade took the evidence with the events.
        self.assertTrue(held,
                        "the prune erased the incident's memory of what "
                        "the operator judged")

        # 4. And the same fact re-observed must reattach, not reopen.
        aegis.record_security_state(_three_sensor_pile("10.0.0.2"),
                                    now=T0 + 61_000)
        self.assertEqual([], self._active_risk(),
                         "a judged case re-opened as a fresh incident after "
                         "the prune stripped its evidence")

    def test_unreferenced_observations_are_still_bounded(self):
        """The cap must keep doing its actual job on raw observations."""
        db = aegis._event_connection()
        try:
            _flood_events(db, 50_500, T0)
        finally:
            db.close()
        aegis.record_security_state([], now=T0 + 60_000)
        db = aegis._event_connection()
        try:
            n = db.execute(
                "SELECT COUNT(*) FROM events WHERE source='filler'"
            ).fetchone()[0]
        finally:
            db.close()
        self.assertLessEqual(n, 50_000,
                             "the retention cap stopped bounding raw events")


if __name__ == "__main__":
    unittest.main()
