"""The precision feedback loop must divide incidents by incidents.

`_category_dismissal_weights` computes per-category precision as
1 - dismissed/total — but `dismissed` counts one row per dismissed INCIDENT
while `opened` counted `COUNT(*)` over incidents ⋈ incident_events ⋈ events,
which fans out to one row per EVIDENCE EVENT. A sensor that re-emits one fact
on every scan (the exact failure mode this loop exists to damp) inflates only
the denominator, so the operator's dismissals barely register. Measured live:
23 of 28 risk incidents dismissed, and the loop applied a 1-2% discount
(persistence 0.9864, process 0.9771 — unit-matched they are 0.25).

The sharp edge: the same scan path already KNOWS re-emissions are duplicates —
`_accumulate_risk` dedupes fingerprints when scoring — so Aegis counted a
re-emitted finding once when scoring it and N times when deciding how much to
trust the sensor that produced it.

Why the existing test never caught this: it inserts dismissals with no
incidents at all, so `opened` is 0 and the `max(opened, dismissed)` fallback
yields the floor — the exact value a CORRECT implementation produces. These
tests populate incidents + incident_events + events, which is the only shape
that can tell the two implementations apart.

Platform-independent by construction: pure SQLite through the real schema.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import aegis                                    # noqa: E402
from test_regression import Sandbox                           # noqa: E402

NOW = 1_700_000_000


def _incident_with_evidence(db, category, n_events, created_at,
                            dismissed=True, dismissed_at=None):
    """One incident carrying `n_events` evidence rows of `category`."""
    with db:
        cur = db.execute(
            "INSERT INTO incidents(kind,correlation_key,title,severity,status,"
            "created_at,first_seen,last_seen,updated_at,reminder_count) "
            "VALUES('signal',?,?,?,?,?,?,?,?,0)",
            ("signal:%s:%d" % (category, created_at), "t", "HIGH",
             "FALSE_POSITIVE" if dismissed else "OPEN",
             created_at, created_at, created_at,
             dismissed_at or created_at))
        iid = cur.lastrowid
        for i in range(n_events):
            ev = db.execute(
                "INSERT INTO events(occurred_at,observed_at,source,event_type,"
                "data_json) VALUES(?,?,?,?,?)",
                (created_at + i, created_at + i, category, "finding",
                 '{"category": "%s"}' % category)).lastrowid
            db.execute("INSERT INTO incident_events(incident_id,event_id) "
                       "VALUES(?,?)", (iid, ev))
        if dismissed:
            db.execute(
                "INSERT INTO dismissals(incident_id,correlation_key,"
                "reason_code,category,dismissed_at) VALUES(?,?,?,?,?)",
                (iid, "k%d" % iid, "benign-positive", category,
                 dismissed_at or created_at))
    return iid


class PrecisionCountsIncidentsNotEventRows(Sandbox):
    def test_re_emission_does_not_neutralize_the_operators_dismissals(self):
        """5 of 5 incidents dismissed = precision 0, whatever the sensor's
        re-emission volume. BEFORE THE FIX: 5 dismissals divided by 200
        evidence rows -> a ~2% discount on a sensor the operator rejects
        every single time."""
        db = aegis._event_connection()
        try:
            for k in range(5):
                _incident_with_evidence(db, "persistence", 40,
                                        NOW - 1000 - k)
            w = aegis._category_dismissal_weights(db, NOW)
        finally:
            db.close()
        self.assertIn("persistence", w)
        self.assertLessEqual(
            w["persistence"], 0.3,
            "5 of 5 incidents dismissed and the loop barely moved: %r" % w)

    def test_a_genuinely_precise_sensor_keeps_its_weight(self):
        """The control: 1 dismissal out of 5 incidents is a precise sensor
        (dismissed < _PRECISION_MIN_SAMPLE keeps it unmuted entirely)."""
        db = aegis._event_connection()
        try:
            _incident_with_evidence(db, "behavior", 10, NOW - 1000,
                                    dismissed=True)
            for k in range(4):
                _incident_with_evidence(db, "behavior", 10, NOW - 900 - k,
                                        dismissed=False)
            w = aegis._category_dismissal_weights(db, NOW)
        finally:
            db.close()
        self.assertNotIn("behavior", w,
                         "one dismissal in five must not mute a sensor")

    def test_mixed_verdicts_scale_between_floor_and_one(self):
        """4 dismissed of 8 opened = precision 0.5, not floor, not ~1.0."""
        db = aegis._event_connection()
        try:
            for k in range(4):
                _incident_with_evidence(db, "hot-dir", 25, NOW - 1000 - k,
                                        dismissed=True)
            for k in range(4):
                _incident_with_evidence(db, "hot-dir", 25, NOW - 800 - k,
                                        dismissed=False)
            w = aegis._category_dismissal_weights(db, NOW)
        finally:
            db.close()
        self.assertAlmostEqual(0.5, w["hot-dir"], places=2)

    def test_dismissed_inside_the_window_counts_opened_outside_it(self):
        """An incident opened before the window but dismissed inside it must
        appear in BOTH sides of the ratio, or old queues read as pure noise
        the moment the operator finally triages them."""
        window = 90 * 86400
        db = aegis._event_connection()
        try:
            # 4 old incidents, opened before the window, dismissed today.
            for k in range(4):
                _incident_with_evidence(db, "staging", 10,
                                        NOW - window - 5000 - k,
                                        dismissed=True, dismissed_at=NOW - 10)
            # 4 recent ones the operator left open — a working sensor.
            for k in range(4):
                _incident_with_evidence(db, "staging", 10, NOW - 900 - k,
                                        dismissed=False)
            w = aegis._category_dismissal_weights(db, NOW)
        finally:
            db.close()
        self.assertAlmostEqual(
            0.5, w["staging"], places=2,
            msg="incidents dismissed in-window but opened out-of-window were "
                "counted against the sensor without being counted for it")


if __name__ == "__main__":
    unittest.main()
