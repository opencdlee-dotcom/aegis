"""A persisting condition is one fact with a count, not an event per scan.

Found live: `record_security_state` minted one `events` row per finding per
scan unconditionally, so a condition that stayed true — an open incident's own
unchanged signal — accumulated 41-177 byte-identical evidence rows (#313: 41
"new entry" events for a fact that was new exactly once; #310: 177). The
correct counter has existed all along: `signals.occurrence_count` increments
on every conflict — and nothing read it. The duplicate rows were pure cost:
they burned the 50k retention budget (~28 days at the observed rate, the
pressure behind the prune cascade), inflated the precision denominator, and
buried real evidence in the incident view.

The dedup is deliberately narrow: an observation is folded into its count
ONLY when an ACTIVE incident already holds evidence for the same signal at
the same severity. A severity change still mints a row (a custody re-grade is
exactly the news the incident needs); a judged incident's recurrence still
attaches as durable evidence (the reattach contract pinned in
test_regression.py is unchanged); and a finding with no incident keeps its
per-scan record (bounded by the retention cap, which no longer touches
referenced evidence).

Platform-independent by construction: findings built directly, recorded
through the real scan path.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import aegis                                    # noqa: E402
from test_regression import Sandbox                           # noqa: E402

T0 = 1_700_000_000


def _f(sev="HIGH"):
    return aegis.finding(sev, "hardening", "standing gap", "d",
                         "hardening:standing:gap")


class APersistingConditionIsRecordedOnce(Sandbox):
    def _counts(self):
        db = aegis._event_connection()
        try:
            rows = db.execute(
                "SELECT COUNT(*) FROM incident_events").fetchone()[0]
            occ = db.execute(
                "SELECT occurrence_count FROM signals").fetchone()[0]
        finally:
            db.close()
        return rows, occ

    def test_four_scans_of_one_unchanged_fact_yield_one_evidence_row(self):
        for i in range(4):
            aegis.record_security_state([_f()], now=T0 + i * 60)
        rows, occ = self._counts()
        self.assertEqual(4, occ, "the recurrence counter must still count")
        # BEFORE THE FIX: 4 rows — one byte-identical event per scan.
        self.assertEqual(1, rows,
                         "an unchanged still-true fact minted an evidence "
                         "row per scan")

    def test_a_severity_change_still_mints_a_row(self):
        """The D4 hook: a re-graded observation must REACH the incident."""
        aegis.record_security_state([_f("HIGH")], now=T0)
        aegis.record_security_state([_f("HIGH")], now=T0 + 60)   # folded
        aegis.record_security_state([_f("MEDIUM")], now=T0 + 120)  # news!
        rows, _occ = self._counts()
        self.assertEqual(2, rows,
                         "a severity change was folded into the count "
                         "instead of reaching the incident")

    def test_the_incident_view_reports_the_count(self):
        """The counter finally gets a reader: the honest statement of #313 is
        'seen 41 times since <date>', not 41 identical evidence lines."""
        for i in range(3):
            aegis.record_security_state([_f()], now=T0 + i * 60)
        inc = aegis.list_incidents()[0]
        detail = aegis.incident_detail(inc["id"])
        self.assertEqual(3, detail.get("occurrences"),
                         "incident_detail does not surface the recurrence "
                         "count")

    def test_a_distinct_signal_on_the_same_incident_still_records(self):
        """Only IDENTICAL signals fold; different fingerprints keep rows."""
        a = aegis.finding("HIGH", "hardening", "gap a", "d", "hardening:a")
        b = aegis.finding("HIGH", "hardening", "gap b", "d", "hardening:b")
        aegis.record_security_state([a], now=T0)
        aegis.record_security_state([a, b], now=T0 + 60)
        db = aegis._event_connection()
        try:
            rows = db.execute("SELECT COUNT(*) FROM events WHERE "
                              "event_type='observation.finding'").fetchone()[0]
        finally:
            db.close()
        self.assertEqual(2, rows)


if __name__ == "__main__":
    unittest.main()
