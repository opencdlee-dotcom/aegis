"""An incident whose own signal was re-graded down needs an exit.

Found live as the single largest source of queue noise: five of fifteen open
incidents sat at HIGH while their own `signals` rows read LOW or MEDIUM —
custody had re-graded the findings days earlier (intent records landed, the
worktree was recognized), and the incident could not follow them down. The
severity ratchet is a DOCUMENTED invariant (ARCHITECTURE.md: "de-escalation
is the operator's verdict to give, not custody's") and stays: nothing here
quietly lowers a severity. But the design already has a machine exit —
age-out closes an incident that ran out of news, as FALSE_POSITIVE, visibly,
reopenable. The re-grade close is the same exit made evidence-driven instead
of clock-driven: when the LATEST word on a signal is a sub-HIGH re-grade, the
OPEN incident closes with an explicit "re-graded" resolution instead of
waiting seven days for the age-out clock.

Same discipline as age-out, pinned here: no dismissals row (a machine verdict
must never feed backtest precision or acquired tolerance), CRITICAL never
closes this way, never-tolerate prefixes are skipped, and the stored severity
is untouched — the ratchet holds even in the closing record.

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
FP = "agent-surface:newexec:/u/.codex/hooks.json:runner|aaaaaaaaaaaa"


def _f(sev):
    return aegis.finding(sev, "agent-surface", "New agent exec entry", "d",
                         FP, path="/u/.codex/hooks.json")


class ARegradedIncidentCloses(Sandbox):
    def _row(self):
        db = aegis._event_connection()
        try:
            return dict(db.execute(
                "SELECT * FROM incidents WHERE correlation_key=?",
                ("signal:" + FP,)).fetchone())
        finally:
            db.close()

    def test_a_sub_high_regrade_closes_the_open_incident(self):
        aegis.record_security_state([_f("HIGH")], now=T0)
        self.assertEqual("OPEN", self._row()["status"])
        aegis.record_security_state([_f("LOW")], now=T0 + 60)
        row = self._row()
        # BEFORE THE FIX: OPEN at HIGH forever, exit only by 7-day age-out.
        self.assertEqual("FALSE_POSITIVE", row["status"],
                         "the incident could not follow its own signal down")
        self.assertIn("re-graded", row["resolution"] or "",
                      "the closure does not say WHY: %r" % row["resolution"])

    def test_the_ratchet_still_holds_on_the_closing_record(self):
        """Nothing quietly lowers a severity — the invariant survives."""
        aegis.record_security_state([_f("HIGH")], now=T0)
        aegis.record_security_state([_f("LOW")], now=T0 + 60)
        self.assertEqual("HIGH", self._row()["severity"],
                         "the machine exit rewrote the severity the operator "
                         "was shown")

    def test_no_dismissals_row_is_written(self):
        """A machine verdict must never feed precision or tolerance — the
        same discipline age-out and _auto_tolerate hold."""
        aegis.record_security_state([_f("HIGH")], now=T0)
        aegis.record_security_state([_f("LOW")], now=T0 + 60)
        db = aegis._event_connection()
        try:
            n = db.execute("SELECT COUNT(*) FROM dismissals").fetchone()[0]
        finally:
            db.close()
        self.assertEqual(0, n)

    def test_critical_never_closes_this_way(self):
        crit = aegis.finding("CRITICAL", "behavior", "phish", "d",
                             "behavior:osascript:phish:x")
        aegis.record_security_state([crit], now=T0)
        demoted = aegis.finding("LOW", "behavior", "phish", "d",
                                "behavior:osascript:phish:x")
        aegis.record_security_state([demoted], now=T0 + 60)
        db = aegis._event_connection()
        try:
            status = db.execute(
                "SELECT status FROM incidents WHERE correlation_key=?",
                ("signal:behavior:osascript:phish:x",)).fetchone()["status"]
        finally:
            db.close()
        self.assertEqual("OPEN", status,
                         "a CRITICAL was machine-closed on a re-grade")

    def test_a_still_high_signal_stays_open(self):
        """The control: no re-grade, no exit."""
        aegis.record_security_state([_f("HIGH")], now=T0)
        aegis.record_security_state([_f("HIGH")], now=T0 + 60)
        self.assertEqual("OPEN", self._row()["status"])


if __name__ == "__main__":
    unittest.main()
