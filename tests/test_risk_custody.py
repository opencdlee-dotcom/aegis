"""The risk tier must not launder custody demotions back into HIGH.

`_accumulate_risk` weighed each finding by severity x confidence x category
precision — no provenance term — and opened every incident at the string
literal "HIGH" regardless of score. So findings the custody grader had
individually demoted BELOW the notify floor, because it proved the operator
authored them, summed straight back into a HIGH interrupt. All four live risk
incidents were this shape: #309 was four findings Aegis itself graded "your
own git working tree" (worktree/local-commit), #310 was six package-managed
signals on Homebrew's syncthing, #305 three package-managed beacons on an
editor extension — severity laundering, the risk tier undoing the demotion
the custody tier just made.

Two changes pinned here: a custody factor in the weight (self-custody rungs
contribute nothing — a finding Aegis proved the operator authored must not
corroborate an attack; vouched/weak rungs are heavily discounted), and the
incident severity derived from the score instead of hardcoded.

Platform-independent by construction: findings built directly, recorded
through the real scan path.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import aegis                                    # noqa: E402
from test_regression import Sandbox                           # noqa: E402

P = "/Users/Shared/authored"


def _f(category, fp, sev="MEDIUM", custody=None, conf="medium"):
    kw = {"path": P, "confidence": conf}
    if custody:
        kw["custody"] = custody
    return aegis.finding(sev, category, "s", "d", fp, **kw)


class RiskDoesNotLaunderCustodyDemotions(Sandbox):
    def _risk(self):
        return [i for i in aegis.list_incidents()
                if i["title"].startswith("Accumulated risk")]

    def test_self_authored_findings_do_not_become_a_high_incident(self):
        """The #309 shape: four findings custody graded as the operator's own
        work, summed. BEFORE THE FIX: one incident, severity 'HIGH'."""
        aegis.record_security_state([
            _f("agent-surface", "as:%s:1" % P, custody="worktree"),
            _f("agent-surface", "as:%s:2" % P, custody="local-commit"),
            _f("agent-surface", "as:%s:3" % P, custody="self-committed"),
            _f("agent-surface", "as:%s:4" % P, custody="self-committed"),
        ])
        self.assertEqual([], self._risk(),
                         "findings Aegis proved the operator authored were "
                         "summed into a risk incident")

    def test_package_managed_findings_do_not_reach_threshold_alone(self):
        """The #310 shape: a package-manager artifact's beacon + process +
        outbound churn, every signal custody-vouched."""
        aegis.record_security_state([
            _f("net-beacon", "beacon:%s:10.0.0.1:443" % P,
               custody="package-managed"),
            _f("net-outbound", "outbound:%s" % P, custody="package-managed"),
            _f("process", "process:%s:adhoc:aaa" % P,
               custody="package-managed"),
            _f("net-beacon", "beacon:%s:10.0.0.1:8443" % P,
               custody="package-managed"),
        ])
        self.assertEqual([], self._risk(),
                         "an entirely custody-vouched pile opened a risk "
                         "incident")

    def test_ungraded_findings_still_accumulate_exactly_as_before(self):
        """The control: no custody field means no discount — the existing
        detection must not regress."""
        aegis.record_security_state([
            _f("hot-dir", "hd:%s" % P),
            _f("staging", "st:%s" % P),
            _f("behavior", "bh:%s" % P),
        ])
        self.assertEqual(1, len(self._risk()),
                         "ungraded corroboration regressed")

    def test_a_marginal_score_opens_below_high(self):
        """Severity now follows the score: barely past threshold is MEDIUM,
        not the string literal 'HIGH'."""
        aegis.record_security_state([
            _f("hot-dir", "hd:%s" % P),
            _f("staging", "st:%s" % P),
            _f("behavior", "bh:%s" % P),
        ])
        risk = self._risk()
        self.assertEqual(1, len(risk))
        self.assertNotEqual("HIGH", risk[0]["severity"],
                            "a marginal score still opens at hardcoded HIGH")

    def test_a_heavy_pile_still_opens_high(self):
        """The other pole: genuinely heavy corroboration keeps its urgency."""
        aegis.record_security_state([
            _f("hot-dir", "hd:%s" % P, sev="HIGH", conf="high"),
            _f("staging", "st:%s" % P, sev="HIGH", conf="high"),
            _f("behavior", "bh:%s" % P, sev="HIGH", conf="high"),
            _f("decoy", "dc:%s:x" % P, sev="CRITICAL", conf="high"),
        ])
        risk = self._risk()
        self.assertEqual(1, len(risk))
        self.assertEqual("HIGH", risk[0]["severity"])


class RiskCountsFactsNotChurn(Sandbox):
    """Distinct-signal counting must count FACTS, not churn.

    Two live incidents were volume defeating the discounts one axis at a
    time. #321: four of the operator's own shell commands each carried a
    below-floor MEDIUM and pooled on the history FILE they share — shared
    infrastructure exactly like the interpreters the entity join already
    refuses. #310: a Homebrew-receipted P2P daemon's peers vary address AND
    port by design, so the (program, port) recurrence fold minted one fresh
    distinct signal per PORT and score 11.3 walked straight through the 0.25
    custody discount. Neither pile was corroboration; each was one fact (or
    none) counted many times."""

    def _risk(self):
        return [i for i in aegis.list_incidents()
                if i["title"].startswith("Accumulated risk")]

    def test_shell_history_commands_never_pool_into_a_risk_incident(self):
        """The #321 shape: distinct benign commands are unrelated facts; the
        history file is the one entity they all share."""
        hist = "/Users/Shared/.bash_history"
        aegis.record_security_state([
            aegis.finding("MEDIUM", "shell-history",
                          "Hostile command in shell history", "d",
                          "shellhist:.bash_history:%016x" % n, path=hist)
            for n in range(4)])
        self.assertEqual([], self._risk(),
                         "unrelated commands summed on the history file")

    def test_receipted_p2p_port_churn_counts_once(self):
        """The #310 shape: many peer ports on one receipted program fold to
        one distinct signal, so churn alone can no longer out-volume the
        custody discount."""
        findings = [_f("net-beacon", "beacon:%s:10.0.0.%d:%d" % (P, n, port),
                       custody="package-managed")
                    for n, port in enumerate(
                        (22000, 22067, 33067, 49156, 50695, 54640,
                         57004, 57082, 61072, 62429), start=1)]
        findings.append(_f("process", "process:%s:adhoc:bbb" % P,
                           custody="package-managed"))
        aegis.record_security_state(findings)
        self.assertEqual([], self._risk(),
                         "a receipted program's peer-port churn accumulated "
                         "past the threshold")

    def test_unreceipted_port_churn_still_accumulates(self):
        """The control that keeps the C2 detection: a program with NO receipt
        rotating ports is exactly the shape the tier exists to catch."""
        aegis.record_security_state([
            _f("net-beacon", "beacon:%s:10.0.0.%d:%d" % (P, n, 22000 + n))
            for n in range(1, 11)])
        self.assertEqual(1, len(self._risk()),
                         "unreceipted port rotation no longer accumulates")

    def test_content_churn_on_one_fact_counts_once(self):
        """One subject re-observed at four content hashes is the same fact
        seen again — the operator's own file re-edited N times must not
        corroborate itself N times."""
        aegis.record_security_state([
            _f("process", "process:%s:adhoc:%s" % (P, ("%02x" % n) * 32))
            for n in range(4)])
        self.assertEqual([], self._risk(),
                         "re-edits of one subject counted as distinct signals")


if __name__ == "__main__":
    unittest.main()
