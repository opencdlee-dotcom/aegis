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


if __name__ == "__main__":
    unittest.main()
