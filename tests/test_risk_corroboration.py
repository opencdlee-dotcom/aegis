"""Corroboration means distinct SENSORS, not distinct category strings.

`_accumulate_risk` granted the cross-sensor bonus (min_signals 3 -> 2, score
x1.5) whenever two CATEGORY strings met on one entity — but findings carry no
sensor name, and two registry sensors emit multiple categories each:
check_outbound emits both `net-outbound` and `net-beacon`, check_hardening
emits both `hardening` and `coverage`. One sensor could therefore corroborate
itself: the same code path observing the same socket twice bought the
higher-precision bonus that exists (per Splunk RBA, cited in the source) for
evidence from INDEPENDENT sources. Live harm was cosmetic (#310's title said
"3 sensors" where the true count was 2), but the lowered bar is latent scoring
inflation: two findings from one sensor could open a risk incident on their
own.

Platform-independent by construction: findings built directly, recorded
through the real scan path.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import aegis                                    # noqa: E402
from test_regression import Sandbox                           # noqa: E402

P = "/Users/Shared/onebinary"


def _f(category, fp, sev="MEDIUM"):
    return aegis.finding(sev, category, "s", "d", fp, path=P,
                         confidence="medium")


class OneSensorCannotCorroborateItself(Sandbox):
    def _risk(self):
        return [i for i in aegis.list_incidents()
                if i["title"].startswith("Accumulated risk")]

    def test_two_categories_from_the_outbound_sensor_do_not_corroborate(self):
        """net-outbound + net-beacon are one sensor observing one socket.
        BEFORE THE FIX: multi=True -> min_signals 2, x1.5 -> 2.8 becomes 4.2
        and an incident opens on self-corroboration alone."""
        aegis.record_security_state([
            _f("net-outbound", "outbound:%s" % P),
            _f("net-beacon", "beacon:%s:10.0.0.1:443" % P),
        ])
        self.assertEqual([], self._risk(),
                         "one sensor's two category strings bought the "
                         "cross-sensor corroboration bonus")

    def test_two_genuinely_distinct_sensors_still_corroborate(self):
        """The control: process + net-outbound are separate registry sensors;
        the exact same weights must still open an incident."""
        aegis.record_security_state([
            _f("process", "process:%s:adhoc:aaa" % P),
            _f("net-outbound", "outbound:%s" % P),
        ])
        self.assertEqual(1, len(self._risk()),
                         "real cross-sensor corroboration regressed")

    def test_the_title_counts_sensors_not_categories(self):
        """#310 read '6 signals across 3 sensors' with two sensors behind it.
        The rendered count must be the grouped one."""
        aegis.record_security_state([
            _f("process", "process:%s:adhoc:aaa" % P),
            _f("net-outbound", "outbound:%s" % P),
            _f("net-beacon", "beacon:%s:10.0.0.1:443" % P),
        ])
        risk = self._risk()
        self.assertEqual(1, len(risk))
        self.assertIn("across 2 sensors", risk[0]["title"],
                      "the title still counts category strings: %r"
                      % risk[0]["title"])


if __name__ == "__main__":
    unittest.main()
