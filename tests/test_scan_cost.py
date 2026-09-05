"""Scan cost: the resource budget, measured per scan and judged in doctor.

Nothing in the repo stated an overhead ceiling before this; a monitor on a
daily-driver machine has one whether or not it is written down. What these
hold:

  * every scan records its wall and CPU (self + children) as a health row,
    so the history is durable per scan, not just the latest;
  * the summary is pure arithmetic: percentiles, mean, CPU share over the
    span, and it abstains below two samples;
  * doctor renders the line, and flags a share over SCAN_CPU_CEILING_PCT as
    a problem.
"""
import contextlib
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling import
import aegis  # noqa: E402
from test_regression import Sandbox, needs_real_scan_lock  # noqa: E402


class TestSummaryArithmetic(unittest.TestCase):
    def test_abstains_below_two_samples(self):
        self.assertIsNone(aegis._scan_cost_summary([]))
        self.assertIsNone(aegis._scan_cost_summary([(1000, 5000, 2000)]))

    def test_two_scans_in_one_second_are_a_window_not_an_abstention(self):
        # occurred_at is whole seconds, so two scans inside one of them used to
        # measure a zero span and abstain. Two samples is not "below two":
        # that read "no history yet" on every host fast enough to scan twice in
        # a second -- Linux CI did, macOS did not, from the same two scans --
        # and it muted the loudest reading there is. Two scans costing 2 s of
        # CPU inside a 1 s window are 200% of it, and doctor has to say so.
        s = aegis._scan_cost_summary([(1000, 5000, 1000), (1000, 5000, 1000)])
        self.assertIsNotNone(s)
        self.assertEqual(2, s["scans"])
        self.assertAlmostEqual(200.0, s["share_pct"])
        self.assertGreater(s["share_pct"], aegis.SCAN_CPU_CEILING_PCT)

    def test_percentiles_mean_and_share(self):
        # Ten hourly scans, 4 s wall each except one 10 s outlier, 1.8 s CPU
        # each: 18 s of CPU over 9 hours.
        samples = [(3600 * i, 4000 if i else 10000, 1800) for i in range(10)]
        s = aegis._scan_cost_summary(samples)
        self.assertEqual(10, s["scans"])
        self.assertEqual(4.0, s["wall_p50_s"])
        self.assertEqual(10.0, s["wall_p95_s"])
        self.assertAlmostEqual(1.8, s["cpu_mean_s"])
        self.assertAlmostEqual(9.0, s["span_h"])
        self.assertAlmostEqual(100.0 * 18 / (9 * 3600), s["share_pct"])
        self.assertLess(s["share_pct"], aegis.SCAN_CPU_CEILING_PCT)

    def test_share_is_order_independent(self):
        a = [(0, 1000, 500), (60, 1000, 500)]
        self.assertEqual(aegis._scan_cost_summary(a),
                         aegis._scan_cost_summary(list(reversed(a))))

    def test_a_hot_loop_breaches_the_ceiling(self):
        # Scans every 60 s each burning 1 s of CPU: 1.67%.
        s = aegis._scan_cost_summary([(60 * i, 5000, 1000) for i in range(5)])
        self.assertGreater(s["share_pct"], aegis.SCAN_CPU_CEILING_PCT)


@needs_real_scan_lock
class TestScanRecordsItsCost(Sandbox):
    def test_health_row_and_durable_sample(self):
        aegis.cmd_scan(quiet=True)
        row = {r["sensor_id"]: r for r in aegis.get_sensor_health()}["scan.cost"]
        self.assertEqual("OK", row["status"])
        self.assertGreater(row["duration_ms"], 0)
        self.assertGreater(row["item_count"], 0, "children CPU not counted")
        samples = aegis._scan_cost_samples()
        self.assertEqual(1, len(samples))
        self.assertEqual((row["duration_ms"], row["item_count"]), samples[0][1:])

    def test_doctor_renders_the_line(self):
        aegis.cmd_scan(quiet=True)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            aegis.cmd_doctor()
        self.assertIn("scan cost", out.getvalue())
        self.assertIn("no history yet", out.getvalue())
        aegis.cmd_scan(quiet=True)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            aegis.cmd_doctor()
        text = out.getvalue()
        line = [l for l in text.splitlines() if "scan cost" in l][0]
        self.assertIn("ceiling", line)
        self.assertIn("over 2 scans", line)
        # Deliberately no verdict assertion here -- see the next test.

    def test_doctor_flags_a_breach_rather_than_reading_green(self):
        """The rendering above can be driven by real scans; the VERDICT cannot.

        This assertion used to read "two scans seconds apart is a hot loop by
        construction, so the share is over the ceiling". That is only true on a
        fast host. On a slow one two back-to-back scans are wall-EXPENSIVE and
        cpu-CHEAP, so the share is tiny and the line honestly reads green:
        Windows CI measured wall p50 199.1s against cpu 0.1s/scan, 0.06% of the
        window, and the old assertion called that correct answer a failure.

        A verdict pinned to measured host speed is not pinned to anything. The
        breach is asserted on samples whose ratio is STATED.
        """
        # 5 s of CPU across a 240 s span = 2.08%, over the 1% ceiling.
        hot = [(60 * i, 5000, 1000) for i in range(5)]
        real = aegis._scan_cost_samples
        aegis._scan_cost_samples = lambda *a, **k: hot
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                aegis.cmd_doctor()
        finally:
            aegis._scan_cost_samples = real
        line = [l for l in out.getvalue().splitlines() if "scan cost" in l][0]
        self.assertTrue(line.strip().startswith("?"), line)
        self.assertIn("ceiling", line)


if __name__ == "__main__":
    unittest.main()
