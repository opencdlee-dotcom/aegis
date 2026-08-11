#!/usr/bin/env python3
"""Beacon-shape outbound recurrence — regression suite.

Outbound cannot be baseline-diffed (a browser opens hundreds of ephemeral
connections per scan), so check_outbound scores live rows per-scan only.
Recurrence keys on a different invariant: the same (binary, remote ip:port)
pair re-observed across many distinct scans is the residue an interval C2
beacon leaves and browser churn does not. These tests pin both poles — a
recurring untrusted pair fires HIGH exactly once at the incident level;
browsers, trusted-prefix binaries, and below-threshold recurrence stay
silent — and that the live per-scan scoring is unregressed.

Fully sandboxed via the test_regression Sandbox base: never touches real
~/.aegis, never fires a desktop notification. Stdlib-only.

Run:  python3 -m unittest discover -s tests        (from the repo root)
  or: python3 tests/test_beacon.py
"""
import gzip
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling import
import aegis  # noqa: E402
from test_regression import Sandbox  # noqa: E402


def history(row, count, step=1800, base=1_700_000_000):
    """`count` stored scan snapshots each containing `row`, `step` secs apart."""
    return [(base + i * step, [list(row)]) for i in range(count)]


class BeaconSandbox(Sandbox):
    def setUp(self):
        super().setUp()
        # The sandbox tmp dir stands in for a user-writable drop path on every
        # platform (mirrors TestOutbound), saved/restored so nothing leaks.
        self._saved.setdefault("RISKY_PREFIXES", aegis.RISKY_PREFIXES)
        aegis.RISKY_PREFIXES = tuple(set(aegis.RISKY_PREFIXES) | {self.tmp})
        self.payload = os.path.join(self.tmp, "payload")
        # (path, remote_ip, remote_port, trust) — trust "unsigned" is
        # suspicious on mac/win; the risky-location arm covers Linux.
        self.row = (self.payload, "45.94.47.145", "8443", "unsigned")


class TestBeaconRecurrence(BeaconSandbox):
    def test_recurring_untrusted_pair_fires_high(self):
        # 3 distinct scans spanning 60 minutes, pair still live this scan.
        hist = history(self.row, 3)
        fs = aegis._beacon_recurrence(hist, [self.row])
        self.assertEqual(len(fs), 1)
        f = fs[0]
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["fingerprint"],
                         "beacon:%s:45.94.47.145:8443" % self.payload)
        # Scan count, span and endpoint must all be in the detail.
        self.assertIn("3 scan", f["detail"])
        self.assertIn("45.94.47.145:8443", f["detail"])

    def test_fires_once_at_incident_level_and_does_not_restorm(self):
        hist = history(self.row, 3)
        first = aegis._beacon_recurrence(hist, [self.row])
        self.assertEqual(len(aegis.emit(first, first_run=False)), 1)
        self.assertEqual(len(self.notifications), 1)
        # The pair keeps recurring on later scans: identical fingerprint, so
        # the seen/signal machinery dedups — no second notification, ever.
        hist += history(self.row, 2, base=1_700_000_000 + 3 * 1800)
        again = aegis._beacon_recurrence(hist, [self.row])
        self.assertEqual(again[0]["fingerprint"], first[0]["fingerprint"])
        self.assertEqual(aegis.emit(again, first_run=False), [])
        self.assertEqual(len(self.notifications), 1)

    def test_browser_recurring_forever_stays_silent(self):
        # Browsers hold long-lived remote pairs legitimately — silent by NAME,
        # even unsigned in a user-writable path (where the trust gates alone
        # would have fired), and helper processes count as the browser too.
        for name in ("Google Chrome", "Google Chrome Helper (Network)",
                     "chrome.exe", "firefox", "Brave Browser Helper"):
            row = (os.path.join(self.tmp, name), "45.94.47.145", "8443",
                   "unsigned")
            hist = history(row, 12)  # far past every threshold
            self.assertEqual(aegis._beacon_recurrence(hist, [row]), [],
                             "browser %r must stay silent" % name)

    def test_trusted_prefix_binary_stays_silent(self):
        path = aegis.TRUSTED_PREFIXES[0] + "beacond"
        # trust "broken" is suspicious on every platform, so only the
        # trusted-prefix gate keeps this silent.
        row = (path, "45.94.47.145", "8443", "broken")
        self.assertEqual(aegis._beacon_recurrence(history(row, 6), [row]), [])

    def test_below_threshold_recurrence_stays_silent(self):
        # Two scans only — even spanning hours.
        two = history(self.row, 2, step=7200)
        self.assertEqual(aegis._beacon_recurrence(two, [self.row]), [])
        # Three scans but a span under 45 minutes.
        tight = history(self.row, 3, step=600)
        self.assertEqual(aegis._beacon_recurrence(tight, [self.row]), [])

    def test_pair_gone_from_current_scan_stays_silent(self):
        # History satisfies the thresholds but the pair is no longer live —
        # nothing to report as a persistent connection.
        hist = history(self.row, 5)
        self.assertEqual(aegis._beacon_recurrence(hist, []), [])

    def test_unvouchable_relative_comm_stays_silent(self):
        # A row whose path never resolved (bare comm name) can't be graded —
        # neither trust arm can vouch against it, so it must not fire.
        row = ("claude", "45.94.47.145", "8443", "unknown")
        self.assertEqual(aegis._beacon_recurrence(history(row, 6), [row]), [])


class TestBeaconThroughCheckOutbound(BeaconSandbox):
    def _stub_platform(self):
        self._saved.setdefault("_outbound_rows", aegis._outbound_rows)
        aegis._outbound_rows = lambda: [(self.payload, "45.94.47.145", "8443")]
        self._saved.setdefault("classify_signature", aegis.classify_signature)
        aegis.classify_signature = lambda p: {
            "trust": "unsigned", "team": None, "authority": None}

    def _seed_observation(self, age_secs, rows):
        os.makedirs(aegis.OBSERVATIONS_DIR, mode=0o700, exist_ok=True)
        name = "outbound.snapshot.%d.json.gz" % (int(time.time()) - age_secs)
        with gzip.open(os.path.join(aegis.OBSERVATIONS_DIR, name), "wb") as f:
            f.write(json.dumps(rows).encode("utf-8"))

    def test_scan_records_rows_and_flags_recurrence(self):
        self._stub_platform()
        stored = [list(self.row)]
        self._seed_observation(3000, stored)   # 50 minutes ago
        self._seed_observation(1500, stored)   # 25 minutes ago
        fs = aegis.check_outbound()
        beacons = [f for f in fs if f["fingerprint"].startswith("beacon:")]
        self.assertEqual(len(beacons), 1)
        self.assertEqual(beacons[0]["severity"], "HIGH")
        # Live per-scan scoring is unregressed: the MEDIUM outbound finding
        # keeps its original fingerprint alongside the recurrence HIGH.
        self.assertTrue(any(
            f["severity"] == "MEDIUM" and f["fingerprint"].startswith("outbound:")
            for f in fs))
        # This scan's row set was recorded for the next scan to count.
        names = [n for n in os.listdir(aegis.OBSERVATIONS_DIR)
                 if n.startswith("outbound.snapshot.")]
        self.assertEqual(len(names), 3)

    def test_two_prior_scans_do_not_fire(self):
        self._stub_platform()
        self._seed_observation(3000, [list(self.row)])  # 1 prior + current = 2
        fs = aegis.check_outbound()
        self.assertEqual(
            [f for f in fs if f["fingerprint"].startswith("beacon:")], [])

    def test_probe_non_answer_records_nothing(self):
        # An empty probe answer must not write an empty snapshot (a failed
        # netstat is indistinguishable from a quiet machine at this level).
        self._saved.setdefault("_outbound_rows", aegis._outbound_rows)
        aegis._outbound_rows = lambda: []
        self.assertEqual(aegis.check_outbound(), [])
        self.assertEqual(
            [n for n in os.listdir(aegis.OBSERVATIONS_DIR)
             if n.startswith("outbound.snapshot.")]
            if os.path.isdir(aegis.OBSERVATIONS_DIR) else [], [])


if __name__ == "__main__":
    unittest.main()
