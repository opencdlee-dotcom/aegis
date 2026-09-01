#!/usr/bin/env python3
"""`rehunt` replayed ONE lane while the store held more.

It hardcoded `persistence.snapshot`, so the retro-hunt — the only instrument
that answers "how long did this sit here before a detector could see it" — was
blind to `outbound.snapshot` (328 stored on the reference machine) and to every
surface, including agent_surface, which is the most precise detector in the
tool at 0.91 alert precision.

Two things had to be true to fix it: the surfaces must actually be recorded
(change-gated, or `watch` mode fills the disk), and the beacon replay must be
linear (the obvious per-step window rebuild measured 66s against 0.5s).
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


class TestRecordIfChanged(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._dir = aegis.OBSERVATIONS_DIR
        aegis.OBSERVATIONS_DIR = os.path.join(self.tmp, "observations")

    def tearDown(self):
        aegis.OBSERVATIONS_DIR = self._dir
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _count(self, sensor="s"):
        try:
            return len([n for n in os.listdir(aegis.OBSERVATIONS_DIR)
                        if n.startswith(sensor + ".")])
        except OSError:
            return 0

    def test_first_snapshot_is_always_written(self):
        self.assertIsNotNone(aegis.record_observation_if_changed("s", {"a": 1}))
        self.assertEqual(self._count(), 1)

    def test_an_identical_snapshot_is_not_rewritten(self):
        aegis.record_observation_if_changed("s", {"a": 1})
        for _ in range(5):
            self.assertIsNone(aegis.record_observation_if_changed("s", {"a": 1}))
        self.assertEqual(self._count(), 1,
                         "unchanged surface still consumed disk every scan")

    def test_a_changed_snapshot_is_written(self):
        # Asserted on the WRITE, not the file count: record_observation names
        # files by epoch-second, so two writes inside one second collide by
        # design. Live that cannot happen (WATCH_MIN_GAP_SECS is 60), so
        # counting files here would be testing the clock, not the change gate.
        self.assertIsNotNone(aegis.record_observation_if_changed("s", {"a": 1}))
        self.assertIsNotNone(aegis.record_observation_if_changed("s", {"a": 2}))
        self.assertIsNone(aegis.record_observation_if_changed("s", {"a": 2}))

    def test_key_order_is_not_a_change(self):
        """Dict ordering must not masquerade as a changed surface."""
        aegis.record_observation_if_changed("s", {"a": 1, "b": 2})
        self.assertIsNone(
            aegis.record_observation_if_changed("s", {"b": 2, "a": 1}))
        self.assertEqual(self._count(), 1)

    def test_sensors_do_not_share_a_digest(self):
        aegis.record_observation_if_changed("s", {"a": 1})
        self.assertIsNotNone(aegis.record_observation_if_changed("t", {"a": 1}))
        self.assertEqual(self._count("t"), 1)


class TestBeaconReplayIsEquivalentToTheNaiveVersion(unittest.TestCase):
    """The sliding window is an OPTIMISATION, so it has to produce exactly what
    rebuilding the window per step produced. This is the test that makes the
    58x speedup safe to keep."""

    @staticmethod
    def _naive(snaps):
        span = aegis.BEACON_WINDOW_DAYS * 86400
        for idx in range(1, len(snaps)):
            cur_ts, cur_rows = snaps[idx]
            if not isinstance(cur_rows, (list, tuple)):
                continue
            window = [(ts, rows) for ts, rows in snaps[:idx]
                      if cur_ts - ts <= span]
            for f in aegis._beacon_recurrence(window, cur_rows):
                yield cur_ts, f

    def _series(self, n, span_secs):
        base = 1_700_000_000
        rows = [("/tmp/evil", "203.0.113.9", "443", "adhoc")]
        step = span_secs // max(n - 1, 1)
        return [(base + i * step, rows) for i in range(n)]

    def _fps(self, gen):
        return sorted((ts, f["fingerprint"]) for ts, f in gen)

    def test_identical_output_on_a_recurring_pair(self):
        snaps = self._series(12, 6 * 3600)
        self.assertEqual(self._fps(aegis._replay_beacon(snaps)),
                         self._fps(self._naive(snaps)))

    def test_identical_output_when_the_window_actually_evicts(self):
        # Spread wider than BEACON_WINDOW_DAYS so eviction is exercised, which
        # is the only place a sliding window can diverge from a rebuild.
        snaps = self._series(20, (aegis.BEACON_WINDOW_DAYS + 6) * 86400)
        self.assertEqual(self._fps(aegis._replay_beacon(snaps)),
                         self._fps(self._naive(snaps)))

    def test_identical_output_with_ragged_rows(self):
        snaps = self._series(8, 4 * 3600)
        snaps[3] = (snaps[3][0], "not-a-list")
        snaps[5] = (snaps[5][0], [("bad",)])
        self.assertEqual(self._fps(aegis._replay_beacon(snaps)),
                         self._fps(self._naive(snaps)))


class TestLanesCoverEverySurface(unittest.TestCase):
    def test_lane_table_is_derived_from_surfaces_not_hardcoded(self):
        lanes = dict(aegis._rehunt_lanes())
        self.assertIn("persistence.snapshot", lanes)
        self.assertIn(aegis.BEACON_SENSOR_ID, lanes)
        for row in aegis.SURFACES:
            key = aegis._surface_row(row)[0]
            self.assertIn("surface." + key, lanes,
                          "a registered surface has no replay lane")

    def test_the_agent_surface_is_replayable(self):
        """The specific blind spot: the tool's most precise detector could not
        be retro-hunted at all."""
        self.assertIn("surface.agent_surface", dict(aegis._rehunt_lanes()))

    def test_every_lane_is_callable_on_an_empty_series(self):
        for _name, replay in aegis._rehunt_lanes():
            self.assertEqual(list(replay([])), [])


if __name__ == "__main__":
    unittest.main()
