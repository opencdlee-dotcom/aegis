"""A privilege wall this machine already proved gets a short probe, not a long wait.

macOS 26 moved `sfltool dumpbtm` behind system.privilege.admin. aegis detects
that correctly and records a named, permanent coverage gap in surface_walls.json
-- but it kept asking with the full 30s timeout, and the only reason the call
ever takes 30s is an authorization prompt no launchd agent can answer, sitting
there until the timeout kills it.

Measured on the reference Mac from its own sensor.health rows: 65 of 107
`surface.btm` runs hit the cap (min 65ms, max 30998ms), making the surface 20.5s
of an 82.3s scan -- 25% of every scan, ~30 minutes of wall-clock a day, spent
re-learning a policy already written down. `aegis.py doctor` reported DEGRADED
on scan cost (4.67% against a 1% ceiling) substantially because of it.

SHORTENING the probe, rather than skipping it, is the whole point. The first
attempt skipped the call entirely for 24h and `test_custody.py::
PrivilegeWallIsRemembered::test_a_success_clears_the_memory_so_later_failures_
are_new` caught it: the documented contract is that ONE success clears the wall,
so a later failure reads as genuinely new. Skipping delays noticing a lifted
wall by however long the skip lasts. Probing briefly keeps that contract exactly
-- a success is still seen on the very next scan -- and still turns 30s into 5s.

Platform-independent by construction: `run` is stubbed, no sfltool required.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import aegis                                    # noqa: E402

WALLED = ("", "sfltool: authorization failed", 1)
BLOCKED = ("", "", 1)              # killed at the timeout: no marker at all
ANSWERED = ("#1:\nUUID: u\nIdentifier: com.x\nName: X\nType: login\n", "", 0)


class BtmWallProbe(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self._walls = aegis.SURFACE_WALLS
        self._run = aegis.run
        aegis.SURFACE_WALLS = os.path.join(self.dir, "walls.json")
        self.timeouts = []

    def tearDown(self):
        aegis.SURFACE_WALLS = self._walls
        aegis.run = self._run

    def _stub(self, result):
        def r(cmd, **kw):
            self.timeouts.append(kw.get("timeout"))
            return result
        aegis.run = r

    # --- the saving -------------------------------------------------------
    def test_an_unproven_wall_still_gets_the_full_timeout(self):
        """A surface that might yet answer is given the time to answer."""
        self._stub(WALLED)
        aegis.snapshot_btm()
        self.assertEqual([30], self.timeouts)

    def test_a_proven_wall_is_probed_briefly(self):
        self._stub(WALLED)
        aegis.snapshot_btm()                      # proves the wall
        aegis._probe_record("btm", last=0)        # ...and a day passes
        aegis.snapshot_btm()                      # the DUE re-probe
        # BEFORE THE FIX: 30 again, and 61% of the time it burned all of it.
        self.assertEqual([30, aegis._BTM_WALLED_TIMEOUT], self.timeouts,
                         "a proven wall was still waited on at full cost")

    def test_the_short_timeout_is_a_real_reduction(self):
        self.assertLess(aegis._BTM_WALLED_TIMEOUT, 30)
        self.assertGreaterEqual(aegis._BTM_WALLED_TIMEOUT, 2,
                                "too tight to let a working dumpbtm answer")

    # --- the contract, and what it costs ----------------------------------
    #
    # This file originally shortened the probe rather than skipping it, to keep
    # "a success is seen on the very NEXT scan". That reasoning was right about
    # the contract and wrong about the cost it was paying: the expense of a
    # probe is not the seconds it blocks but the SecurityAgent password dialog
    # it raises, and SecurityAgent spawns about a second after the
    # authorization request -- so a 10s probe prompts exactly as a 30s one
    # does. Measured on the reference Mac: 29 dialogs in 45 minutes under a
    # change-driven watch, the closest pair 3 seconds apart. Shortening the
    # timeout cut the scan cost (which is what it was for, and it still does)
    # but could not have cut the prompting.
    #
    # So a proven wall is now re-probed at most daily, and the contract holds
    # at that cadence on the sfltool path. Where it still holds IMMEDIATELY is
    # the root-dump path (see test_btm_root_dump.py): the daemon's file is read
    # every scan with no authorization request at all, so an operator who
    # installs it gets both the old immediacy and no dialogs.
    def test_one_success_clears_the_wall_at_the_next_due_reprobe(self):
        self._stub(WALLED)
        aegis.snapshot_btm()
        self.assertTrue(aegis._wall_seen("btm"))
        aegis._probe_record("btm", last=0)        # a day passes
        self._stub(ANSWERED)
        snap = aegis.snapshot_btm()
        self.assertIn("com.x", snap)
        self.assertFalse(aegis._wall_seen("btm"),
                         "a lifted wall was not noticed at the due re-probe")

    def test_a_proven_wall_is_not_re_probed_before_it_is_due(self):
        """The prompting fix itself: between re-probes sfltool is not called,
        so no dialog can be raised."""
        self._stub(WALLED)
        aegis.snapshot_btm()
        self.timeouts = []
        for _ in range(5):
            self.assertIs(aegis.snapshot_btm(), aegis.SURFACE_PRIVILEGED)
        self.assertEqual(self.timeouts, [],
                         "a proven wall must not be probed on every scan")

    def test_a_cleared_wall_returns_to_the_full_timeout(self):
        self._stub(WALLED)
        aegis.snapshot_btm()
        aegis._probe_record("btm", last=0)
        self._stub(ANSWERED)
        aegis.snapshot_btm()
        self._stub(WALLED)
        aegis.snapshot_btm()
        self.assertEqual([30, aegis._BTM_WALLED_TIMEOUT, 30], self.timeouts)

    # --- verdicts are unchanged ------------------------------------------
    def test_the_verdict_is_identical_at_the_short_timeout(self):
        """Cheaper, not quieter: the same named coverage gap is reported."""
        self._stub(WALLED)
        self.assertIs(aegis.SURFACE_PRIVILEGED, aegis.snapshot_btm())
        self._stub(BLOCKED)
        self.assertIs(aegis.SURFACE_PRIVILEGED, aegis.snapshot_btm())

    def test_a_genuine_non_answer_is_still_a_non_answer(self):
        """No wall ever proven + an empty failure = None (skipped), NOT
        'zero background items'. The false-empty guard is untouched."""
        self._stub(BLOCKED)
        self.assertIsNone(aegis.snapshot_btm())


if __name__ == "__main__":
    unittest.main()
