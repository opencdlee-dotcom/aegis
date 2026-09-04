#!/usr/bin/env python3
"""A restart is not an attack, and the dead-pid rule could not tell them apart.

heartbeat_verdict fails closed by design: anything not provably healthy is a
dead state. One of those states, BEAT_DEAD_PID, fires on a fresh correctly
signed beat whose watch process no longer exists — "the monitor was killed and
something is still writing beats", which the watchdog renders as "treat this
as active tampering".

Every restart produces exactly that state legitimately. `install`, a launchd
reload, and the KeepAlive respawn the watch-loop hardening deliberately relies
on all leave the previous beat naming a pid that is now a corpse, until the new
process finishes its first scan. Measured on the reference machine one minute
after a routine `aegis.py install watch`: the watchdog announced active
tampering. That is the loudest false positive this project can emit, on its
most ordinary operation.

The discriminator is a LIVE agent under the scheduler's own label, which
malware cannot manufacture without actually running the monitor. Absence of
that evidence keeps the accusation — fail closed is still the rule, and these
tests pin both directions.
"""
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

DEAD_PID = 999_999          # never a live pid on any supported body
LIVE_PID = 4242


class HeartbeatVerdict(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis-beat-")
        self.state = os.path.join(self.tmp, ".aegis")
        os.makedirs(self.state, mode=0o700)
        self._saved = {n: getattr(aegis, n)
                       for n in ("STATE_DIR", "RUN_LOG", "HMAC_KEY_FILE")}
        aegis.STATE_DIR = self.state
        aegis.RUN_LOG = os.path.join(self.state, "run.log")
        aegis.HMAC_KEY_FILE = os.path.join(self.state, "hmac.key")
        with open(aegis.HMAC_KEY_FILE, "wb") as fh:
            fh.write(b"k" * 32)
        self._real_alive = aegis._pid_alive
        self._real_sched = aegis._scheduled_agent_pid
        self.addCleanup(setattr, aegis, "_pid_alive", self._real_alive)
        self.addCleanup(setattr, aegis, "_scheduled_agent_pid", self._real_sched)
        aegis._pid_alive = lambda pid: False if pid == DEAD_PID else True

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(aegis, n, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _beat(self, pid=DEAD_PID, mode="watch", age=60):
        beat = {"epoch": int(time.time()) - age, "ts": aegis.now_iso(),
                "pid": pid, "status": "ok", "alerts": 0, "top_alert": "",
                "mode": mode}
        beat["mac"] = aegis._heartbeat_mac(beat)
        return beat

    # --- the restart case -------------------------------------------------
    def test_a_live_agent_on_a_different_pid_means_restarted_not_attacked(self):
        aegis._scheduled_agent_pid = lambda: LIVE_PID
        state, human = aegis.heartbeat_verdict(self._beat())
        self.assertEqual(aegis.BEAT_OK, state)
        self.assertIn("restarted", human)
        self.assertIn(str(LIVE_PID), human)

    # --- fail closed: everything else still accuses -----------------------
    def test_no_scheduled_agent_is_still_tampering(self):
        aegis._scheduled_agent_pid = lambda: None
        state, _ = aegis.heartbeat_verdict(self._beat())
        self.assertEqual(aegis.BEAT_DEAD_PID, state)

    def test_a_scheduler_naming_the_same_dead_pid_is_still_tampering(self):
        """If the scheduler agrees the dead pid is the current one, nothing
        has restarted — the process is simply gone."""
        aegis._scheduled_agent_pid = lambda: DEAD_PID
        state, _ = aegis.heartbeat_verdict(self._beat())
        self.assertEqual(aegis.BEAT_DEAD_PID, state)

    def test_an_unanswerable_probe_never_clears_the_accusation(self):
        """No evidence is not evidence of innocence: a body with no probe, an
        unparseable answer and a refusal all read as None, and None must keep
        the dead-pid verdict."""
        aegis._scheduled_agent_pid = lambda: None
        self.assertEqual(aegis.BEAT_DEAD_PID,
                         aegis.heartbeat_verdict(self._beat())[0])

    def test_a_forged_beat_is_never_rescued_by_a_live_agent(self):
        """Authenticity is checked BEFORE liveness, and the restart escape
        must not become a way to launder an unsigned or forged beat."""
        aegis._scheduled_agent_pid = lambda: LIVE_PID
        b = self._beat()
        b["mac"] = "0" * 64
        self.assertEqual(aegis.BEAT_FORGED, aegis.heartbeat_verdict(b)[0])
        b2 = self._beat()
        del b2["mac"]
        self.assertEqual(aegis.BEAT_UNSIGNED, aegis.heartbeat_verdict(b2)[0])

    def test_a_stale_beat_is_never_rescued_by_a_live_agent(self):
        aegis._scheduled_agent_pid = lambda: LIVE_PID
        old = self._beat(age=aegis.HEARTBEAT_STALE_SECS + 600)
        self.assertEqual(aegis.BEAT_STALE, aegis.heartbeat_verdict(old)[0])

    def test_scan_mode_never_consults_the_pid_at_all(self):
        """A scan-mode writer is SUPPOSED to have exited, so its pid is never
        evidence — and the scheduler probe must not be paid for either."""
        def _boom():
            raise AssertionError("scan mode must not probe the scheduler")
        aegis._scheduled_agent_pid = _boom
        self.assertEqual(aegis.BEAT_OK,
                         aegis.heartbeat_verdict(self._beat(mode="scan"))[0])


class ScheduledAgentPid(unittest.TestCase):
    """The probe itself: only a positive, live pid may soften a verdict."""

    def setUp(self):
        self._real_run = aegis.run
        self.addCleanup(setattr, aegis, "run", self._real_run)

    def _run(self, out="", rc=0):
        aegis.run = lambda *a, **k: (out, "", rc)

    @unittest.skipUnless(aegis.IS_MAC, "launchctl probe is macOS-only")
    def test_a_running_job_reports_its_pid(self):
        self._run(out="state = running\n\tpid = 4242\n", rc=0)
        aegis._pid_alive = lambda pid: True
        self.addCleanup(setattr, aegis, "_pid_alive", aegis._pid_alive)
        self.assertEqual(4242, aegis._scheduled_agent_pid())

    @unittest.skipUnless(aegis.IS_MAC, "launchctl probe is macOS-only")
    def test_loaded_but_not_running_is_no_evidence(self):
        self._run(out="state = not running\n", rc=0)
        self.assertIsNone(aegis._scheduled_agent_pid())

    @unittest.skipUnless(aegis.IS_MAC, "launchctl probe is macOS-only")
    def test_a_refusal_is_no_evidence(self):
        self._run(out="", rc=113)
        self.assertIsNone(aegis._scheduled_agent_pid())


if __name__ == "__main__":
    unittest.main()
