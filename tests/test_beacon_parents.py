#!/usr/bin/env python3
"""#352: the beacon sensor graded a supervised Worker as if nobody started it.

`<runner>/bin.2.336.0/Runner.Worker`, "Persistent outbound connection (beacon
shape)", HIGH with no rung. The `supervised` rung already answers for that
exact binary on the PROCESS sensor, because check_processes hands
_grade_binary the ancestor exe list: the Worker was started by the
operator-vouched Runner.Listener, out of the Listener's own install
directory. The network sensors never passed `parents`, so the same Worker's
beacon -- and its live outbound record -- graded HIGH beside a MEDIUM process
finding about the same bytes, and the records carried no `ancestry`, so the
replay harness could not re-derive the grade either.

Every class pins the rung AND what must still earn nothing: an ancestor
nobody vouched for, a vouched ancestor in another directory, a connection
whose pid the row does not carry. And the cost guard: a host with no vouch
never reads the ancestry table, which is the common case.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import aegis                                          # noqa: E402
from test_false_alarm_batch_20260922 import (SUPERVISED_TABLE,      # noqa: E402
                                             _untrusted)
from test_regression import Sandbox                                 # noqa: E402

REMOTE = "20.85.130.105"
T0 = 1_787_000_000


class _RunnerSandbox(Sandbox):
    """A runner install on disk, a vouch for its Listener, and every live
    source the network sensors read replaced by a fixed table."""

    def setUp(self):
        super().setUp()
        aegis._CUSTODY_CARRY_CACHE.clear()
        aegis._GRADED_SHA_CACHE.clear()
        self.addCleanup(aegis._CUSTODY_CARRY_CACHE.clear)
        self.addCleanup(aegis._GRADED_SHA_CACHE.clear)
        runner = os.path.join(self.tmp, "actions-runners", "professor-os")
        self.bin = os.path.join(runner, "bin.2.336.0")
        self.listener = self._file(self.bin, "Runner.Listener")
        self.worker = self._file(self.bin, "Runner.Worker")
        self.shell = self._file(os.path.join(self.tmp, "elsewhere"), "bash")
        self.vouched = {os.path.realpath(self.listener)}
        self.host_vouches = True
        self.procs = [("100", self.listener), ("200", self.worker)]
        self.table = dict(SUPERVISED_TABLE)
        self.rows = [(self.worker, REMOTE, "443", "200")]
        self.tables_built = 0
        self.process_reads = 0
        trust = _untrusted()
        me = aegis._own_owner()

        def build():
            self.tables_built += 1
            return dict(self.table)

        def procs():
            self.process_reads += 1
            return iter([(pid, me, exe, exe) for pid, exe in self.procs])

        def history(_sensor, _days):
            return [(T0 + i * 1800, [(r[0], r[1], r[2], trust)
                                     for r in self.rows]) for i in range(3)]

        for name, fake in (
                ("_vouch_covers", self._covers),
                ("load_vouches", lambda now=None: (
                    self._vouches() if self.host_vouches else {}, None)),
                ("_process_ancestry_table", build),
                ("_iter_processes", procs),
                ("_outbound_rows", lambda: list(self.rows)),
                ("_load_observations", history),
                ("record_observation", lambda sensor, rows: None),
                ("_intel_net_finding", lambda path, rip, rport: None),
                ("is_risky_location", lambda path: True),
                ("classify_signature", lambda p: {
                    "trust": trust, "team": None, "authority": None})):
            self._saved.setdefault(name, getattr(aegis, name))
            setattr(aegis, name, fake)

    def _file(self, d, name):
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, name)
        with open(path, "wb") as f:
            f.write(("%s bytes\n" % path).encode("utf-8"))
        return path

    def _covers(self, path, endpoint=None, now=None):
        """An identity vouch: it covers the bytes, and names no endpoint."""
        return endpoint is None and os.path.realpath(path) in self.vouched

    def _vouches(self):
        return {aegis._vouch_subject(p): {"path": p} for p in
                sorted(self.vouched) or [os.path.realpath(self.shell)]}

    def scan(self):
        """{category: finding} from the REAL check_outbound."""
        return {f["category"]: f for f in aegis.check_outbound()}


class TheBeaconAsksWhoStartedIt(_RunnerSandbox):

    def test_a_worker_its_vouched_supervisor_started_is_supervised(self):
        f = self.scan()["net-beacon"]
        # BEFORE: ('HIGH', None) -- #352, the same bytes the process sensor
        # graded `supervised` in the same scan.
        self.assertEqual(("MEDIUM", "supervised"),
                         (f["severity"], f["custody"]))
        self.assertEqual([self.listener], f["ancestry"],
                         "the replay re-derives the rung from this field")

    def test_the_outbound_record_is_graded_the_same_way(self):
        f = self.scan()["net-outbound"]
        self.assertEqual(("LOW", "supervised"), (f["severity"], f["custody"]))
        self.assertEqual([self.listener], f["ancestry"])

    def test_an_ancestor_nobody_vouched_for_earns_nothing(self):
        self.vouched = set()
        f = self.scan()["net-beacon"]
        self.assertEqual(("HIGH", None), (f["severity"], f["custody"]))
        self.assertEqual([self.listener], f["ancestry"],
                         "the evidence still names who started it")

    def test_a_vouched_ancestor_in_another_directory_earns_nothing(self):
        self.procs = [("150", self.shell), ("200", self.worker)]
        self.table = {"200": ("150", "20"), "150": ("1", "15")}
        self.vouched = {os.path.realpath(self.shell)}
        f = self.scan()["net-beacon"]
        self.assertEqual(("HIGH", None), (f["severity"], f["custody"]))
        self.assertEqual([self.shell], f["ancestry"])

    def test_a_row_without_a_pid_grades_as_before(self):
        self.rows = [(self.worker, REMOTE, "443")]
        f = self.scan()["net-beacon"]
        self.assertEqual(("HIGH", None), (f["severity"], f["custody"]))
        self.assertNotIn("ancestry", f)
        self.assertEqual(0, self.tables_built)


class TheCostStaysZeroWithoutAVouch(_RunnerSandbox):

    def test_no_vouch_on_the_host_reads_no_ancestry(self):
        self.host_vouches = False
        fs = self.scan()
        self.assertEqual(0, self.tables_built,
                         "a host with no vouch paid for a process-table read "
                         "no rung could use")
        self.assertEqual(0, self.process_reads)
        self.assertEqual(("HIGH", None), (fs["net-beacon"]["severity"],
                                          fs["net-beacon"]["custody"]))
        self.assertNotIn("ancestry", fs["net-beacon"])
        self.assertNotIn("ancestry", fs["net-outbound"])

    def test_the_ancestry_table_is_read_once_per_scan(self):
        self.rows = [(self.worker, REMOTE, "443", "200"),
                     (self.worker, "20.85.130.106", "443", "200")]
        self.scan()
        self.assertEqual(1, self.tables_built)
        self.assertEqual(1, self.process_reads)


class TheReplayReDerivesIt(_RunnerSandbox):
    """A recorded beacon that carries `ancestry` re-grades exactly as the
    sensor would; one that does not, where a vouched program could have
    earned it the rung, is replayed as recorded and says why."""

    def _record(self, **extra):
        return aegis.finding(
            "HIGH", "net-beacon",
            "Persistent outbound connection (beacon shape)", "d",
            "beacon:%s:%s:443" % (aegis._program_subject(self.worker), REMOTE),
            path=self.worker, program=self.worker, remote=REMOTE, port="443",
            trust=_untrusted(), **extra)

    def _stats(self):
        stats = dict.fromkeys(("reobserved", "trust_changed",
                               "custody_changed", "changed",
                               "severity_changed", "no_longer_emitted",
                               "gone"), 0)
        stats.update(not_rederivable={}, persistence_changes={},
                     dropped_why={})
        return stats

    def test_a_record_with_ancestry_re_derives_the_rung(self):
        g, as_recorded = aegis._reobserve(
            self._record(ancestry=[self.listener]), {}, self._stats())
        self.assertIsNone(as_recorded)
        self.assertEqual(("MEDIUM", "supervised"),
                         (g["severity"], g["custody"]))

    def test_a_record_without_ancestry_is_replayed_as_recorded(self):
        stats = self._stats()
        f = self._record()
        g, as_recorded = aegis._reobserve(f, {}, stats)
        self.assertEqual("field missing: ancestry", as_recorded)
        self.assertIs(f, g)
        self.assertEqual({"field missing: ancestry": 1},
                         stats["not_rederivable"])


if __name__ == "__main__":
    unittest.main()
