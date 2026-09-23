#!/usr/bin/env python3
"""The 2026-09-22 batch: 14 open incidents, and the largest share of them stood
on a verdict no probe ever returned.

Counted by fact rather than by row, the 14 were six things.

  A   A codesign probe that printed nothing was filed as `unsigned`, and the
      verdict cache made it permanent.

      `_classify_mac` ignored the exit status of `codesign -dv`, and every
      rung of its ladder reads an ABSENCE: no "not signed at all" marker, no
      `Authority=` line, no adhoc flag. So a probe that timed out -- run()
      hands back ("", "timeout", 124) -- or printed nothing at all fell through
      every rung and landed on `unsigned`. `codesign --verify --strict` had the
      twin: a non-zero exit with an empty stderr became `broken`. Neither set
      `probe_failed`, so classify_signature cached the verdict against a stat
      signature that would never change again. The Windows classifier has
      honoured that contract since 2026-08-04; the mac one never had it.

      MEASURED on the live store. Spotify's main binary and its helper are
      Developer ID signed (team 2FNC3A47ZF; `codesign --verify` answers in
      about 0.2s). They classified `developer-id` on 96 findings over
      2026-09-11..12, then `unsigned` from 2026-09-20 08:32:24 onward -- 366
      findings on the main binary alone -- and the cache held `trust:
      unsigned, authority: None` on the current bytes (same inode, ctime,
      mtime and size). The scan that minted it landed 18 minutes after its predecessor
      on a 10-minute cadence. The outbound sensor's gate is
      `suspicious_sig(trust) or is_risky_location(path)`, and /Applications is
      not risky, so with the right verdict not one Spotify beacon would have
      been emitted: eight beacon incidents (#528-#533, #535, #536) stood on
      that one silence. Obsidian's `broken` (#526) was minted in the same scan.

      Why codesign did not answer on that scan is not recoverable: run.log
      records no codesign failure, and a timeout under load and a read in the
      middle of an update are both consistent with it. That is the point. The
      defect is not the silence; it is that a silence became a verdict and a
      cache made the verdict permanent. A non-answer now returns probe_failed
      with trust `unknown` -- which suspicious_sig() does not flag, and which
      the `signature.classify` health row reports DEGRADED for that scan -- and
      is never cached, so the next scan asks again. A file that changed while
      codesign was reading it is not cached either, and _SIGCACHE_LOGIC_VERSION
      is 3, so every verdict minted under the old reading is re-probed once.
      The real "not signed at all" marker still means `unsigned`, and a strict
      verify that FAILS WITH A REASON still means `broken`: an answer is still
      an answer.

      The exit half. A right verdict stops the emission, and that is all it
      does: a beacon that is no longer emitted brings no new evidence, so the
      re-grade exit (which reads the incident's latest evidence) never fires,
      and a beacon is an event, not a state, so the cleared-state exit never
      looks at it. The eight Spotify incidents would have waited out the
      7-day age-out clock and its reminder ladder for a verdict that had
      already been corrected. `_close_reverified_incidents` asks the sensor's
      own question again: when the incident's own sensor answered OK this
      scan without re-asserting the case, and the incident's newest evidence
      names a path whose untrusted signature was the gate, the path is
      re-classified; a publisher verdict at a location that is not risky is
      exactly what the sensor's gate (`suspicious_sig(trust) or
      is_risky_location(path)`) no longer emits, and the incident closes
      FALSE_POSITIVE, "re-verified". Evidence that carries a sha must still
      hash to it, so replacing the binary cannot close a content-keyed case,
      and a probe that does not answer now reads `unknown`, which is not a
      publisher. The discipline is the re-grade exit's: OPEN only, CRITICAL
      and never-tolerate keys skipped, the severity untouched, no dismissals
      row.

  A2  A program that binds ephemeral ports was one listener signal per port.
      Spotify bound 225 distinct ports, every one at or above 49152, so three
      of them inside the risk window summed to a risk incident (#527) out of
      churn the OS itself defines as "not a service port".

  B   Custody asked the WORKTREE whether this machine commits to the repo, and
      a fresh worktree always answers no: its own HEAD reflog holds only
      `reset:` entries until something is committed in it. The operator's
      agents build in fresh worktrees all day; #537 is a dev build of a
      bundled `plugin-container` graded with no custody rung at all.

      `_git_created_here` read `git log -g`: the reflog of the worktree's OWN
      HEAD. Branch reflogs live in the common git dir and are shared by every
      worktree of the repository, and a commit made in any of them enters its
      branch's reflog as `commit:`. So the question ("did this machine make
      HEAD?") was the right one, asked of the one record a fresh worktree does
      not have. MEASURED by experiment 2026-09-22: a local commit answers True
      from the checkout that made it and False from a `git worktree add` of
      the same repo at the same commit; a commit made in a worktree and
      fast-forwarded into main answers False from main, whose HEAD log says
      `merge agent/x: Fast-forward`. `--all` reads every reflog of the same
      repository, so all three answer True. The scope widens no further than
      that: remote-tracking reflogs record `fetch:` and `update by push`,
      never `commit:`, and the author email must still equal `user.email`.

      Two more ways a "no" could be recorded that git never said, both A's
      family. A git probe that timed out (10-15 s caps, a scan at background
      QoS, an agent's build storm) fell through to False and was cached as
      (root, False). And `cmd_watch` runs every scan IN-PROCESS, so the three
      custody caches outlived the scan that filled them: an answer given about
      a worktree while it was fresh stood for the life of the daemon, through
      every commit made in it afterwards. Which of the three minted #537's
      null is not recoverable from the store; offline, the same path grades
      (MEDIUM, build-output). A timed-out custody probe is now a non-answer --
      no rung, full severity, counted once into a `custody.grade` DEGRADED
      health row -- and the caches are cleared at the start of every scan, so
      the incident re-grades the first time git answers. Within one scan the
      non-answer IS remembered, as a non-answer, so a git that is timing out
      costs its timeouts once per repo rather than once per file.

  C   A runner workload outgrows its vouch on every self-update.
      `Runner.Worker` is spawned by the vouched `Runner.Listener` out of the
      same install directory and has never been vouched itself (#534).

  D   A hot-dir finding had no exit when its file is gone. `/tmp/qtest_local`
      (#525) was a throwaway test binary, deleted since; nothing could close
      its incident before age-out.

  E   The behavior identity redesign of 2026-09-19 (its D6) orphaned its own
      open case: #503 is keyed on a raw-argv hash that no future finding can
      re-emit.

The rule this batch adds is the one A broke: a probe that did not answer is
not a verdict. ARCHITECTURE.md already held it for a sensor that returns None
and for an item it found and could not examine; a verdict probe whose answers
are CACHED is the third form, and the one where a single silence lasts
forever.
"""
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import aegis                                    # noqa: E402
from test_regression import (                                 # noqa: E402
    Sandbox, needs_real_scan_lock, needs_the_real_body)

# `codesign -dv --verbose=4` on a Developer ID binary. codesign writes this
# detail to STDERR and exits 0; the field names and their order are the real
# ones, the identity is an example.
DEV_ID_DV = (
    "Executable=/Applications/Example.app/Contents/MacOS/Example\n"
    "Identifier=com.example.app\n"
    "Format=app bundle with Mach-O universal (x86_64 arm64)\n"
    "CodeDirectory v=20500 size=1234 flags=0x10000(runtime) hashes=27+7 "
    "location=embedded\n"
    "Authority=Developer ID Application: Example Ltd (ABCDE12345)\n"
    "Authority=Developer ID Certification Authority\n"
    "Authority=Apple Root CA\n"
    "TeamIdentifier=ABCDE12345\n")

TIMED_OUT = ("", "timeout", 124)     # exactly what run() returns on a timeout
CLEAN_VERIFY = ("", "", 0)           # a passing strict verify prints NOTHING


class A1ANonAnswerIsNotAVerdict(Sandbox):
    """A codesign probe that did not answer is a coverage gap, not `unsigned`.

    run() is mocked, so the mac ladder runs on every body: what is under test
    is the classifier's reading of codesign's output, not the platform."""

    def setUp(self):
        super().setUp()
        # Sandbox.tearDown restores everything in _saved.
        self._saved["run"] = aegis.run
        self._saved["_SIG_PROBE_FAILURES"] = aegis._SIG_PROBE_FAILURES
        aegis._SIG_PROBE_FAILURES = 0
        # A real file: classify_signature answers `missing` for a path that
        # does not exist without probing anything.
        self.path = os.path.join(self.tmp, "Example")
        with open(self.path, "wb") as fh:
            fh.write(b"\xcf\xfa\xed\xfe fixture bytes")

    def _codesign(self, dv, verify=CLEAN_VERIFY, on_dv=None):
        """Answer the two codesign calls _classify_mac makes; any other command
        is a test bug and fails loudly. on_dv runs while the -dv probe is
        "reading", which is where a mid-probe replacement lands."""
        calls = []

        def fake(cmd, timeout=15, extra_env=None, stdin_data=None):
            calls.append(list(cmd))
            if list(cmd[:2]) == ["codesign", "-dv"]:
                if on_dv is not None:
                    on_dv()
                return dv
            if list(cmd[:2]) == ["codesign", "--verify"]:
                return verify
            raise AssertionError("unexpected command %r" % (cmd,))
        aegis.run = fake
        return calls

    def _classify_as_mac(self):
        """classify_signature, with this body's dispatch routed through the
        REAL mac classifier. Only the dispatch is platform-shaped; everything
        behind it runs against the mocked codesign."""
        if aegis.IS_LINUX:
            name = "_classify_linux"
        elif aegis.IS_WIN:
            name = "_classify_windows"
        else:
            name = "_classify_mac"
        if name != "_classify_mac":
            self._saved[name] = getattr(aegis, name)
            setattr(aegis, name, aegis._classify_mac)
        # On Windows the Sandbox pins classify_signature itself to a stub; the
        # real one is what is under test here.
        return self._saved.get("classify_signature", aegis.classify_signature)

    # ---- the one spelling of a timeout -------------------------------------

    @needs_the_real_body
    def test_the_timeout_spelling_matches_what_run_returns(self):
        """Asserted against the PRODUCER, not a fixture of it: if run() ever
        spells a timeout differently, this fails instead of every caller
        quietly reading the timeout as an answer again. Real body only: run()
        builds its Windows environment from constants a simulated Windows on
        a POSIX host does not have, and the windows-latest leg runs it for
        real."""
        aegis.run = self._saved["run"]
        got = aegis.run([sys.executable, "-c", "import time; time.sleep(30)"],
                        timeout=0.5)
        self.assertTrue(aegis._probe_timed_out(got[1], got[2]), got)

    def test_each_half_alone_is_an_answer(self):
        # Exit 124 is also GNU timeout's own status; a tool may print the word.
        self.assertFalse(aegis._probe_timed_out("", 124))
        self.assertFalse(aegis._probe_timed_out("timeout", 1))
        self.assertFalse(aegis._probe_timed_out(None, 0))

    # ---- the -dv probe -------------------------------------------------------

    def test_a_timed_out_dv_probe_is_not_unsigned(self):
        calls = self._codesign(TIMED_OUT)
        result = aegis._classify_mac(self.path)
        # BEFORE: {"trust": "unsigned"} -- no marker, no Authority= line, no
        # adhoc flag, so the silence fell through every rung of the ladder.
        self.assertIs(True, result.get("probe_failed"), result)
        self.assertEqual("unknown", result["trust"])
        self.assertEqual(1, aegis._SIG_PROBE_FAILURES,
                         "the scan must be able to report the gap")
        self.assertEqual(1, len(calls),
                         "nothing to verify when nothing was read")

    def test_empty_output_is_not_unsigned(self):
        self._codesign(("", "", 1))
        result = aegis._classify_mac(self.path)
        self.assertIs(True, result.get("probe_failed"), result)
        self.assertEqual("unknown", result["trust"])
        self.assertEqual(1, aegis._SIG_PROBE_FAILURES)

    def test_the_real_unsigned_marker_still_verdicts(self):
        self._codesign(
            ("", "%s: code object is not signed at all\n" % self.path, 1))
        result = aegis._classify_mac(self.path)
        self.assertEqual("unsigned", result["trust"])
        self.assertNotIn("probe_failed", result)
        self.assertEqual(0, aegis._SIG_PROBE_FAILURES)

    # ---- the strict verify ---------------------------------------------------

    def test_a_clean_verify_prints_nothing_and_is_a_verdict(self):
        """The positive control the verify rule is shaped around: a PASSING
        strict verify is silent with exit 0, so silence alone cannot be the
        non-answer test there -- only silence with a failing exit."""
        self._codesign(("", DEV_ID_DV, 0), CLEAN_VERIFY)
        result = aegis._classify_mac(self.path)
        self.assertEqual("developer-id", result["trust"])
        self.assertEqual("ABCDE12345", result["team"])
        self.assertNotIn("probe_failed", result)

    def test_a_timed_out_verify_is_not_broken(self):
        self._codesign(("", DEV_ID_DV, 0), TIMED_OUT)
        result = aegis._classify_mac(self.path)
        # BEFORE: {"trust": "broken"} -- rc 124 and no "not signed" in stderr.
        self.assertIs(True, result.get("probe_failed"), result)
        self.assertEqual("unknown", result["trust"])
        self.assertEqual(1, aegis._SIG_PROBE_FAILURES)

    def test_a_silent_verify_failure_is_not_broken(self):
        self._codesign(("", DEV_ID_DV, 0), ("", "", 1))
        result = aegis._classify_mac(self.path)
        self.assertIs(True, result.get("probe_failed"), result)
        self.assertEqual("unknown", result["trust"])

    def test_a_real_strict_failure_is_still_broken(self):
        self._codesign(
            ("", DEV_ID_DV, 0),
            ("", "%s: a sealed resource is missing or invalid\n" % self.path,
             1))
        result = aegis._classify_mac(self.path)
        self.assertEqual("broken", result["trust"])
        self.assertNotIn("probe_failed", result)
        self.assertEqual(0, aegis._SIG_PROBE_FAILURES)

    # ---- the cache -----------------------------------------------------------

    def test_a_non_answer_is_never_cached(self):
        classify = self._classify_as_mac()
        self._codesign(TIMED_OUT)
        result = classify(self.path)
        self.assertEqual("unknown", result["trust"])
        self.assertNotIn("probe_failed", result,
                         "the marker is internal; callers see the normal shape")
        # BEFORE: {"trust": "unsigned"} cached against a stat that never
        # changes again -- the live Spotify entry.
        self.assertNotIn(self.path, aegis._sigcache,
                         "a non-answer was cached as a verdict")

        # ...so the next scan asks again, and an answer IS cached.
        self._codesign(("", DEV_ID_DV, 0), CLEAN_VERIFY)
        self.assertEqual("developer-id", classify(self.path)["trust"])
        entry = aegis._sigcache.get(self.path)
        self.assertIsNotNone(entry, "a real answer must still be cached")
        self.assertEqual("developer-id", entry["result"]["trust"])
        self.assertEqual(aegis._SIGCACHE_LOGIC_VERSION, entry.get("v"))

    def test_a_file_replaced_mid_probe_is_not_cached(self):
        classify = self._classify_as_mac()
        replacement = os.path.join(self.tmp, "Example.new")

        def replace_it():
            with open(replacement, "wb") as fh:
                fh.write(b"\xcf\xfa\xed\xfe different, longer fixture bytes")
            os.replace(replacement, self.path)

        self._codesign(("", DEV_ID_DV, 0), CLEAN_VERIFY, on_dv=replace_it)
        # This call's answer stands; it describes bytes that are gone, so it
        # is not persisted.
        self.assertEqual("developer-id", classify(self.path)["trust"])
        self.assertNotIn(self.path, aegis._sigcache,
                         "a verdict on bytes that changed under the probe "
                         "was cached")

    def test_logic_version_is_bumped(self):
        """Every v2 verdict could be a silence that became `unsigned` or
        `broken`; the bump is what makes the fix reach a running install."""
        self.assertEqual(3, aegis._SIGCACHE_LOGIC_VERSION)


# The binary under custody here is the git the rung itself runs.
GIT = aegis._git_bin()
ME = "me@example.invalid"
SOMEONE_ELSE = "someone-else@example.invalid"

# A repo this machine commits to, as the custody probes see it: one answer per
# question, keyed by _git_question(). Any single one is replaced per test.
FAKE_ROOT = "/work/repo"
FAKE_SHA = "a" * 40
SELF_COMMITTED = {
    "rev-parse": (FAKE_ROOT + "\n", "", 0),
    "head": ("%s|%s\n" % (FAKE_SHA, ME), "", 0),
    "config": (ME + "\n", "", 0),
    "reflog": ("%s commit: build\n" % FAKE_SHA, "", 0),
    "signature": ("N\n", "", 0),
    "check-ignore": ("", "", 0),
}


def _git_question(cmd):
    """Which custody question a git argv asks. The fleet probe passes its
    roster with `-c`, so it is told apart by its format, not by `config`."""
    args = list(cmd)
    for q in ("rev-parse", "check-ignore", "config"):
        if q in args:
            return q
    if "log" in args:
        if "-g" in args:
            return "reflog"
        if "--format=%G?" in args:
            return "signature"
        return "head"
    raise AssertionError("not a custody question: %r" % (args,))


class B1AWorktreeIsStillTheRepo(Sandbox):
    """"Does this machine commit here?" is a question about the REPOSITORY,
    and a timed-out git is not an answer to it.

    Two halves. The real-git tests build a repo and its worktrees in the
    sandbox, because what is under test there is git's own reflog layout. The
    mocked tests replace run() and so run on every body: what is under test
    there is how the rung reads a git that did not answer."""

    def setUp(self):
        super().setUp()
        # Sandbox.tearDown restores everything in _saved.
        self._saved["run"] = aegis.run
        self._saved["_git_bin"] = aegis._git_bin
        self._saved["_CUSTODY_PROBE_FAILURES"] = getattr(
            aegis, "_CUSTODY_PROBE_FAILURES", 0)
        aegis._CUSTODY_PROBE_FAILURES = 0
        self._clear_caches()
        self.addCleanup(self._clear_caches)
        # realpath: git reports its top level resolved (/private/var on a
        # Mac, the long form of an 8.3 name on Windows), and the rung's caches
        # are keyed on what git reports.
        self.base = os.path.realpath(self.tmp)
        self.dist = os.path.join(self.base, "dist")
        os.makedirs(self.dist)
        self.binary = os.path.join(self.dist, "bin")

    @staticmethod
    def _clear_caches():
        aegis._REPO_ROOT_CACHE.clear()
        aegis._REPO_SELFNESS_CACHE.clear()
        aegis._BUILD_OUTPUT_CACHE.clear()

    # ---- fixtures: a fake git ------------------------------------------------

    def _fake_git(self, **answers):
        """Patch run() with a git that answers SELF_COMMITTED, overridden per
        question. Returns the questions asked, in order."""
        table = dict(SELF_COMMITTED)
        table.update(answers)
        asked = []

        def fake(cmd, timeout=15, extra_env=None, stdin_data=None):
            q = _git_question(cmd)
            asked.append(q)
            return table[q]
        aegis.run = fake
        aegis._git_bin = lambda: "git"
        return asked

    def _pin_a_fleet_roster(self):
        # The fleet rung asks nothing unless a roster has been pinned.
        with open(aegis.FLEET_SIGNERS, "w") as fh:
            fh.write("")

    # ---- fixtures: a real git ------------------------------------------------

    def _git(self, cwd, *args, **kw):
        """A fixture git that the operator's own config cannot reach: global
        and system config are nulled, and signing is off by `-c` as well, so a
        machine that signs every commit (this one does) cannot make a fixture
        commit it did not mean to."""
        env = dict(os.environ)
        env.update({"GIT_TERMINAL_PROMPT": "0",
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_CONFIG_SYSTEM": os.devnull})
        cmd = [GIT, "-c", "commit.gpgsign=false",
               "-c", "user.email=%s" % kw.get("email", ME),
               "-c", "user.name=Custody Test",
               "-c", "init.defaultBranch=main",
               "-C", cwd] + list(args)
        r = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if r.returncode != 0:
            raise AssertionError("fixture git %r failed: %s"
                                 % (args, r.stderr.strip()))
        return r.stdout

    def _repo(self, email=ME):
        """The operator's repo: `user.email` configured, and a committed
        .gitignore declaring dist/ as build output. The config is written
        into the repo because the rung reads it through run(), which sees the
        real global config -- the repo's own value is what must win."""
        repo = os.path.join(self.base, "repo")
        os.makedirs(repo)
        self._git(repo, "init", "-q")
        self._git(repo, "config", "user.email", ME)
        with open(os.path.join(repo, ".gitignore"), "wb") as fh:
            fh.write(b"dist/\n")
        self._git(repo, "add", ".gitignore")
        self._git(repo, "commit", "-q", "-m", "dist/ is build output",
                  email=email)
        return repo

    def _worktree(self, repo, name, branch):
        wt = os.path.join(self.base, name)
        self._git(repo, "worktree", "add", "-q", "-b", branch, wt)
        return wt

    @staticmethod
    def _build(tree):
        """A generated artifact under `tree`'s dist/: an agent's dev build."""
        d = os.path.join(tree, "dist")
        if not os.path.isdir(d):
            os.makedirs(d)
        p = os.path.join(d, "bin")
        with open(p, "wb") as fh:
            fh.write(b"\xcf\xfa\xed\xfe fixture build output")
        return p

    # ---- the worktree is still the repo (real git) ---------------------------

    @unittest.skipUnless(GIT, "no git binary on this machine")
    @needs_the_real_body
    def test_a_fresh_worktree_inherits_the_repos_selfness(self):
        repo = self._repo()
        wt = self._worktree(repo, "wt", "agent/x")
        # Positive control: from the checkout that made the commit it was
        # always a rung.
        self.assertEqual("build-output",
                         aegis._build_output_rung(self._build(repo)))
        # BEFORE: None. The worktree's own HEAD log holds `reset: moving to
        # HEAD` and nothing else; `commit (initial)` is in main's reflog.
        self.assertEqual("build-output",
                         aegis._build_output_rung(self._build(wt)))
        got = aegis._repo_is_self_committed(GIT, os.path.join(wt, "dist"))
        self.assertIs(True, got[1], got)

    @unittest.skipUnless(GIT, "no git binary on this machine")
    @needs_the_real_body
    def test_a_commit_made_in_one_worktree_counts_from_another(self):
        """The landing path: an agent commits in its worktree, the branch is
        fast-forwarded into main, and main's HEAD log records a MERGE."""
        repo = self._repo()
        wt = self._worktree(repo, "wt", "agent/x")
        with open(os.path.join(wt, "work.txt"), "wb") as fh:
            fh.write(b"made in the worktree\n")
        self._git(wt, "add", "work.txt")
        self._git(wt, "commit", "-q", "-m", "made in the worktree")
        self._git(repo, "merge", "-q", "--ff-only", "agent/x")
        head = self._git(repo, "log", "-g", "-n", "1", "--format=%gs").strip()
        self.assertTrue(head.startswith("merge agent/x"), head)
        # BEFORE: None -- main's HEAD log never saw the commit being made.
        self.assertEqual("build-output",
                         aegis._build_output_rung(self._build(repo)))

    @unittest.skipUnless(GIT, "no git binary on this machine")
    @needs_the_real_body
    def test_a_real_no_is_still_cached(self):
        """A commit authored by someone else is an ANSWER: not this machine's.
        It is cached, and it counts as nothing timing out."""
        repo = self._repo(email=SOMEONE_ELSE)
        d = os.path.join(repo, "dist")
        os.makedirs(d)
        got = aegis._repo_is_self_committed(GIT, d)
        self.assertIsNotNone(got)
        self.assertIs(False, got[1], got)
        self.assertEqual(got, aegis._REPO_SELFNESS_CACHE.get(got[0]))
        self.assertIsNone(aegis._build_output_rung(self._build(repo)))
        self.assertIn(d, aegis._BUILD_OUTPUT_CACHE)
        self.assertEqual(0, aegis._CUSTODY_PROBE_FAILURES)

    # ---- a timed-out git is not a no (mocked, every body) --------------------

    def test_a_timed_out_git_log_is_not_a_no(self):
        asked = self._fake_git(head=TIMED_OUT, reflog=TIMED_OUT,
                               signature=TIMED_OUT)
        got = aegis._repo_is_self_committed("git", self.dist)
        # BEFORE: (FAKE_ROOT, False), cached for the rest of the scan -- and,
        # in watch mode, for the life of the daemon.
        self.assertEqual((FAKE_ROOT, None), got)
        self.assertEqual(1, aegis._CUSTODY_PROBE_FAILURES)
        # Remembered for THIS scan, as a non-answer: every later file in the
        # repo costs a lookup, not another round of timeouts.
        self.assertEqual((FAKE_ROOT, None),
                         aegis._REPO_SELFNESS_CACHE.get(FAKE_ROOT))
        before = len(asked)
        self.assertIsNone(aegis._build_output_rung(self.binary))
        self.assertIsNone(aegis._build_output_rung(
            os.path.join(self.dist, "sibling")))
        self.assertEqual(before, len(asked),
                         "the same scan asked git again: %r" % asked[before:])
        self.assertNotIn(self.dist, aegis._BUILD_OUTPUT_CACHE)
        self.assertEqual(1, aegis._CUSTODY_PROBE_FAILURES,
                         "one question git did not answer, however many "
                         "files asked it")
        # ...and for this scan ONLY.
        aegis._reset_custody_probes()
        self.assertNotIn(FAKE_ROOT, aegis._REPO_SELFNESS_CACHE)

    def test_every_custody_probe_that_times_out_is_a_non_answer(self):
        self._pin_a_fleet_roster()
        cases = {
            "rev-parse": {},
            "head": {},
            "config": {},
            "reflog": {},
            # The fleet rung is asked only after the reflog has said no.
            "signature": {"reflog": ("", "", 0)},
        }
        for question, setup in sorted(cases.items()):
            with self.subTest(question=question):
                self._clear_caches()
                aegis._CUSTODY_PROBE_FAILURES = 0
                answers = dict(setup)
                answers[question] = TIMED_OUT
                asked = self._fake_git(**answers)
                got = aegis._repo_is_self_committed("git", self.dist)
                self.assertIn(question, asked)
                self.assertIsNotNone(got, "a timeout read as 'no repo'")
                self.assertIsNone(got[1], "a timeout read as an answer")
                if question == "rev-parse":
                    # Not "this directory is in no repo", either: remembered
                    # as the sentinel, which is not None.
                    self.assertIs(aegis._GIT_NO_ANSWER,
                                  aegis._REPO_ROOT_CACHE.get(self.dist))
                    self.assertEqual({}, aegis._REPO_SELFNESS_CACHE)
                else:
                    self.assertEqual({FAKE_ROOT: (FAKE_ROOT, None)},
                                     aegis._REPO_SELFNESS_CACHE)
                self.assertEqual(1, aegis._CUSTODY_PROBE_FAILURES)
                before = len(asked)
                self.assertIsNone(aegis._build_output_rung(self.binary))
                self.assertEqual(before, len(asked), asked[before:])
                self.assertEqual({}, aegis._BUILD_OUTPUT_CACHE)
                self.assertEqual(1, aegis._CUSTODY_PROBE_FAILURES)

    def test_a_timed_out_check_ignore_is_not_a_no(self):
        asked = self._fake_git(**{"check-ignore": TIMED_OUT})
        self.assertIsNone(aegis._build_output_rung(self.binary))
        # Remembered for this scan as the sentinel -- None would be the
        # ANSWER "not build output".
        self.assertIs(aegis._GIT_NO_ANSWER,
                      aegis._BUILD_OUTPUT_CACHE.get(self.dist))
        self.assertEqual(1, aegis._CUSTODY_PROBE_FAILURES)
        # The repo's selfness WAS answered, and stays remembered.
        self.assertEqual((FAKE_ROOT, True),
                         aegis._REPO_SELFNESS_CACHE.get(FAKE_ROOT))
        # A sibling costs a lookup, and the sentinel never escapes: every
        # caller reads this rung for truth, and the sentinel is truthy.
        before = len(asked)
        self.assertIsNone(aegis._build_output_rung(
            os.path.join(self.dist, "sibling")))
        self.assertEqual(before, len(asked), asked[before:])
        self.assertEqual(1, aegis._CUSTODY_PROBE_FAILURES)

    def test_an_answer_from_either_rung_still_stands(self):
        """One rung timing out does not void the other's answer: a verified
        fleet signature is a yes whatever the reflog did."""
        self._pin_a_fleet_roster()
        self._fake_git(reflog=TIMED_OUT, signature=("G\n", "", 0))
        self.assertEqual((FAKE_ROOT, True),
                         aegis._repo_is_self_committed("git", self.dist))
        self.assertIn(FAKE_ROOT, aegis._REPO_SELFNESS_CACHE)
        self.assertEqual(0, aegis._CUSTODY_PROBE_FAILURES)

        # ...and a yes from the reflog never asks the fleet rung at all.
        self._clear_caches()
        asked = self._fake_git(signature=TIMED_OUT)
        self.assertEqual((FAKE_ROOT, True),
                         aegis._repo_is_self_committed("git", self.dist))
        self.assertNotIn("signature", asked)
        self.assertEqual(0, aegis._CUSTODY_PROBE_FAILURES)

    def test_the_first_answer_after_a_timeout_is_the_grade(self):
        for question in ("rev-parse", "head", "check-ignore"):
            with self.subTest(question=question):
                self._clear_caches()
                self._fake_git(**{question: TIMED_OUT})
                self.assertIsNone(aegis._build_output_rung(self.binary))
                # The next scan starts clean and asks a git that answers.
                aegis._reset_custody_probes()
                self._fake_git()
                self.assertEqual("build-output",
                                 aegis._build_output_rung(self.binary))
                self.assertEqual("build-output",
                                 aegis._BUILD_OUTPUT_CACHE[self.dist])

    # ---- the caches are per scan ---------------------------------------------

    def test_the_git_caches_do_not_outlive_a_scan(self):
        aegis._REPO_ROOT_CACHE["/seeded"] = "/seeded"
        aegis._REPO_ROOT_CACHE["/timed-out"] = aegis._GIT_NO_ANSWER
        aegis._REPO_SELFNESS_CACHE["/seeded"] = ("/seeded", False)
        aegis._REPO_SELFNESS_CACHE["/timed-out"] = ("/timed-out", None)
        aegis._BUILD_OUTPUT_CACHE["/seeded/dist"] = None
        aegis._BUILD_OUTPUT_CACHE["/timed-out/dist"] = aegis._GIT_NO_ANSWER
        aegis._CUSTODY_PROBE_FAILURES = 3
        aegis._reset_custody_probes()
        self.assertEqual({}, aegis._REPO_ROOT_CACHE)
        self.assertEqual({}, aegis._REPO_SELFNESS_CACHE)
        self.assertEqual({}, aegis._BUILD_OUTPUT_CACHE)
        self.assertEqual(0, aegis._CUSTODY_PROBE_FAILURES)

    @needs_real_scan_lock
    def test_a_scan_starts_clean_and_reports_what_did_not_answer(self):
        """cmd_watch runs every scan in-process, so the reset has to happen
        inside the scan, before any sensor grades a binary. gather_all is
        replaced so the scan is cheap and so it can look at the caches at
        the moment sensors would."""
        seen = {}

        def sensors(baseline_snap, current_snap, health=None):
            seen["selfness"] = dict(aegis._REPO_SELFNESS_CACHE)
            seen["build"] = dict(aegis._BUILD_OUTPUT_CACHE)
            aegis._CUSTODY_PROBE_FAILURES += seen.get("fail", 0)
            return []

        self._saved["gather_all"] = aegis.gather_all
        aegis.gather_all = sensors

        def custody_row():
            rows = [r for r in aegis.get_sensor_health()
                    if r["sensor_id"] == "custody.grade"]
            self.assertEqual(1, len(rows), rows)
            return rows[0]

        aegis._REPO_SELFNESS_CACHE["/seeded"] = ("/seeded", False)
        aegis._BUILD_OUTPUT_CACHE["/seeded/dist"] = None
        aegis._CUSTODY_PROBE_FAILURES = 5
        seen["fail"] = 2
        aegis.cmd_scan(quiet=True)
        self.assertEqual({}, seen["selfness"],
                         "a previous scan's answer was still standing")
        self.assertEqual({}, seen["build"])
        row = custody_row()
        self.assertEqual("DEGRADED", row["status"])
        self.assertEqual(2, row["item_count"],
                         "the count must be this scan's, not the daemon's")
        self.assertIn("2 custody probe(s) timed out", row["detail"])

        seen["fail"] = 0
        aegis.cmd_scan(quiet=True)
        row = custody_row()
        self.assertEqual("OK", row["status"])
        self.assertEqual(0, row["item_count"])
        self.assertEqual("", row["detail"] or "")



# --------------------------------------------------------------------------- #
# A2 -- the exit half of A: a verdict that flips on the same bytes closes what
# the wrong verdict opened.
# --------------------------------------------------------------------------- #
T0 = 1_700_000_000
REMOTE = "203.0.113.7"          # TEST-NET-3: an address that routes nowhere
ELSEWHERE = "/Applications/Other.app/Contents/MacOS/Other"


def _untrusted():
    """A verdict suspicious_sig() flags on THIS body, read from the function
    rather than assumed: Linux flags only `broken`, and CI runs Linux."""
    return next(t for t in ("unsigned", "broken") if aegis.suspicious_sig(t))


def _publisher():
    """A verdict publisher_sig() accepts on THIS body."""
    return next(t for t in ("developer-id", "signed-valid", "os-managed")
                if aegis.publisher_sig(t))


def _health(sensor, status="OK"):
    """One sensor_status row, in the shape _collect_sensor appends."""
    return [{"sensor_id": sensor, "status": status, "detail": "",
             "duration_ms": 0, "item_count": 0}]


class A2AFlippedVerdictClosesItsIncident(Sandbox):
    """Fixing the classifier stops the emission; this is the exit for what the
    wrong verdict had already opened.

    classify_signature and is_risky_location are replaced, so what is under
    test is the closer's reading of its own evidence against the emitting
    sensor's gate, on every body."""

    def setUp(self):
        super().setUp()
        # setdefault: on Windows the Sandbox has already replaced
        # classify_signature, and its ORIGINAL is what tearDown must restore.
        for name in ("classify_signature", "is_risky_location"):
            self._saved.setdefault(name, getattr(aegis, name))
        self.verdict = _untrusted()
        self.risky = False
        self.classified = []

        def classify(path):
            self.classified.append(path)
            return {"trust": self.verdict, "team": None, "authority": None}
        aegis.classify_signature = classify
        aegis.is_risky_location = lambda path: self.risky
        self.path = os.path.join(self.tmp, "Example")
        with open(self.path, "wb") as fh:
            fh.write(b"\xcf\xfa\xed\xfe fixture bytes")

    # ---- fixtures ------------------------------------------------------------

    def _beacon(self, severity="HIGH", fingerprint=None):
        """A beacon as _beacon_from_sightings emits it: path == program, the
        trust it was gated on, and no sha -- the sensor's gate is path-level."""
        key = fingerprint or "beacon:%s:%s:443" % (self.path, REMOTE)
        return aegis.finding(
            severity, "net-beacon",
            "Persistent outbound connection (beacon shape)",
            "%s [%s] has held a connection to %s:443"
            % (self.path, _untrusted(), REMOTE),
            key, case_fingerprint=key, path=self.path, program=self.path,
            remote=REMOTE, port="443", trust=_untrusted(),
            sensor_id="outbound")

    def _process(self, sha):
        """A process case as check_processes emits it: path-keyed signal,
        sha-keyed case, and the sha in the evidence."""
        return aegis.finding(
            "HIGH", "process", "Suspicious running process",
            "%s (%s) running from user-writable path"
            % (self.path, _untrusted()),
            "process:%s:%s:%s" % (self.path, _untrusted(), sha),
            case_fingerprint="process:sha:%s" % sha, path=self.path,
            trust=_untrusted(), sha256=sha, sensor_id="process")

    def _row(self, f):
        db = aegis._event_connection()
        try:
            r = db.execute(
                "SELECT * FROM incidents WHERE correlation_key=?",
                ("signal:" + (f.get("case_fingerprint") or f["fingerprint"]),)
            ).fetchone()
            return dict(r) if r else None
        finally:
            db.close()

    def _open(self, f, sensor):
        aegis.record_security_state([f], sensor_health=_health(sensor),
                                    now=T0)
        row = self._row(f)
        self.assertEqual("OPEN", row["status"], "fixture did not open")
        return row

    def _rescan(self, sensor, status="OK", findings=(), at=T0 + 600):
        aegis.record_security_state(list(findings),
                                    sensor_health=_health(sensor, status),
                                    now=at)

    # ---- the exit ------------------------------------------------------------

    def test_a_flipped_verdict_closes_the_beacon_it_opened(self):
        f = self._beacon()
        self._open(f, "outbound")
        # The classifier answers now: a publisher signed these bytes. The
        # outbound sensor ran, answered OK, and no longer emits the beacon.
        self.verdict = _publisher()
        self._rescan("outbound")
        row = self._row(f)
        # BEFORE: OPEN, with no exit but the age-out clock. No new evidence,
        # so the re-grade exit never fired; a beacon is an event, so the
        # cleared-state exit never looked. Live: #528-#533, #535, #536.
        self.assertEqual("FALSE_POSITIVE", row["status"],
                         "a corrected verdict could not reach the incident "
                         "the wrong one opened")
        self.assertIn("re-verified", row["resolution"] or "")
        self.assertIn(_publisher(), row["resolution"] or "")
        self.assertIn(self.path, self.classified)

    def test_a_failed_sensor_leaves_it_standing(self):
        f = self._beacon()
        self._open(f, "outbound")
        self.verdict = _publisher()
        self._rescan("outbound", "FAILED")
        self.assertEqual("OPEN", self._row(f)["status"],
                         "a sensor that did not answer was read as having "
                         "stopped asserting the case")
        # ...nor one that did not run at all this scan.
        self._rescan("process", at=T0 + 1200)
        self.assertEqual("OPEN", self._row(f)["status"])

    def test_still_suspicious_stays_open(self):
        f = self._beacon()
        self._open(f, "outbound")
        self._rescan("outbound")
        self.assertEqual("OPEN", self._row(f)["status"])

    def test_a_probe_that_does_not_answer_now_is_not_a_flip(self):
        """A1's rule, from the other side: `unknown` is a non-answer, and a
        non-answer closes nothing."""
        f = self._beacon()
        self._open(f, "outbound")
        self.verdict = "unknown"
        self._rescan("outbound")
        self.assertEqual("OPEN", self._row(f)["status"])

    def test_a_risky_location_stays_open(self):
        """The beacon gate is `suspicious_sig(trust) or
        is_risky_location(path)`: a publisher signature answers only the
        first half, and the sensor would still emit on the second."""
        f = self._beacon()
        self._open(f, "outbound")
        self.verdict = _publisher()
        self.risky = True
        self._rescan("outbound")
        self.assertEqual("OPEN", self._row(f)["status"])

    def test_a_path_that_is_gone_stays_open(self):
        """Nothing is left to re-verify; the other exits own a vanished file."""
        f = self._beacon()
        self._open(f, "outbound")
        os.remove(self.path)
        self.verdict = _publisher()
        del self.classified[:]
        self._rescan("outbound")
        self.assertEqual("OPEN", self._row(f)["status"])
        self.assertNotIn(self.path, self.classified)

    def test_a_process_case_with_moved_bytes_stays_open(self):
        """A content-keyed case is about BYTES. A signed binary put where the
        flagged one stood is a different subject, and replacing the file must
        not be a way to close the case."""
        f = self._process(aegis.sha256(self.path))
        self._open(f, "process")
        with open(self.path, "wb") as fh:
            fh.write(b"\xcf\xfa\xed\xfe other, signed-looking bytes")
        self.verdict = _publisher()
        self._rescan("process")
        self.assertEqual("OPEN", self._row(f)["status"],
                         "a replaced binary closed the case its "
                         "predecessor opened")

    def test_a_process_case_with_the_same_bytes_closes(self):
        f = self._process(aegis.sha256(self.path))
        self._open(f, "process")
        self.verdict = _publisher()
        self._rescan("process")
        row = self._row(f)
        self.assertEqual("FALSE_POSITIVE", row["status"])
        self.assertIn("same bytes", row["resolution"] or "")

    def test_a_verdict_about_another_file_is_not_re_asked(self):
        """The evidence's trust must be a verdict ABOUT its path. A
        persistence item records its PROGRAM's trust against the item's own
        path; re-classifying the item answers a different question."""
        f = aegis.finding(
            "HIGH", "persistence", "New persistence item",
            "com.example.agent -> %s [%s]" % (ELSEWHERE, _untrusted()),
            "persistence:new:%s:abc" % self.path, path=self.path,
            program=ELSEWHERE, trust=_untrusted(), sensor_id="persistence")
        self._open(f, "persistence")
        self.verdict = _publisher()
        self._rescan("persistence")
        self.assertEqual("OPEN", self._row(f)["status"])

    # ---- the sensor still asserting it outranks the re-check -----------------

    def test_an_observed_fingerprint_is_left_to_the_regrade_exit(self):
        f = self._beacon()
        self._open(f, "outbound")
        self.verdict = _publisher()
        # The sensor still emits the case this scan: whatever the closer's own
        # re-check says, the sensor's answer is the one on the record, and the
        # re-grade exit reads it.
        self._rescan("outbound", findings=[f])
        self.assertEqual("OPEN", self._row(f)["status"])

    def test_either_fingerprint_counts_as_observed(self):
        """A process case is keyed on its sha; its signal on its path. Seeing
        EITHER this scan means the sensor re-asserted the case."""
        sha = aegis.sha256(self.path)
        f = self._process(sha)
        row = self._open(f, "process")
        self.verdict = _publisher()
        now = T0 + 600
        for observed in ({f["case_fingerprint"]}, {f["fingerprint"]}):
            with self.subTest(observed=observed):
                db = aegis._event_connection()
                try:
                    with db:
                        aegis._record_health(db, _health("process"), now)
                        self.assertEqual(0, aegis._close_reverified_incidents(
                            db, observed, now))
                finally:
                    db.close()
                self.assertEqual("OPEN", self._row(f)["status"])
        # ...and record_security_state hands the closer both.
        seen = []
        real = aegis._close_reverified_incidents
        self._saved.setdefault("_close_reverified_incidents", real)

        def spy(db, observed, now):
            seen.append(set(observed))
            return real(db, observed, now)
        aegis._close_reverified_incidents = spy
        self._rescan("process", findings=[f], at=now + 600)
        self.assertEqual(1, len(seen))
        self.assertIn(f["fingerprint"], seen[0])
        self.assertIn(f["case_fingerprint"], seen[0])
        self.assertEqual("OPEN", self._row(f)["status"])
        self.assertEqual(row["id"], self._row(f)["id"])

    # ---- the re-grade exit's discipline --------------------------------------

    def test_severity_is_never_rewritten(self):
        f = self._beacon()
        self._open(f, "outbound")
        self.verdict = _publisher()
        self._rescan("outbound")
        row = self._row(f)
        self.assertEqual("FALSE_POSITIVE", row["status"])
        self.assertEqual("HIGH", row["severity"],
                         "the ratchet: a machine exit closes the case and "
                         "never rewrites what the operator was shown")

    def test_no_dismissals_row_is_written(self):
        """A machine verdict must never feed backtest precision or acquired
        tolerance -- the discipline every machine exit holds."""
        f = self._beacon()
        self._open(f, "outbound")
        self.verdict = _publisher()
        self._rescan("outbound")
        self.assertEqual("FALSE_POSITIVE", self._row(f)["status"])
        db = aegis._event_connection()
        try:
            self.assertEqual(
                0, db.execute("SELECT COUNT(*) FROM dismissals").fetchone()[0])
        finally:
            db.close()

    def test_an_acknowledged_incident_is_the_operators(self):
        f = self._beacon()
        row = self._open(f, "outbound")
        db = aegis._event_connection()
        try:
            with db:
                db.execute("UPDATE incidents SET status='ACK' WHERE id=?",
                           (row["id"],))
        finally:
            db.close()
        self.verdict = _publisher()
        self._rescan("outbound")
        self.assertEqual("ACK", self._row(f)["status"])

    def test_critical_is_never_closed_this_way(self):
        f = self._beacon(severity="CRITICAL")
        self._open(f, "outbound")
        self.verdict = _publisher()
        self._rescan("outbound")
        self.assertEqual("OPEN", self._row(f)["status"])

    def test_a_never_tolerate_key_is_never_closed_this_way(self):
        """Attack-defined evidence: no machine re-check reads it away, even
        where its evidence could be read as a signature gate."""
        f = self._beacon(fingerprint="decoy:replaced:%s" % self.path)
        row = self._open(f, "outbound")
        self.assertEqual("HIGH", row["severity"],
                         "fixture: must fail on the prefix, not on CRITICAL")
        self.verdict = _publisher()
        self._rescan("outbound")
        self.assertEqual("OPEN", self._row(f)["status"])


if __name__ == "__main__":
    unittest.main()
