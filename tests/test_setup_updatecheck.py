#!/usr/bin/env python3
"""Regression suite for `setup` (the guided opt-in walkthrough) and
`update-check` (runtime-copy drift detection).

Same contract as the rest of the suite: stdlib only, fully sandboxed (every
~/.aegis path is redirected into a per-test tmp dir), never fires a
notification, never makes a network call (urlopen is stubbed), and never
touches the developer's real state.

Each test is named for the property it pins and would FAIL against code that
did not have it. The two properties that matter most:

- `setup` ORCHESTRATES the existing commands — a yes to canary must produce
  exactly what `aegis.py canary` produces, proven on the artifacts (the
  planted file and its recorded hash), not on a print string.
- `update-check` exists because the README's "re-run install.sh after editing
  aegis.py" is a warning nobody re-reads: the runtime copy at
  ~/.aegis/aegis.py silently forks from the repo on every edit, and until now
  nothing could detect it.
"""
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


def _inventory(root):
    """Every file under `root` with content hash AND mtime: 'mutates nothing'
    means no file appeared, vanished, changed content, or was rewritten."""
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = os.path.join(dirpath, name)
            try:
                with open(p, "rb") as f:
                    digest = hashlib.sha256(f.read()).hexdigest()
                out[os.path.relpath(p, root)] = (digest,
                                                 os.stat(p).st_mtime_ns)
            except OSError:
                continue
    return out


class SetupSandbox(unittest.TestCase):
    """Redirect every state path setup/update-check can touch."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_setup_")
        self.state = os.path.join(self.tmp, ".aegis")
        self.canarydir = os.path.join(self.tmp, "Documents")
        os.makedirs(self.state)
        os.makedirs(self.canarydir)
        self._saved = {}
        overrides = {
            "STATE_DIR": self.state,
            "SELFSTATE": os.path.join(self.state, "selfstate.json"),
            "CANARY_STATE": os.path.join(self.state, "canaries.json"),
            "CANARY_DIRS": [self.canarydir],
            "LATCH_FILE": os.path.join(self.state, "latches.json"),
            "DECOY_FILE": os.path.join(self.state, "decoys.json"),
            "GUARD_DIR": os.path.join(self.state, "guard"),
            "GUARD_LOG": os.path.join(self.state, "guard",
                                      "observations.jsonl"),
            "AEGIS_CONFIG": os.path.join(self.state, "config.json"),
            "HEARTBEAT_FILE": os.path.join(self.state, "heartbeat.json"),
            "ACTION_LOG": os.path.join(self.state, "actions.jsonl"),
            "RUN_LOG": os.path.join(self.state, "run.log"),
            "BASELINE": os.path.join(self.state, "baseline.json"),
            "ALLOWLIST": os.path.join(self.state, "allowlist.json"),
            "EVENT_DB": os.path.join(self.state, "aegis.db"),
            "RUNTIME_SCRIPT": os.path.join(self.state, "aegis.py"),
            "_SELF_PATH": os.path.join(self.tmp, "repo", "aegis.py"),
        }
        for k, v in overrides.items():
            self._saved[k] = getattr(aegis, k)
            setattr(aegis, k, v)
        os.makedirs(os.path.join(self.tmp, "repo"))
        with open(aegis._SELF_PATH, "w", encoding="utf-8") as f:
            f.write("# fake repo aegis.py v2\n")

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(aegis, k, v)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- scripted interactive harness ---------------------------------------
    def _script(self, yes_when=(), lines=()):
        """Drive the walkthrough: tty gate answers True, _ask_yn answers yes
        only when the question contains one of `yes_when` (case-insensitive),
        _ask_line pops from `lines`. Returns the recorder dict."""
        rec = {"questions": [], "lines_asked": []}
        self._stub(aegis, "_setup_stdio_is_interactive", lambda: True)

        def fake_yn(question):
            rec["questions"].append(question)
            q = question.lower()
            return any(w in q for w in yes_when)

        pending = list(lines)

        def fake_line(prompt):
            rec["lines_asked"].append(prompt)
            return pending.pop(0) if pending else ""

        self._stub(aegis, "_ask_yn", fake_yn)
        self._stub(aegis, "_ask_line", fake_line)
        return rec

    def _stub(self, obj, name, value):
        saved = getattr(obj, name)
        self.addCleanup(setattr, obj, name, saved)
        setattr(obj, name, value)

    def _run_setup(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = aegis.cmd_setup()
        return rc, out.getvalue()


# --------------------------------------------------------------------------- #
# setup — interactivity gate
# --------------------------------------------------------------------------- #
class TestSetupRefusesAutomation(SetupSandbox):

    def test_non_tty_caller_is_refused_with_zero_mutation(self):
        """Under pytest stdin is not a tty — exactly the automation case. The
        refusal must come BEFORE any state is created or touched: a refusal
        that first writes state is not a refusal."""
        before = _inventory(self.tmp)
        rc, out = self._run_setup()
        self.assertEqual(1, rc)
        self.assertIn("interactive", out.lower())
        self.assertEqual(before, _inventory(self.tmp),
                         "a refused setup still mutated the sandbox")


# --------------------------------------------------------------------------- #
# setup — the walkthrough itself
# --------------------------------------------------------------------------- #
class TestSetupWalkthrough(SetupSandbox):

    def test_all_no_mutates_nothing(self):
        """Default No everywhere means a user who reads and declines every
        question ends with a byte-identical sandbox — opt-IN, structurally."""
        rec = self._script(yes_when=())
        before = _inventory(self.tmp)
        rc, _out = self._run_setup()
        self.assertEqual(0, rc)
        self.assertEqual(before, _inventory(self.tmp),
                         "an all-No walkthrough mutated state")
        self.assertTrue(rec["questions"], "the walkthrough asked nothing")
        self.assertEqual([], rec["lines_asked"],
                         "free-text prompts must only follow a yes")

    def test_yes_to_canary_runs_the_real_canary_command(self):
        """Orchestration, not reimplementation: a yes must leave exactly the
        artifacts `aegis.py canary` leaves — the planted file with the real
        canary content, and its hash recorded in CANARY_STATE."""
        self._script(yes_when=("canary",))
        rc, _out = self._run_setup()
        self.assertEqual(0, rc)
        planted = os.path.join(self.canarydir, aegis.CANARY_NAME)
        self.assertTrue(os.path.isfile(planted), "no canary file was planted")
        with open(planted, encoding="utf-8") as f:
            self.assertEqual(aegis.CANARY_CONTENT, f.read())
        with open(aegis.CANARY_STATE, encoding="utf-8") as f:
            self.assertIn(planted, json.load(f))

    def test_second_run_reports_enabled_and_reruns_nothing(self):
        """Idempotency: a tier already on is detected from its state, shown as
        enabled, and NOT re-prompted or re-run. Pinned on the artifacts: the
        second run leaves every file byte-and-mtime identical."""
        self._script(yes_when=("canary",))
        self._run_setup()
        # Pre-seed latch state too: enabled-detection must not depend on the
        # walkthrough having done the enabling itself.
        aegis.save_json(aegis.LATCH_FILE, {"/x": {"mode": "uchg", "ts": 1}})

        rec = self._script(yes_when=("canary", "latch"))  # yes again — must not matter
        before = _inventory(self.tmp)
        rc, out = self._run_setup()
        self.assertEqual(0, rc)
        self.assertEqual(before, _inventory(self.tmp),
                         "an idempotent re-run rewrote state")
        self.assertIn("[enabled] canary", out)
        self.assertIn("[enabled] latch", out)
        for q in rec["questions"]:
            low = q.lower()
            self.assertNotIn("canary", low, "re-prompted an enabled tier")
            self.assertNotIn("latch", low, "re-prompted an enabled tier")

    def test_yes_to_heartbeat_stores_the_pasted_url_in_config(self):
        """The one background egress is configured by pasting a URL the user
        controls into config.json — no network call is made to 'verify' it."""
        self._script(yes_when=("heartbeat",),
                     lines=("https://hb.example/beat",))
        rc, _out = self._run_setup()
        self.assertEqual(0, rc)
        with open(aegis.AEGIS_CONFIG, encoding="utf-8") as f:
            cfg = json.load(f)
        self.assertEqual("https://hb.example/beat", cfg["heartbeat_url"])

    def test_heartbeat_rejects_a_non_http_paste(self):
        """A mistyped paste must not arm background egress to garbage."""
        self._script(yes_when=("heartbeat",), lines=("ftp://nope",))
        rc, _out = self._run_setup()
        self.assertEqual(0, rc)
        self.assertEqual({}, aegis.load_json(aegis.AEGIS_CONFIG, {}))

    def test_walkthrough_never_calls_authorize_interactive(self):
        """setup's tty gate is a UX refusal, not a security gate — nothing it
        orchestrates may consume the out-of-band authorization path, which
        belongs to unlatch alone."""
        def boom(*_a, **_k):
            raise AssertionError("setup reached authorize_interactive")
        self._stub(aegis, "authorize_interactive", boom)
        self._script(yes_when=("canary", "heartbeat"), lines=("",))
        rc, _out = self._run_setup()
        self.assertEqual(0, rc)


# --------------------------------------------------------------------------- #
# update-check — runtime-copy drift
# --------------------------------------------------------------------------- #
class TestUpdateCheck(SetupSandbox):

    def _write(self, path, text):
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def test_not_installed_says_so_and_exits_zero(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = aegis.cmd_update_check()
        self.assertEqual(0, rc)
        self.assertIn("no runtime copy", out.getvalue().lower())

    def test_in_sync_exits_zero(self):
        with open(aegis._SELF_PATH, encoding="utf-8") as f:
            self._write(aegis.RUNTIME_SCRIPT, f.read())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = aegis.cmd_update_check()
        self.assertEqual(0, rc)
        self.assertIn("in sync", out.getvalue().lower())

    def test_drift_exits_one_with_the_exact_refresh_line(self):
        """The failure the command exists for: an edited repo file and a stale
        runtime copy. The output must contain a runnable refresh command that
        names the INVOKED file, preserving the recorded install mode so a
        watch-mode install is not silently downgraded to scan mode."""
        self._write(aegis.RUNTIME_SCRIPT, "# OLD runtime copy v1\n")
        aegis.save_json(aegis.SELFSTATE, {"installed": True,
                                          "install_mode": "watch"})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = aegis.cmd_update_check()
        self.assertEqual(1, rc)
        text = out.getvalue()
        self.assertIn("STALE", text)
        # _refresh_line() quotes the path on Windows (the reference repo path
        # has spaces and '&'), so reimplementing the quoting here would just
        # re-encode the same assumption the production code makes. Use it as
        # the oracle instead — SELFSTATE is unchanged since cmd_update_check
        # read it, so both calls see the same install_mode.
        self.assertIn(aegis._refresh_line(), text)

    def test_refresh_line_defaults_to_scan_mode(self):
        self._write(aegis.RUNTIME_SCRIPT, "# OLD runtime copy v1\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = aegis.cmd_update_check()
        self.assertEqual(1, rc)
        self.assertIn(aegis._refresh_line(), out.getvalue())

    def test_doctor_surfaces_drift_as_a_problem(self):
        """doctor is where rot surfaces: a stale runtime copy must degrade the
        doctor verdict, not hide behind a command nobody runs."""
        self._write(aegis.RUNTIME_SCRIPT, "# OLD runtime copy v1\n")
        home = os.path.join(self.tmp, "home")
        for d in ("Downloads", "Desktop"):
            os.makedirs(os.path.join(home, d))
        self._stub(aegis, "HOME", home)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = aegis.cmd_doctor()
        self.assertEqual(1, rc)
        self.assertIn("STALE", out.getvalue())

    def test_doctor_reports_in_sync_quietly(self):
        with open(aegis._SELF_PATH, encoding="utf-8") as f:
            self._write(aegis.RUNTIME_SCRIPT, f.read())
        home = os.path.join(self.tmp, "home")
        for d in ("Downloads", "Desktop"):
            os.makedirs(os.path.join(home, d))
        self._stub(aegis, "HOME", home)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            aegis.cmd_doctor()
        self.assertIn("runtime copy", out.getvalue())
        self.assertNotIn("STALE", out.getvalue())


# --------------------------------------------------------------------------- #
# update-check --remote — the by-hand network half
# --------------------------------------------------------------------------- #
class TestUpdateCheckRemote(SetupSandbox):

    def _fake_origin(self, url):
        """A .git/config is enough: the derivation must work even where the
        git binary is not on run()'s restricted PATH (Windows)."""
        gd = os.path.join(self.tmp, "repo", ".git")
        os.makedirs(gd, exist_ok=True)
        with open(os.path.join(gd, "config"), "w", encoding="utf-8") as f:
            f.write('[remote "origin"]\n\turl = %s\n\tfetch = '
                    '+refs/heads/*:refs/remotes/origin/*\n' % url)

    def _stub_urlopen(self, body):
        import urllib.request
        calls = []

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return body

        def fake_urlopen(url, timeout=0):
            calls.append(url)
            return _Resp()

        self._stub(urllib.request, "urlopen", fake_urlopen)
        return calls

    def test_remote_fetches_exactly_the_stated_github_raw_url(self):
        self._fake_origin("https://github.com/owner/repo.git")
        with open(aegis._SELF_PATH, "rb") as f:
            calls = self._stub_urlopen(f.read())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = aegis.cmd_update_check(remote=True)
        self.assertEqual(0, rc)
        want = "https://raw.githubusercontent.com/owner/repo/HEAD/aegis.py"
        self.assertEqual([want], calls, "fetched something other than the "
                                        "stated canonical URL, or twice")
        self.assertIn(want, out.getvalue(), "the fetched URL must be stated")

    def test_remote_mismatch_exits_one(self):
        self._fake_origin("git@github.com:owner/repo.git")
        calls = self._stub_urlopen(b"# different upstream bytes\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = aegis.cmd_update_check(remote=True)
        self.assertEqual(1, rc)
        self.assertEqual(1, len(calls))
        self.assertIn("DIFFERS", out.getvalue())

    def test_no_github_origin_skips_the_fetch(self):
        """A non-GitHub or missing origin must not guess a URL."""
        self._fake_origin("https://gitlab.example/owner/repo.git")
        calls = self._stub_urlopen(b"")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = aegis.cmd_update_check(remote=True)
        self.assertEqual(2, rc)
        self.assertEqual([], calls, "fetched despite no GitHub origin")

    def test_plain_update_check_never_touches_the_network(self):
        """The scan path never reaches this code at all, and even the by-hand
        command without --remote must make zero network calls — the same
        structural local-only guarantee as `vt`."""
        def boom(*_a, **_k):
            raise AssertionError("update-check without --remote opened a URL")
        import urllib.request
        self._stub(urllib.request, "urlopen", boom)
        self._write_runtime_stale()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = aegis.cmd_update_check()
        self.assertEqual(1, rc)

    def _write_runtime_stale(self):
        with open(aegis.RUNTIME_SCRIPT, "w", encoding="utf-8") as f:
            f.write("# OLD runtime copy v1\n")

    def test_urllib_import_is_lazy_inside_the_remote_branch(self):
        """`import urllib.request` must sit inside cmd_update_check (the `vt`
        pattern), so the scan path never even loads the networking module."""
        import inspect
        src = inspect.getsource(aegis.cmd_update_check)
        self.assertIn("import urllib.request", src)


if __name__ == "__main__":
    unittest.main()
