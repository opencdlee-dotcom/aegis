#!/usr/bin/env python3
"""Rootwatch (opt-in ROOT witness) — tests-first coverage for the kill gap.

A same-uid attacker can kill Aegis AND the user-level watchdog agent in one
sweep; the notary only makes that evident later. `rootwatch` is the opt-in
answer: a tiny root-owned script on a root schedule that alerts within
minutes. These tests pin its whole contract:

  * the generated privileged script stays small enough to audit in one glance
    (the smallness IS the security argument), imports only the stated stdlib
    modules, and is executed for REAL (as the test user) against a fake
    heartbeat dir — fresh beat exits 0 silently, stale/missing beat appends a
    durable alert line, attempts the user notification (osascript/notify-send
    stubbed via PATH), and NEVER writes into the user's ~/.aegis surrogate;
  * the generated LaunchDaemon plist passes `plutil -lint` (macOS) and the
    systemd system units have the right Linux shape;
  * `rootwatch install` WITHOUT root provably mutates nothing and prints
    exactly one pasteable sudo line — Aegis never self-elevates.

Fully sandboxed like the rest of the suite: every ROOTWATCH_* path is
redirected into a per-test tmp dir; nothing here touches real /Library,
/etc, /var or ~/.aegis, and no real launchctl/systemctl/sudo ever runs.
"""
import contextlib
import io
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

IS_POSIX = os.name == "posix"

# Modules the privileged script is allowed to import — the audit budget the
# task and the script's own header comment both promise.
_ALLOWED_IMPORTS = {"json", "os", "subprocess", "sys", "time"}
_LINE_BUDGET = 60


def _inventory(root):
    """Names + sizes of everything under root — before/after mutation proof."""
    inv = {}
    for base, dirs, files in os.walk(root):
        for n in dirs:
            inv[os.path.join(base, n)] = "dir"
        for n in files:
            p = os.path.join(base, n)
            try:
                inv[p] = os.stat(p).st_size
            except OSError:
                inv[p] = "unstattable"
    return inv


def _imported_names(text):
    names = set()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("import "):
            for tok in line[len("import "):].split(","):
                names.add(tok.strip().split(" as ")[0].split(".")[0])
        elif line.startswith("from "):
            names.add(line.split()[1].split(".")[0])
    return names


class RootwatchSandbox(unittest.TestCase):
    """Redirect every ROOTWATCH_* path (and STATE_DIR) into a throwaway tmp."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_rw_")
        # '&' in the log path exercises the plist XML-escape, the same F0
        # class the installer tests pin.
        self.rootdir = os.path.join(self.tmp, "r & oot")
        self._saved = {}
        overrides = {
            "ROOTWATCH_SCRIPT": os.path.join(self.rootdir, "libexec",
                                             "aegis-rootwatch.py"),
            "ROOTWATCH_PLIST": os.path.join(self.rootdir, "LaunchDaemons",
                                            "com.aegis.rootwatch.plist"),
            "ROOTWATCH_UNIT_DIR": os.path.join(self.rootdir, "systemd"),
            "ROOTWATCH_LOG": os.path.join(self.rootdir, "Aegis",
                                          "rootwatch.log"),
            # NOT created: the non-root paths must never call ensure_state().
            "STATE_DIR": os.path.join(self.tmp, ".aegis"),
        }
        for name, val in overrides.items():
            self._saved[name] = getattr(aegis, name)
            setattr(aegis, name, val)
        # No real launchctl/systemctl query ever runs from these tests.
        self._saved_run = aegis.run
        aegis.run = lambda cmd, timeout=15, extra_env=None: ("", "", 3)

    def tearDown(self):
        aegis.run = self._saved_run
        for name, val in self._saved.items():
            setattr(aegis, name, val)
        shutil.rmtree(self.tmp, ignore_errors=True)


# --------------------------------------------------------------------------- #
# The generated privileged script: shape and audit budget.
# --------------------------------------------------------------------------- #
class TestRootwatchScriptShape(unittest.TestCase):
    def _text(self, mac):
        return aegis._rootwatch_script_text(
            "/home/u/.aegis/heartbeat.json", 501,
            "/var/log/aegis/rootwatch.log", mac=mac)

    def test_script_fits_the_audit_budget(self):
        for mac in (True, False):
            text = self._text(mac)
            self.assertLessEqual(
                len(text.splitlines()), _LINE_BUDGET,
                "the privileged script must stay auditable in one glance "
                "(<= %d lines); it is the ONLY thing Aegis runs as root"
                % _LINE_BUDGET)
            compile(text, "aegis-rootwatch.py", "exec")  # valid python

    def test_script_imports_only_the_stated_stdlib(self):
        for mac in (True, False):
            extra = _imported_names(self._text(mac)) - _ALLOWED_IMPORTS
            self.assertFalse(
                extra, "unexpected imports in the ROOT script: %s" % extra)

    def test_script_bakes_paths_uid_and_watchdog_tolerance(self):
        text = self._text(mac=True)
        self.assertIn("/home/u/.aegis/heartbeat.json", text)
        self.assertIn("501", text)
        self.assertIn("/var/log/aegis/rootwatch.log", text)
        # Reuses cmd_watchdog's tolerance, not a second ad-hoc number.
        self.assertIn(str(aegis.HEARTBEAT_STALE_SECS), text)


# --------------------------------------------------------------------------- #
# The generated LaunchDaemon plist (macOS) and systemd system units (Linux).
# --------------------------------------------------------------------------- #
@unittest.skipUnless(aegis.IS_MAC, "plutil is macOS-only; the Linux unit "
                     "shape is covered below on every platform")
class TestRootwatchPlist(RootwatchSandbox):
    def test_plist_lints_and_targets_root_owned_paths(self):
        text = aegis._rootwatch_plist_text()
        path = os.path.join(self.tmp, "com.aegis.rootwatch.plist")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        lint = subprocess.run(["plutil", "-lint", path],
                              capture_output=True, text=True)
        self.assertIn("OK", lint.stdout, lint.stdout + lint.stderr)
        with open(path, "rb") as f:
            d = plistlib.load(f)
        self.assertEqual(d["Label"], "com.aegis.rootwatch")
        # A root daemon must run the root-owned system interpreter and the
        # root-owned script — never a venv python or a $HOME path.
        self.assertEqual(d["ProgramArguments"],
                         [aegis.ROOTWATCH_PY, aegis.ROOTWATCH_SCRIPT])
        self.assertEqual(d["StartInterval"], aegis.ROOTWATCH_INTERVAL)
        self.assertTrue(d.get("RunAtLoad"))


class TestRootwatchUnits(RootwatchSandbox):
    def test_linux_units_have_system_timer_shape(self):
        service, timer = aegis._rootwatch_unit_texts()
        self.assertIn("Type=oneshot", service)
        self.assertIn('ExecStart="%s" "%s"'
                      % (aegis.ROOTWATCH_PY, aegis.ROOTWATCH_SCRIPT), service)
        self.assertIn("OnUnitActiveSec=%ds" % aegis.ROOTWATCH_INTERVAL, timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("WantedBy=timers.target", timer)


# --------------------------------------------------------------------------- #
# The GENERATED script, executed for real against a fake heartbeat dir.
# --------------------------------------------------------------------------- #
@unittest.skipUnless(IS_POSIX, "executes the generated script with /bin/sh "
                     "PATH stubs for launchctl/osascript/notify-send")
class TestRootwatchScriptExecution(unittest.TestCase):
    UID = 501

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_rwx_")
        self.aegis_dir = os.path.join(self.tmp, "home", ".aegis")
        os.makedirs(self.aegis_dir)
        self.hb = os.path.join(self.aegis_dir, "heartbeat.json")
        self.log = os.path.join(self.tmp, "rootlog", "rootwatch.log")
        self.calls = os.path.join(self.tmp, "calls.log")
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        for name in ("launchctl", "osascript", "logger", "notify-send", "wall"):
            stub = os.path.join(self.bin, name)
            with open(stub, "w") as f:
                f.write('#!/bin/sh\necho "%s $@" >> "%s"\nexit 0\n'
                        % (name, self.calls))
            os.chmod(stub, 0o755)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, mac, beat_epoch="absent"):
        if beat_epoch != "absent":
            with open(self.hb, "w") as f:
                json.dump({"epoch": beat_epoch, "pid": 1234}, f)
        script = os.path.join(self.tmp, "aegis-rootwatch.py")
        with open(script, "w", encoding="utf-8") as f:
            f.write(aegis._rootwatch_script_text(self.hb, self.UID, self.log,
                                                 mac=mac))
        before = _inventory(self.aegis_dir)
        r = subprocess.run(
            [sys.executable, script], capture_output=True, text=True,
            timeout=60, env={"PATH": self.bin, "HOME": self.tmp})
        # The doctrine the script's header states: it NEVER writes into the
        # user's ~/.aegis (root-owned files there would break Aegis's own
        # atomic-replace assumptions).
        self.assertEqual(before, _inventory(self.aegis_dir),
                         "the ROOT script wrote into the user's state dir")
        return r

    def _stub_calls(self):
        if not os.path.exists(self.calls):
            return ""
        with open(self.calls) as f:
            return f.read()

    def test_fresh_beat_exits_zero_silently(self):
        r = self._run(mac=True, beat_epoch=int(time.time()))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, "")
        self.assertEqual(r.stderr, "")
        self.assertFalse(os.path.exists(self.log), "healthy => no alert line")
        self.assertEqual(self._stub_calls(), "", "healthy => no notification")

    def test_stale_beat_alerts_and_notifies_mac_shape(self):
        stale = int(time.time()) - aegis.HEARTBEAT_STALE_SECS - 600
        r = self._run(mac=True, beat_epoch=stale)
        self.assertNotEqual(r.returncode, 0)
        with open(self.log) as f:
            line = f.read()
        self.assertIn("NOT beating", line)
        calls = self._stub_calls()
        self.assertIn("launchctl asuser %d osascript" % self.UID, calls)
        self.assertIn("logger", calls)

    def test_stale_beat_notifies_linux_shape(self):
        stale = int(time.time()) - aegis.HEARTBEAT_STALE_SECS - 600
        r = self._run(mac=False, beat_epoch=stale)
        self.assertNotEqual(r.returncode, 0)
        calls = self._stub_calls()
        self.assertIn("notify-send", calls)
        self.assertIn("wall", calls)
        self.assertIn("logger", calls)

    def test_missing_beat_is_stale_not_healthy(self):
        r = self._run(mac=True, beat_epoch="absent")
        self.assertNotEqual(
            r.returncode, 0,
            "a WIPED ~/.aegis must read as a dead monitor, not a healthy one "
            "(the same suppression cmd_watchdog's `armed` logic closes)")
        with open(self.log) as f:
            self.assertIn("NOT beating", f.read())


# --------------------------------------------------------------------------- #
# `rootwatch` without root: zero mutation, one pasteable line. And status /
# doctor never need root.
# --------------------------------------------------------------------------- #
@unittest.skipUnless(IS_POSIX and os.geteuid() != 0,
                     "needs an unprivileged POSIX user")
class TestRootwatchNonRoot(RootwatchSandbox):
    def _call(self, action):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = aegis.cmd_rootwatch(action)
        return rc, buf.getvalue()

    def test_nonroot_install_mutates_nothing_and_prints_one_pasteable(self):
        before = _inventory(self.tmp)
        rc, out = self._call("install")
        self.assertEqual(rc, 2)
        sudo_lines = [l for l in out.splitlines()
                      if l.strip().startswith("sudo ")]
        self.assertEqual(len(sudo_lines), 1,
                         "exactly ONE pasteable line:\n%s" % out)
        self.assertIn("rootwatch install", sudo_lines[0])
        # Paths are quoted (this repo lives under "Work & Projects").
        self.assertIn('"%s"' % aegis._SELF_PATH, sudo_lines[0])
        self.assertEqual(before, _inventory(self.tmp),
                         "non-root install must perform ZERO mutation")
        self.assertFalse(os.path.exists(aegis.STATE_DIR),
                         "non-root install must not even create state")

    def test_nonroot_uninstall_also_only_prints_the_line(self):
        before = _inventory(self.tmp)
        rc, out = self._call("uninstall")
        self.assertEqual(rc, 2)
        self.assertEqual(
            len([l for l in out.splitlines()
                 if l.strip().startswith("sudo ")]), 1)
        self.assertEqual(before, _inventory(self.tmp))

    def test_status_reports_absent_without_root_or_mutation(self):
        before = _inventory(self.tmp)
        rc, out = self._call("status")
        self.assertEqual(rc, 0)
        self.assertIn("absent", out)
        self.assertIn("kill gap", out)
        self.assertEqual(before, _inventory(self.tmp))

    def test_status_reports_installed_pieces(self):
        for p in (aegis.ROOTWATCH_SCRIPT,
                  aegis.ROOTWATCH_PLIST if aegis.IS_MAC else
                  os.path.join(aegis.ROOTWATCH_UNIT_DIR,
                               "aegis-rootwatch.timer")):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write("x")
        self.assertTrue(aegis._rootwatch_installed())
        rc, out = self._call("status")
        self.assertEqual(rc, 0)
        self.assertIn("installed", out)

    def test_bad_action_prints_usage(self):
        rc, out = self._call("bogus")
        self.assertEqual(rc, 1)
        self.assertIn("usage", out)


class TestRootwatchWindowsHonesty(unittest.TestCase):
    def test_windows_says_future_work_and_refuses(self):
        saved = (aegis.IS_MAC, aegis.IS_LINUX, aegis.IS_WIN)
        aegis.IS_MAC, aegis.IS_LINUX, aegis.IS_WIN = False, False, True
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = aegis.cmd_rootwatch("install")
            self.assertEqual(rc, 2)
            self.assertIn("future work", buf.getvalue())
            self.assertFalse(aegis._rootwatch_installed())
        finally:
            aegis.IS_MAC, aegis.IS_LINUX, aegis.IS_WIN = saved


# --------------------------------------------------------------------------- #
# Doctor tie-in: absence is INFO ("the kill gap is open"), never a problem.
# --------------------------------------------------------------------------- #
@unittest.skipUnless(IS_POSIX, "the rootwatch doctor line is absent on "
                     "Windows, where rootwatch is not built")
class TestRootwatchDoctorLine(RootwatchSandbox):
    def _doctor(self):
        saved = (aegis.get_sensor_health, aegis.list_incidents, aegis.EVENT_DB)
        aegis.get_sensor_health = lambda: []
        aegis.list_incidents = lambda: []
        aegis.EVENT_DB = os.path.join(self.tmp, ".aegis", "aegis.db")
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = aegis.cmd_doctor()
            return rc, buf.getvalue()
        finally:
            (aegis.get_sensor_health, aegis.list_incidents,
             aegis.EVENT_DB) = saved

    def test_absent_is_one_info_line_and_never_degrades(self):
        rc_absent, out = self._doctor()
        self.assertIn("kill gap is open", out)
        self.assertIn("rootwatch install", out)
        # Install the artifacts; the doctor verdict must not change — the
        # rootwatch line is INFO for an opt-in, not a problem.
        for p in (aegis.ROOTWATCH_SCRIPT,
                  aegis.ROOTWATCH_PLIST if aegis.IS_MAC else
                  os.path.join(aegis.ROOTWATCH_UNIT_DIR,
                               "aegis-rootwatch.timer")):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write("x")
        rc_installed, out2 = self._doctor()
        self.assertNotIn("kill gap is open", out2)
        self.assertEqual(rc_absent, rc_installed,
                         "rootwatch presence must not change the verdict")


if __name__ == "__main__":
    unittest.main()
