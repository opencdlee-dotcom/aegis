"""Windows persistence-evasion sensors: COM hijack, IFEO, AppInit_DLLs, Sysmon.

The rung above Run keys/schtasks/Winlogon (which the persistence snapshot
already covers): registry hijack points that execute inside TRUSTED processes,
so no autostart entry ever appears (T1546.015 / .012 / .008 / .010), plus a
narrow harvest of the Sysmon Operational channel where Sysmon is installed.

Same doctrine as test_cross_platform.py: every scoring/parsing function is
pure and runs on every host with text/dict fixtures; the winreg walks execute
end-to-end against a fake winreg module injected into sys.modules (the
WindowsPersistenceLivePlumbing pattern), so no test ever touches a real
registry — and none of these tests writes to ~/.aegis or fires a notification
(diff/parse functions only construct finding dicts).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


# --------------------------------------------------------------------------- #
# Fake winreg (mirrors the stdlib API surface the snapshots use: OpenKey as a
# context manager and on an already-open key, EnumKey/EnumValue ending with
# OSError, QueryValueEx). OSError(2) IS FileNotFoundError in Python 3, so a
# missing key exercises the real-empty branch; _DeniedWinreg exercises the
# non-answer branch with a genuine permission error.
# --------------------------------------------------------------------------- #
class _FakeKey:
    def __init__(self, values=None, subkeys=None):
        self.values = list((values or {}).items())
        self.subkeys = subkeys or {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeWinreg:
    HKEY_CURRENT_USER = "HKCU"
    HKEY_LOCAL_MACHINE = "HKLM"

    def __init__(self, tree):
        # tree: {("HKCU", "Sub\\Key"): _FakeKey}
        self.tree = tree

    def OpenKey(self, hive, subkey):
        if isinstance(hive, _FakeKey):
            child = hive.subkeys.get(subkey)
            if child is None:
                raise OSError(2, "not found")
            return child
        key = self.tree.get((hive, subkey))
        if key is None:
            raise OSError(2, "not found")
        return key

    def EnumKey(self, key, index):
        names = sorted(key.subkeys)
        try:
            return names[index]
        except IndexError:
            raise OSError(259, "no more data")

    def EnumValue(self, key, index):
        try:
            name, val = key.values[index]
        except IndexError:
            raise OSError(259, "no more data")
        return name, val, 1

    def QueryValueEx(self, key, name):
        for k, v in key.values:
            if k == name:
                return v, 1
        raise OSError(2, "no such value")


class _DeniedWinreg(_FakeWinreg):
    def OpenKey(self, hive, subkey):
        raise PermissionError(13, "access denied")


class _WinFlags(unittest.TestCase):
    """Patch the platform flags + prefix tables so is_risky_location grades
    literal Windows paths identically on every host (the established pattern
    from WindowsPersistenceLivePlumbing)."""

    def setUp(self):
        self._saved = {k: getattr(aegis, k) for k in
                       ("IS_WIN", "IS_MAC", "IS_LINUX",
                        "TRUSTED_PREFIXES", "RISKY_PREFIXES")}
        aegis.IS_WIN, aegis.IS_MAC, aegis.IS_LINUX = True, False, False
        aegis.TRUSTED_PREFIXES = ("C:\\Windows\\", "C:\\Program Files\\")
        aegis.RISKY_PREFIXES = ("C:\\Users\\",)

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(aegis, k, v)

    def _winreg(self, fake):
        sys.modules["winreg"] = fake
        self.addCleanup(sys.modules.pop, "winreg", None)


# --------------------------------------------------------------------------- #
# COM hijack (T1546.015): HKCU CLSID server registrations, baseline-diffed
# --------------------------------------------------------------------------- #
class ComHijackDiff(_WinFlags):
    RISKY = "C:\\Users\\bob\\AppData\\Roaming\\evil.dll"
    TRUSTED = "C:\\Program Files\\Vendor\\real.dll"

    def test_new_server_in_user_writable_path_is_high(self):
        fs = aegis.diff_com_hijack(
            {}, {"{018D5C66-4533-4307-9B53-224DE2ED1FE6}\\InprocServer32":
                 self.RISKY})
        self.assertEqual(1, len(fs))
        self.assertEqual("HIGH", fs[0]["severity"])
        self.assertIn("com-hijack", fs[0]["markers"])

    def test_changed_target_into_user_writable_path_is_high(self):
        key = "{018D5C66-4533-4307-9B53-224DE2ED1FE6}\\InprocServer32"
        fs = aegis.diff_com_hijack({key: self.TRUSTED}, {key: self.RISKY})
        self.assertEqual(1, len(fs))
        self.assertEqual("HIGH", fs[0]["severity"])
        self.assertIn("CHANGED", fs[0]["title"])

    def test_new_server_in_program_files_is_silent(self):
        # The benign pole: per-user CLSID registrations pointing at an
        # admin-writable install tree are routine app-install churn.
        fs = aegis.diff_com_hijack(
            {}, {"{AAAA0000-0000-0000-0000-000000000001}\\InprocServer32":
                 self.TRUSTED})
        self.assertEqual([], fs)

    def test_unchanged_entries_are_silent(self):
        snap = {"{X}\\InprocServer32": self.RISKY}
        self.assertEqual([], aegis.diff_com_hijack(snap, snap))

    def test_env_var_target_is_expanded_before_grading(self):
        os.environ["AEGIS_FAKE_ROAMING"] = "C:\\Users\\bob\\AppData\\Roaming"
        self.addCleanup(os.environ.pop, "AEGIS_FAKE_ROAMING", None)
        fs = aegis.diff_com_hijack(
            {}, {"{X}\\InprocServer32": "%AEGIS_FAKE_ROAMING%\\evil.dll"})
        self.assertEqual(1, len(fs))
        self.assertEqual("HIGH", fs[0]["severity"])

    def test_quoted_localserver_command_line_resolves_the_exe(self):
        fs = aegis.diff_com_hijack(
            {}, {"{X}\\LocalServer32":
                 '"C:\\Users\\bob\\AppData\\Local\\srv.exe" /automation'})
        self.assertEqual(1, len(fs))
        self.assertEqual("HIGH", fs[0]["severity"])


class ComHijackSnapshot(_WinFlags):
    def test_clsid_tree_walk_collects_both_server_types(self):
        clsids = _FakeKey(subkeys={
            "{A}": _FakeKey(subkeys={
                "InprocServer32": _FakeKey({"": "C:\\pf\\a.dll",
                                            "ThreadingModel": "Both"})}),
            "{B}": _FakeKey(subkeys={
                "LocalServer32": _FakeKey({"": '"C:\\pf\\b.exe" /auto'})}),
            "{C}": _FakeKey(subkeys={"ProgID": _FakeKey({"": "c.prog"})}),
        })
        self._winreg(_FakeWinreg({("HKCU", aegis._COM_CLSID_KEY): clsids}))
        snap = aegis.snapshot_com_hijack()
        self.assertEqual({"{A}\\InprocServer32": "C:\\pf\\a.dll",
                          "{B}\\LocalServer32": '"C:\\pf\\b.exe" /auto'}, snap)

    def test_missing_clsid_root_is_a_real_empty(self):
        # HKCU\...\CLSID is created by the first per-user registration, so a
        # profile without one has genuinely zero entries — an answer, not a gap.
        self._winreg(_FakeWinreg({}))
        self.assertEqual({}, aegis.snapshot_com_hijack())

    def test_unreadable_registry_is_a_non_answer(self):
        self._winreg(_DeniedWinreg({}))
        self.assertIsNone(aegis.snapshot_com_hijack())


# --------------------------------------------------------------------------- #
# IFEO Debugger + SilentProcessExit (T1546.012 / T1546.008)
# --------------------------------------------------------------------------- #
class IfeoDiff(unittest.TestCase):
    PAYLOAD = "C:\\Users\\bob\\AppData\\Roaming\\shell.exe"

    def test_new_debugger_on_each_accessibility_binary_is_critical(self):
        # Writing this needs admin; READING it does not, and the value
        # appearing is the signal regardless of who wrote it. sethc.exe-class
        # binaries launch from the LOCK SCREEN, so this is the pre-auth
        # sticky-keys backdoor.
        for exe in ("sethc.exe", "utilman.exe", "osk.exe", "magnify.exe",
                    "narrator.exe", "displayswitch.exe"):
            fs = aegis.diff_ifeo({}, {"debugger:%s" % exe: self.PAYLOAD})
            self.assertEqual(1, len(fs), exe)
            self.assertEqual("CRITICAL", fs[0]["severity"], exe)

    def test_new_debugger_on_any_other_binary_is_high(self):
        fs = aegis.diff_ifeo({}, {"debugger:chrome.exe": self.PAYLOAD})
        self.assertEqual(1, len(fs))
        self.assertEqual("HIGH", fs[0]["severity"])

    def test_new_monitorprocess_is_high(self):
        fs = aegis.diff_ifeo({}, {"monitor:notepad.exe": self.PAYLOAD})
        self.assertEqual(1, len(fs))
        self.assertEqual("HIGH", fs[0]["severity"])

    def test_changed_debugger_is_reported(self):
        key = "debugger:sethc.exe"
        fs = aegis.diff_ifeo({key: "C:\\old\\dbg.exe"}, {key: self.PAYLOAD})
        self.assertEqual(1, len(fs))
        self.assertEqual("CRITICAL", fs[0]["severity"])
        self.assertIn("CHANGED", fs[0]["title"])

    def test_preexisting_entry_adopted_at_baseline_is_silent(self):
        # The benign pole: a developer's vsjitdebugger registration that was
        # present when the surface was first sighted must never re-alert.
        snap = {"debugger:myapp.exe":
                '"C:\\Windows\\system32\\vsjitdebugger.exe"'}
        self.assertEqual([], aegis.diff_ifeo(snap, snap))


class IfeoSnapshot(_WinFlags):
    def test_debugger_and_monitorprocess_values_are_snapshotted(self):
        ifeo = _FakeKey(subkeys={
            "sethc.exe": _FakeKey({"Debugger": "C:\\evil\\d.exe"}),
            "myapp.exe": _FakeKey({"MitigationOptions": 256}),
        })
        spe = _FakeKey(subkeys={
            "notepad.exe": _FakeKey({"MonitorProcess": "C:\\evil\\m.exe"}),
        })
        self._winreg(_FakeWinreg({("HKLM", aegis._WIN_IFEO_KEY): ifeo,
                                  ("HKLM", aegis._WIN_SPE_KEY): spe}))
        snap = aegis.snapshot_ifeo()
        self.assertEqual({"debugger:sethc.exe": "C:\\evil\\d.exe",
                          "monitor:notepad.exe": "C:\\evil\\m.exe"}, snap)

    def test_missing_keys_are_a_real_empty(self):
        self._winreg(_FakeWinreg({}))
        self.assertEqual({}, aegis.snapshot_ifeo())

    def test_unreadable_registry_is_a_non_answer(self):
        self._winreg(_DeniedWinreg({}))
        self.assertIsNone(aegis.snapshot_ifeo())


# --------------------------------------------------------------------------- #
# AppInit_DLLs (T1546.010)
# --------------------------------------------------------------------------- #
class AppInitDiff(unittest.TestCase):
    def test_value_appearing_is_high(self):
        fs = aegis.diff_appinit(
            {}, {aegis._WIN_APPINIT_KEYS[0]: "C:\\Users\\b\\evil.dll"})
        self.assertEqual(1, len(fs))
        self.assertEqual("HIGH", fs[0]["severity"])

    def test_value_changing_is_high(self):
        key = aegis._WIN_APPINIT_KEYS[0]
        fs = aegis.diff_appinit({key: "old.dll"}, {key: "new.dll"})
        self.assertEqual(1, len(fs))
        self.assertEqual("HIGH", fs[0]["severity"])
        self.assertIn("CHANGED", fs[0]["title"])

    def test_stable_value_is_silent(self):
        snap = {aegis._WIN_APPINIT_KEYS[0]: "corp-mandated.dll"}
        self.assertEqual([], aegis.diff_appinit(snap, snap))


class AppInitSnapshot(_WinFlags):
    def test_nonempty_value_captured_and_empty_skipped(self):
        self._winreg(_FakeWinreg({
            ("HKLM", aegis._WIN_APPINIT_KEYS[0]):
                _FakeKey({"AppInit_DLLs": "C:\\x\\hook.dll",
                          "LoadAppInit_DLLs": 1}),
            ("HKLM", aegis._WIN_APPINIT_KEYS[1]):
                _FakeKey({"AppInit_DLLs": "  "}),
        }))
        self.assertEqual({aegis._WIN_APPINIT_KEYS[0]: "C:\\x\\hook.dll"},
                         aegis.snapshot_appinit())

    def test_unreadable_registry_is_a_non_answer(self):
        self._winreg(_DeniedWinreg({}))
        self.assertIsNone(aegis.snapshot_appinit())


# --------------------------------------------------------------------------- #
# Sysmon harvest: EID 1 (ProcessCreate), 6 (driver loaded), 25 (tampering)
# --------------------------------------------------------------------------- #
_EID1 = ("Process Create: RuleName: - UtcTime: 2026-08-10 14:03:22.001 "
         "ProcessGuid: {a23eae89-bd56-5903-0000-0010e9d95e00} ProcessId: 6228 "
         "Image: %(image)s FileVersion: - Description: - Product: - Company: - "
         "OriginalFileName: x CommandLine: %(cmd)s "
         "CurrentDirectory: C:\\Users\\bob\\ User: DESKTOP-1\\bob "
         "LogonGuid: {a23eae89-0000-0000-0000-000000000000} LogonId: 0x3E7 "
         "TerminalSessionId: 1 IntegrityLevel: Medium Hashes: SHA256=AAAA "
         "ParentProcessGuid: {a23eae89-1111-0000-0000-000000000000} "
         "ParentProcessId: 800 ParentImage: C:\\Windows\\explorer.exe "
         "ParentCommandLine: explorer.exe ParentUser: DESKTOP-1\\bob")

_EID6 = ("Driver loaded: RuleName: - UtcTime: 2026-08-10 13:00:00.000 "
         "ImageLoaded: %(driver)s Hashes: SHA256=BBBB Signed: %(signed)s "
         "Signature: %(sig)s SignatureStatus: %(status)s")

_EID25 = ("Process Tampering: RuleName: - UtcTime: 2026-08-10 15:00:00.000 "
          "ProcessGuid: {a23eae89-2222-0000-0000-000000000000} "
          "ProcessId: 4432 Image: C:\\Users\\bob\\AppData\\Roaming\\svc.exe "
          "Type: Image is replaced User: DESKTOP-1\\bob")

_ENC = ("SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi"
        "AEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA")


def _row(eid, msg):
    return [("Microsoft-Windows-Sysmon/Operational", eid,
             "2026-08-10T14:03:22.0000000Z", msg)]


class SysmonFieldParser(unittest.TestCase):
    def test_image_and_commandline_are_extracted(self):
        msg = _EID1 % {"image": "C:\\Users\\bob\\AppData\\Local\\Temp\\s.exe",
                       "cmd": '"C:\\Users\\bob\\AppData\\Local\\Temp\\s.exe" /S'}
        kv = aegis._parse_sysmon_kv(msg)
        self.assertEqual("C:\\Users\\bob\\AppData\\Local\\Temp\\s.exe",
                         kv["Image"])
        self.assertEqual('"C:\\Users\\bob\\AppData\\Local\\Temp\\s.exe" /S',
                         kv["CommandLine"])
        self.assertEqual("C:\\Windows\\explorer.exe", kv["ParentImage"])

    def test_driver_signature_fields_are_extracted(self):
        kv = aegis._parse_sysmon_kv(_EID6 % {
            "driver": "C:\\Windows\\Temp\\evil.sys", "signed": "false",
            "sig": "-", "status": "Unavailable"})
        self.assertEqual("C:\\Windows\\Temp\\evil.sys", kv["ImageLoaded"])
        self.assertEqual("false", kv["Signed"])
        self.assertEqual("Unavailable", kv["SignatureStatus"])

    def test_garbage_never_raises(self):
        self.assertEqual({}, aegis._parse_sysmon_kv(""))
        self.assertEqual({}, aegis._parse_sysmon_kv("no fields here"))


class SysmonScoring(_WinFlags):
    def test_eid1_hostile_commandline_scores_high(self):
        msg = _EID1 % {"image": "C:\\Windows\\System32\\"
                                "WindowsPowerShell\\v1.0\\powershell.exe",
                       "cmd": "powershell.exe -nop -w hidden -enc " + _ENC}
        fs = aegis._sysmon_findings(_row("1", msg))
        self.assertEqual(1, len(fs))
        self.assertEqual("HIGH", fs[0]["severity"])
        self.assertIn("powershell-encoded-command", fs[0]["markers"])

    def test_eid1_risky_image_alone_is_medium_not_silent(self):
        msg = _EID1 % {"image": "C:\\Users\\bob\\AppData\\Local\\Temp\\s.exe",
                       "cmd": '"C:\\Users\\bob\\AppData\\Local\\Temp\\s.exe" /S'}
        fs = aegis._sysmon_findings(_row("1", msg))
        self.assertEqual(1, len(fs))
        self.assertEqual("MEDIUM", fs[0]["severity"])
        self.assertIn("risky-path-exec", fs[0]["markers"])

    def test_eid1_signed_binary_in_trusted_path_is_silent(self):
        # The benign pole: an ordinary process creation must produce nothing.
        msg = _EID1 % {"image": "C:\\Program Files\\Microsoft Teams\\Teams.exe",
                       "cmd": '"C:\\Program Files\\Microsoft Teams\\Teams.exe" '
                              "--type=renderer"}
        self.assertEqual([], aegis._sysmon_findings(_row("1", msg)))

    def test_eid6_unsigned_driver_is_high(self):
        msg = _EID6 % {"driver": "C:\\Windows\\Temp\\evil.sys",
                       "signed": "false", "sig": "-", "status": "Unavailable"}
        fs = aegis._sysmon_findings(_row("6", msg))
        self.assertEqual(1, len(fs))
        self.assertEqual("HIGH", fs[0]["severity"])
        self.assertIn("unsigned-driver", fs[0]["markers"])

    def test_eid6_validly_signed_driver_is_silent(self):
        msg = _EID6 % {"driver": "C:\\Windows\\System32\\drivers\\rt.sys",
                       "signed": "true", "sig": "Realtek Semiconductor Corp",
                       "status": "Valid"}
        self.assertEqual([], aegis._sysmon_findings(_row("6", msg)))

    def test_eid25_process_tampering_is_high(self):
        fs = aegis._sysmon_findings(_row("25", _EID25))
        self.assertEqual(1, len(fs))
        self.assertEqual("HIGH", fs[0]["severity"])
        self.assertIn("process-tampering", fs[0]["markers"])

    def test_duplicate_events_dedupe_to_one_finding(self):
        rows = _row("25", _EID25) * 3
        self.assertEqual(1, len(aegis._sysmon_findings(rows)))

    def test_unknown_event_ids_are_ignored(self):
        self.assertEqual([], aegis._sysmon_findings(_row("13", "whatever")))


class SysmonProbeContract(unittest.TestCase):
    def _with_run(self, fn, out="", err="", rc=0):
        saved = aegis.run
        aegis.run = lambda cmd, timeout=15, extra_env=None: (out, err, rc)
        try:
            return fn()
        finally:
            aegis.run = saved

    def test_probe_failure_is_a_non_answer(self):
        self.assertIsNone(self._with_run(aegis.check_sysmon_log,
                                         err="boom", rc=1))

    def test_readable_channel_reporting_a_read_error_is_a_non_answer(self):
        # The channel exists but Get-WinEvent failed for a non-"no events"
        # reason: coverage was possible and was not obtained — DEGRADED.
        self.assertIsNone(self._with_run(aegis.check_sysmon_log,
                                         out="sysmon-probe=failed\n", rc=0))

    def test_no_events_in_the_window_is_a_real_empty(self):
        self.assertEqual([], self._with_run(aegis.check_sysmon_log))


class SysmonRegistration(_WinFlags):
    def test_channel_absent_means_sensor_absent_not_degraded(self):
        # Sysmon not installed is a machine without the product — no sensor,
        # no DEGRADED health row, exactly like a launchd check on Linux.
        self._winreg(_FakeWinreg({}))
        self.assertEqual([], aegis._sysmon_sensor())

    def test_channel_present_registers_the_sensor(self):
        self._winreg(_FakeWinreg(
            {("HKLM", aegis._SYSMON_CHANNEL_KEY): _FakeKey()}))
        sensors = aegis._sysmon_sensor()
        self.assertEqual(1, len(sensors))
        self.assertEqual("sysmon-log", sensors[0][0])
        self.assertIs(aegis.check_sysmon_log, sensors[0][1])

    def test_unreadable_channel_key_still_registers(self):
        # Cannot prove absence: register, and let the harvest degrade honestly
        # rather than silently dropping possible coverage.
        self._winreg(_DeniedWinreg({}))
        self.assertEqual(1, len(aegis._sysmon_sensor()))


# --------------------------------------------------------------------------- #
# Registry integrity for the new surfaces
# --------------------------------------------------------------------------- #
class EvasionRegistryIntegrity(unittest.TestCase):
    def test_all_new_entrypoints_exist_everywhere(self):
        for name in ("snapshot_com_hijack", "diff_com_hijack",
                     "snapshot_ifeo", "diff_ifeo",
                     "snapshot_appinit", "diff_appinit",
                     "check_sysmon_log", "_sysmon_sensor"):
            self.assertTrue(callable(getattr(aegis, name, None)),
                            "%s is missing" % name)

    @unittest.skipUnless(aegis.IS_WIN, "surface registry is per-platform")
    def test_windows_registers_the_evasion_surfaces(self):
        keys = {r[0] for r in aegis.SURFACES}
        for key in ("win_com_hijack", "win_ifeo", "win_appinit"):
            self.assertIn(key, keys)

    def test_posix_does_not_register_the_evasion_surfaces(self):
        if aegis.IS_WIN:
            self.skipTest("windows host")
        keys = {r[0] for r in aegis.SURFACES}
        for key in ("win_com_hijack", "win_ifeo", "win_appinit"):
            self.assertNotIn(key, keys)


if __name__ == "__main__":
    unittest.main()
