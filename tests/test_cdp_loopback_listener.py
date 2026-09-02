"""Browser-in-the-Middle, technique (1): CDP enabled IN MEMORY.

check_browser_automation catches a browser STARTED with
--remote-debugging-port. The BOF-style attack injects into the running
browser and enables CDP with no flag anywhere, and the only unprivileged
trace is a new loopback TCP listener on the browser process — which every
listener parser here dropped by design (dev servers churn on 127.0.0.1).

What these hold:
  * every parser keeps its default (loopback dropped) byte-for-byte and
    answers the inverse question on request;
  * only a BROWSER's loopback bind becomes a key, and not when the flag is on
    its command line (that is the argv sensor's finding, not a second one);
  * the key diffs to a HIGH session-theft finding;
  * each platform's snapshot reaches the key from its own substrate.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling import
import aegis  # noqa: E402

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
LSOF = ("p633\nczotero\nLuser\nf30\nn127.0.0.1:23119\n"
        "p636\ncCC\nf8\nn*:7000\nf9\nn[::1]:8080\nf10\nn[fe80::1]:9999\n"
        "p4242\ncGoogle\nf11\nn127.0.0.1:9222\n")
PROC_TCP = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
            "retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:2406 00000000:0000 0A 00000000:00000000 00:00000000 "
            "00000000   501        0 77001 1 0 100 0 0 10 0\n"
            "   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 "
            "00000000     0        0 77002 1 0 100 0 0 10 0\n")
NETSTAT = ("  TCP    127.0.0.1:9222         0.0.0.0:0              LISTENING       4242\n"
           "  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       5\n")


class TestParsersKeepTheirDefault(unittest.TestCase):
    def test_lsof_default_unchanged_and_inverse_on_request(self):
        self.assertEqual({"636": {"*:7000", "[fe80::1]:9999"}},
                         aegis._parse_lsof_listeners(LSOF))
        self.assertEqual({"633": {"127.0.0.1:23119"}, "636": {"[::1]:8080"},
                          "4242": {"127.0.0.1:9222"}},
                         aegis._parse_lsof_listeners(LSOF, loopback=True))

    def test_proc_net_tcp_default_unchanged_and_inverse_on_request(self):
        self.assertEqual([("80", "0", "77002")],
                         aegis._parse_proc_net_tcp(PROC_TCP))
        self.assertEqual([("9222", "501", "77001")],
                         aegis._parse_proc_net_tcp(PROC_TCP, loopback=True))

    def test_netstat_default_unchanged_and_inverse_on_request(self):
        self.assertEqual([("80", "5")],
                         aegis._parse_netstat_listen_windows(NETSTAT))
        self.assertEqual([("9222", "4242")],
                         aegis._parse_netstat_listen_windows(NETSTAT,
                                                             loopback=True))


class TestOnlyABrowserWithoutTheFlagIsAKey(unittest.TestCase):
    def test_browser_without_flag_is_keyed(self):
        self.assertEqual({"loopback:%s:9222" % CHROME: CHROME},
                         aegis._browser_loopback_entries(
                             [(CHROME, "9222", CHROME)]))

    def test_windows_and_linux_spellings_are_browsers(self):
        for exe in (r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                    "/usr/lib/chromium/chromium", "/opt/brave.com/brave/brave"):
            self.assertEqual(1, len(aegis._browser_loopback_entries(
                [(exe, "9222", exe)])), exe)

    def test_flagged_browser_belongs_to_the_argv_sensor(self):
        self.assertEqual({}, aegis._browser_loopback_entries(
            [(CHROME, "9222", CHROME + " --remote-debugging-port=9222")]))

    def test_dev_server_and_unresolved_pid_are_silent(self):
        self.assertEqual({}, aegis._browser_loopback_entries([
            ("/usr/local/bin/node", "3000", "node server.js"),
            ("/usr/bin/python3", "8000", "python3 -m http.server"),
            (None, "9222", ""), ("", "9222", None)]))


class TestDiffGradesIt(unittest.TestCase):
    def test_new_loopback_key_is_high_session_theft(self):
        key = "loopback:%s:9222" % CHROME
        fs = aegis.diff_listeners({}, {key: CHROME})
        self.assertEqual(1, len(fs))
        f = fs[0]
        self.assertEqual(("HIGH", "session-theft", "high", "9222"),
                         (f["severity"], f["category"], f["confidence"],
                          f["port"]))
        self.assertEqual("listener:" + key, f["fingerprint"])
        self.assertIn("no --remote-debugging-port", f["detail"])

    def test_baselined_key_stays_silent(self):
        cur = {"loopback:%s:9222" % CHROME: CHROME}
        self.assertEqual([], aegis.diff_listeners(dict(cur), cur))


class _Procs(unittest.TestCase):
    ROWS = [("4242", "501", CHROME, CHROME),
            ("633", "501", "/usr/local/bin/zotero", "zotero"),
            ("5", "0", "/usr/sbin/httpd", "httpd")]

    def setUp(self):
        self._iter = aegis._iter_processes
        aegis._iter_processes = lambda: iter(self.ROWS)

    def tearDown(self):
        aegis._iter_processes = self._iter


@unittest.skipUnless(aegis.IS_MAC, "lsof substrate")
class TestMacSnapshotReachesTheKey(_Procs):
    def test_snapshot_carries_the_browser_loopback_key(self):
        saved = aegis.run

        def fake_run(cmd, **kw):
            if cmd == aegis.LSOF_LISTEN_CMD:
                return LSOF, "", 0
            if cmd[:3] == ["ps", "-o", "comm="]:
                return "/usr/local/bin/CC", "", 0
            raise AssertionError("unexpected command %r" % (cmd,))
        aegis.run = fake_run
        try:
            snap = aegis.snapshot_listeners()
        finally:
            aegis.run = saved
        self.assertIn("loopback:%s:9222" % CHROME, snap)
        self.assertNotIn("loopback:/usr/local/bin/zotero:23119", snap)
        self.assertIn("/usr/local/bin/CC:7000", snap)     # regular path intact


class TestWindowsSnapshotReachesTheKey(_Procs):
    def test_snapshot_carries_the_browser_loopback_key(self):
        saved = aegis._NETSTAT_SNAPSHOT
        aegis._NETSTAT_SNAPSHOT = (NETSTAT, 0)
        try:
            snap = aegis._snapshot_listeners_windows()
        finally:
            aegis._NETSTAT_SNAPSHOT = saved
        self.assertIn("loopback:%s:9222" % CHROME, snap)


class TestLinuxSnapshotReachesTheKey(_Procs):
    def test_snapshot_carries_the_browser_loopback_key(self):
        saved = (aegis._read_text, aegis._SOCKET_INODE_SNAPSHOT,
                 aegis._listener_worth_tracking)
        aegis._read_text = lambda p, **kw: PROC_TCP if p == "/proc/net/tcp" \
            else None
        aegis._SOCKET_INODE_SNAPSHOT = {"77001": "4242"}
        aegis._listener_worth_tracking = lambda p: False   # no readlink path
        try:
            snap = aegis._snapshot_listeners_linux()
        finally:
            (aegis._read_text, aegis._SOCKET_INODE_SNAPSHOT,
             aegis._listener_worth_tracking) = saved
        self.assertIn("loopback:%s:9222" % CHROME, snap)


class TestAssayLane(unittest.TestCase):
    def test_cdp_loopback_lane_exists_and_passes(self):
        lanes = {lane_id: fn for lane_id, _d, fn in aegis._assay_lanes()}
        self.assertIn("cdp-loopback", lanes)
        self.assertTrue(lanes["cdp-loopback"]("n0nce"))


if __name__ == "__main__":
    unittest.main()
