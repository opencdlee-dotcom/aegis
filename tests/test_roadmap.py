#!/usr/bin/env python3
"""Regression suite for the roadmap detectors added by the /doit build.

One test (or small cluster) per new capability, each written so it would FAIL
against the pre-build code (the detector / behavior did not exist). Reuses the
fully-sandboxed Sandbox base from test_regression, so this NEVER touches real
~/.aegis, reads the live host, or fires a notification. Stdlib-only.

Covers: dead-man's-switch heartbeat + watchdog (#1), HMAC trust-store watermark
(#5), agent-skill sensor (#6), auth-session sensor (#7), outbound exfil (#4),
syspolicy-deny harvest (#3), timestomp (#8), residual-ASEP coverage (#9),
confidence axis + routing gate + risk accumulator (#2), and the Bastion/XPdb
opt-in tier (#10).
"""
import json
import os
import sqlite3
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # for sibling import
import aegis  # noqa: E402
from test_regression import Sandbox  # noqa: E402


# --------------------------------------------------------------------------- #
# #1 — dead-man's-switch heartbeat + watchdog
# --------------------------------------------------------------------------- #
class TestHeartbeat(Sandbox):
    def test_write_and_read_beat_local_only_by_default(self):
        # No URL configured → NO network call is even attempted.
        called = {"n": 0}
        self._saved["_post_heartbeat"] = aegis._post_heartbeat
        aegis._post_heartbeat = lambda *a, **k: called.__setitem__("n", called["n"] + 1)
        beat = aegis.write_heartbeat(status="ok", alerts=2, top_alert="x")
        self.assertEqual(called["n"], 0, "must not POST when no URL configured")
        self.assertEqual(aegis.read_heartbeat()["alerts"], 2)
        self.assertTrue(aegis.read_heartbeat()["epoch"])

    def test_off_host_post_only_when_url_set(self):
        called = {"url": None}
        self._saved["_post_heartbeat"] = aegis._post_heartbeat
        aegis._post_heartbeat = lambda url, beat: called.__setitem__("url", url)
        aegis.save_json(aegis.AEGIS_CONFIG, {"heartbeat_url": "https://hb.example/beat"})
        aegis.write_heartbeat()
        self.assertEqual(called["url"], "https://hb.example/beat")

    def test_watchdog_ok_on_fresh_beat_stale_on_old(self):
        aegis.write_heartbeat()
        self.assertEqual(aegis.cmd_watchdog(), 0)
        self.assertFalse(os.path.exists(aegis.WATCHDOG_ALERT))
        # Backdate the beat well past tolerance → stale → alarm + durable sentinel.
        aegis.save_json(aegis.HEARTBEAT_FILE,
                        {"epoch": int(time.time()) - aegis.HEARTBEAT_STALE_SECS - 60,
                         "pid": 1})
        self.assertEqual(aegis.cmd_watchdog(), 1)
        self.assertTrue(os.path.exists(aegis.WATCHDOG_ALERT))
        # Recovery clears the sentinel.
        aegis.write_heartbeat()
        self.assertEqual(aegis.cmd_watchdog(), 0)
        self.assertFalse(os.path.exists(aegis.WATCHDOG_ALERT))

    def test_watchdog_quiet_before_first_scan(self):
        # No heartbeat AND no baseline → a fresh install is not "dead".
        self.assertEqual(aegis.cmd_watchdog(), 0)


# --------------------------------------------------------------------------- #
# #5 — HMAC-watermarked trust-store tamper evidence
# --------------------------------------------------------------------------- #
class TestHmacWatermark(Sandbox):
    def _seed_baseline(self):
        aegis.save_json(aegis.BASELINE, {"persistence": {}, "trust": "verified"})
        aegis.record_selfstate()

    def test_clean_baseline_no_finding_and_mac_recorded(self):
        self._seed_baseline()
        st = aegis.load_json(aegis.SELFSTATE, {})
        self.assertTrue(st.get("baseline_mac"), "HMAC watermark must be recorded")
        self.assertEqual([f for f in aegis.check_self_protection()
                          if f["category"] == "self-protection"
                          and "baseline" in f["title"]], [])

    def test_out_of_band_edit_is_caught(self):
        self._seed_baseline()
        # Attacker edits the baseline to bless their own persistence.
        aegis.save_json(aegis.BASELINE, {"persistence": {"/evil.plist": "x"},
                                         "trust": "verified"})
        fps = [f["fingerprint"] for f in aegis.check_self_protection()]
        self.assertTrue(any("self:baseline:tampered" in fp for fp in fps))

    def test_recomputed_sha_still_caught_by_mac(self):
        # The core win over a plain-sha watermark: an attacker who edits the file
        # AND recomputes its sha256 (what most tooling does) still can't forge the
        # keyed MAC. Simulate: rewrite baseline, set baseline_sha to the NEW
        # content's sha, but the recorded MAC is still the old one.
        self._seed_baseline()
        aegis.save_json(aegis.BASELINE, {"persistence": {"/evil.plist": "x"}})
        st = aegis.load_json(aegis.SELFSTATE, {})
        st["baseline_sha"] = aegis.sha256(aegis.BASELINE)  # forged plain hash
        aegis.save_json(aegis.SELFSTATE, st)
        fps = [f["fingerprint"] for f in aegis.check_self_protection()]
        self.assertTrue(any("self:baseline:tampered" in fp for fp in fps),
                        "MAC must catch an edit even when the sha was recomputed")


# --------------------------------------------------------------------------- #
# #6 — AI-agent skill sensor
# --------------------------------------------------------------------------- #
class TestAgentSkills(Sandbox):
    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.tmp, "skills")
        os.makedirs(self.root)
        aegis.AGENT_SKILL_ROOTS = [self.root]

    def _skill(self, name, body="do a thing"):
        d = os.path.join(self.root, name)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "SKILL.md"), "w") as f:
            f.write(body)
        return d

    def test_new_skill_flagged_medium(self):
        self._skill("evil-helper")
        cur = aegis.snapshot_agent_skills()
        fs = aegis.diff_agent_skills({}, cur)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["severity"], "MEDIUM")
        self.assertEqual(fs[0]["category"], "agent-skill")
        self.assertIn("new", fs[0]["fingerprint"])

    def test_changed_skill_is_low_confidence(self):
        self._skill("helper", "v1")
        prior = aegis.snapshot_agent_skills()
        self._skill("helper", "v2 now curls a payload")
        cur = aegis.snapshot_agent_skills()
        fs = aegis.diff_agent_skills(prior, cur)
        self.assertEqual(len(fs), 1)
        # A skills author edits constantly → changed must NOT page (low conf).
        self.assertEqual(fs[0]["confidence"], "low")
        self.assertIn("changed", fs[0]["fingerprint"])

    def test_unchanged_never_realerts(self):
        self._skill("helper")
        snap = aegis.snapshot_agent_skills()
        self.assertEqual(aegis.diff_agent_skills(snap, snap), [])


# --------------------------------------------------------------------------- #
# #7 — auth-session sensor
# --------------------------------------------------------------------------- #
class TestAuthSessions(unittest.TestCase):
    def test_parse_who_keeps_remote_drops_local(self):
        text = ("user console  Jul 21 10:42\n"
                "user ttys001  Jul 21 13:51\n"
                "user ttys004  Jul 22 09:00 (10.0.0.9)\n")
        remote = aegis._parse_who_remote(text)
        self.assertEqual(len(remote), 1)
        self.assertIn("user@10.0.0.9:ttys004", remote)

    def test_new_remote_session_is_high(self):
        prior = {}
        cur = {"user@10.0.0.9:ttys004": "10.0.0.9"}
        fs = aegis.diff_auth_sessions(prior, cur)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["severity"], "HIGH")
        self.assertEqual(fs[0]["category"], "auth-session")

    def test_snapshot_none_on_hard_fail(self):
        saved = aegis.WHO_CMD
        try:
            aegis.WHO_CMD = ["/usr/bin/false"]  # rc 1 — but who never 124/127 here
            # A missing binary (127) is the true non-answer:
            aegis.WHO_CMD = ["/nonexistent/who"]
            self.assertIsNone(aegis.snapshot_auth_sessions())
        finally:
            aegis.WHO_CMD = saved


# --------------------------------------------------------------------------- #
# #4 — outbound exfil
# --------------------------------------------------------------------------- #
class TestOutbound(Sandbox):
    def test_parse_netstat_established(self):
        text = (
            "Active Internet connections\n"
            "tcp4  0 0 10.0.0.2.52840 142.251.45.10.443 ESTABLISHED 5120 2332 1 1 "
            "Google Chrome He:59518 00102\n"
            "tcp4  0 0 10.0.0.2.52802 34.149.66.165.443 ESTABLISHED 0 0 1 1 "
            "claude:25023 00102\n"
            "tcp4  0 0 127.0.0.1.53 127.0.0.1.5000 ESTABLISHED 0 0 1 1 loop:1 00\n"
            "tcp4  0 0 10.0.0.2.111 1.2.3.4.80 LISTEN 0 0 1 1 srv:9 00\n")
        rows = aegis._parse_netstat_established(text)
        peers = {(r[0], r[2], r[3]) for r in rows}
        self.assertIn(("Google Chrome He", "142.251.45.10", "443"), peers)
        self.assertIn(("claude", "34.149.66.165", "443"), peers)
        # loopback dropped, LISTEN (not ESTABLISHED) dropped
        self.assertFalse(any(r[2].startswith("127.") for r in rows))
        self.assertEqual(len(rows), 2)

    def test_adhoc_binary_in_risky_path_flagged_signed_not(self):
        risky = os.path.join(self.tmp, "payload")  # tmp is a risky prefix
        aegis.RISKY_PREFIXES = tuple(set(aegis.RISKY_PREFIXES) | {self.tmp})
        self.adhoc_binary(risky)
        f = aegis._outbound_finding(risky, "45.94.47.145", "8080")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "MEDIUM")
        self.assertIn("outbound-exfil", f["markers"])
        # A system-signed binary talking out is normal → no finding.
        self.assertIsNone(aegis._outbound_finding("/bin/ls", "45.94.47.145", "80"))


# --------------------------------------------------------------------------- #
# #3 — syspolicy / Gatekeeper deny harvest
# --------------------------------------------------------------------------- #
class TestSyspolicyHarvest(unittest.TestCase):
    def test_parse_denials(self):
        text = "\n".join([
            json.dumps({"eventMessage": "GKE: assessment denied /tmp/x",
                        "timestamp": "2026-07-22 09:00"}),
            json.dumps({"eventMessage": "assessment ok for /Applications/Safari"}),
            json.dumps({"eventMessage": "blocked launch of com.evil"}),
            "not json at all",
            "[1,2,3]",  # valid non-object json
        ])
        hits = aegis._parse_syspolicy_denials(text)
        msgs = [m for m, _ in hits]
        self.assertEqual(len(hits), 2)
        self.assertTrue(any("denied" in m for m in msgs))
        self.assertTrue(any("blocked" in m for m in msgs))

    def test_check_security_log_emits_medium_low(self):
        fixture = json.dumps({"eventMessage": "GKE: assessment denied /tmp/x",
                              "timestamp": "t"})
        saved = aegis.run
        try:
            aegis.run = lambda cmd, timeout=15: (fixture, "", 0)
            fs = aegis.check_security_log()
            self.assertEqual(len(fs), 1)
            self.assertEqual(fs[0]["severity"], "MEDIUM")
            self.assertEqual(fs[0]["confidence"], "low")  # below notify floor
        finally:
            aegis.run = saved

    def test_check_security_log_empty_on_failure(self):
        saved = aegis.run
        try:
            aegis.run = lambda cmd, timeout=15: ("", "timeout", 124)
            self.assertEqual(aegis.check_security_log(), [])
        finally:
            aegis.run = saved


# --------------------------------------------------------------------------- #
# #8 — timestomp
# --------------------------------------------------------------------------- #
class TestTimestomp(Sandbox):
    def test_backdated_mtime_detected(self):
        p = os.path.join(self.tmp, "f")
        with open(p, "w") as f:
            f.write("x")
        old = time.time() - 400 * 86400
        os.utime(p, (old, old))  # mtime backdated; ctime stays ~now
        self.assertIsNotNone(aegis.timestomp_signal(p))

    def test_normal_file_clean(self):
        p = os.path.join(self.tmp, "g")
        with open(p, "w") as f:
            f.write("x")
        self.assertIsNone(aegis.timestomp_signal(p))

    def test_hotdir_flags_backdated_drop_that_mtime_would_skip(self):
        # A payload whose mtime is backdated 400 days (older than the 14-day hot
        # window) is NORMALLY skipped by check_hot_dirs' mtime cutoff — the exact
        # evasion. With ctime recent, timestomp must un-skip and flag it HIGH.
        p = os.path.join(self.hot, "payload")
        self.adhoc_binary(p)
        old = time.time() - 400 * 86400
        os.utime(p, (old, old))
        fs = aegis.check_hot_dirs()
        hot = [f for f in fs if f["category"] == "hot-dir"]
        self.assertTrue(hot, "backdated adhoc drop must not be aged out")
        self.assertEqual(hot[0]["severity"], "HIGH")
        self.assertIn("timestomp", hot[0].get("markers") or [])


# --------------------------------------------------------------------------- #
# #9 — residual ASEP persistence coverage
# --------------------------------------------------------------------------- #
class TestResidualAsep(unittest.TestCase):
    def test_asep_dirs_in_default_coverage(self):
        joined = " ".join(aegis.EXTRA_PERSIST_DIRS)
        for needle in ("SecurityAgentPlugins", "Spotlight", "QuickLook",
                       "ScriptingAdditions", "Folder Actions"):
            self.assertIn(needle, joined, "%s must be watched" % needle)


# --------------------------------------------------------------------------- #
# #2 — confidence axis + routing gate + risk accumulator
# --------------------------------------------------------------------------- #
class TestConfidenceAndRisk(Sandbox):
    def test_low_confidence_high_does_not_notify(self):
        hi_med = aegis.finding("HIGH", "x", "loud", "d", "fp1", confidence="medium")
        hi_low = aegis.finding("HIGH", "x", "quiet", "d", "fp2", confidence="low")
        notified = aegis.emit([hi_med, hi_low], first_run=False)
        titles = [f["title"] for f in notified]
        self.assertIn("loud", titles)
        self.assertNotIn("quiet", titles, "low-confidence HIGH must route below "
                         "the notify floor")

    def test_risk_accumulates_three_mediums_on_one_entity(self):
        entity = "/Users/Shared/thing"
        fs = [aegis.finding("MEDIUM", "net-outbound", "o%d" % i, "d",
                            "fp-%d" % i, path=entity, confidence="medium")
              for i in range(3)]
        aegis.record_security_state(fs)
        risk = [i for i in aegis.list_incidents() if i["title"].startswith(
            "Accumulated risk")]
        self.assertTrue(risk, "3 MEDIUMs on one entity should open a risk incident")

    def test_single_medium_does_not_open_risk(self):
        f = aegis.finding("MEDIUM", "net-outbound", "one", "d", "solo",
                          path="/Users/Shared/x", confidence="medium")
        aegis.record_security_state([f])
        risk = [i for i in aegis.list_incidents() if i["title"].startswith(
            "Accumulated risk")]
        self.assertEqual(risk, [])


# --------------------------------------------------------------------------- #
# #10 — Bastion / XPdb opt-in tier
# --------------------------------------------------------------------------- #
class TestBastion(Sandbox):
    def _fake_xpdb(self):
        p = os.path.join(self.tmp, "XPdb")
        con = sqlite3.connect(p)
        con.execute("CREATE TABLE violations(rule TEXT, process TEXT, "
                    "target TEXT, timestamp TEXT)")
        con.execute("INSERT INTO violations VALUES(?,?,?,?)",
                    ("BrowserData", "/tmp/evil", "~/Library/.../Cookies", "t"))
        con.commit()
        con.close()
        return p

    def test_parse_xpdb_rows(self):
        rows = aegis._parse_xpdb(self._fake_xpdb())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "BrowserData")
        self.assertEqual(rows[0][1], "/tmp/evil")

    def test_parse_xpdb_garbage_never_raises(self):
        p = os.path.join(self.tmp, "notadb")
        with open(p, "w") as f:
            f.write("garbage")
        self.assertEqual(aegis._parse_xpdb(p), [])

    def test_bastion_cmd_absent_db_returns_2(self):
        aegis.XPDB_PATH = os.path.join(self.tmp, "no-such-xpdb")
        self.assertEqual(aegis.cmd_bastion(), 2)


if __name__ == "__main__":
    unittest.main()
