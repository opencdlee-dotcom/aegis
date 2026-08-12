#!/usr/bin/env python3
"""Regression suite for the 2026-08-12 battle-test findings — one class per fix.

Each test would FAIL against the pre-fix code and passes after it. Stdlib
`unittest` only (matching the tool's own trust model). The state-touching cases
redirect the relevant aegis globals into a per-test tmp dir, so this never reads
or writes real ~/.aegis state.

Findings pinned here:
  F1 osascript password-phish: a fully-functional phish with a >512-char dialog
     MESSAGE padded the single bridged regex's .{0,512} gap and produced NO
     finding at all (README claims CRITICAL). Now scored by ordered token checks.
  F2 redact_sensitive: SCREAMING_SNAKE env-var secrets (DB_PASSWORD=, API_TOKEN=,
     AWS_SECRET_KEY=) were not redacted (the \\b never fires next to `_`), and a
     quoted multi-word flag value leaked its tail past the first space.
  F3 quarantine restore/destroy: an unvalidated qid escaped the store via an
     absolute/`..` path, and cmd_restore had no protected-path refusal on its
     destination (unlike cmd_quarantine/neutralize).
  F4 gui-kill-coercion: a `killall -0 X` liveness probe (signal 0 never kills)
     was scored identically to a real kill loop — a false positive the README's
     benign-use carve-out says must not fire.
  F5 Linux socket-inode map: the full /proc fd-table walk ran twice per scan
     (listeners + outbound); now a scan-scoped cache.
  F6 Windows netstat TCP table: `netstat -ano -p tcp` was spawned twice per scan
     (listeners + outbound); now a scan-scoped cache.
  F7 macOS unified-log harvest: the three independent `log show` sensors (xprotect
     / syspolicy / amfid) ran serially in the sensor loop; now prewarmed
     CONCURRENTLY once per scan into a cache the sensors read (measured 4.8s->2.1s).
  H1 ld-so-preload-write argv idiom: a plain `ld\\.so\\.preload` literal was
     quote-evadable (`/etc/ld.so.pre""load`); now quote-tolerant (coverage widens).
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


def _phish(message):
    """A fully-functional AMOS-style fake password prompt with a given message."""
    return ('osascript -e \'display dialog "%s" default answer "" '
            'with hidden answer\'' % message)


# --------------------------------------------------------------------------- #
# F1 — the phish signal must survive an arbitrarily long dialog message.
# --------------------------------------------------------------------------- #
class TestOsascriptPhishPadding(unittest.TestCase):
    def _sev(self, argv):
        return dict(aegis._argv_signals(argv)).get("osascript-password-phish")

    def test_short_control_is_critical(self):
        self.assertEqual(self._sev(_phish("System update needs your password")),
                         "CRITICAL")

    def test_long_message_phish_still_critical(self):
        # >512 chars of attacker-controlled message text between "display dialog"
        # and the answer keyword — the exact bridge the old regex let padding
        # defeat. The phish is still fully functional.
        msg = ("macOS Security Update Assistant needs to verify your identity to "
               "finish installing critical security updates. ") * 12
        self.assertGreater(len(msg), 512)
        self.assertEqual(self._sev(_phish(msg)), "CRITICAL")

    def test_benign_osascript_not_flagged(self):
        # A dialog with no answer field is not a credential prompt.
        self.assertIsNone(self._sev(
            "osascript -e 'display notification \"build done\"'"))
        self.assertIsNone(self._sev(
            "osascript -e 'display dialog \"Continue?\" buttons {\"OK\"}'"))


# --------------------------------------------------------------------------- #
# F2 — redaction must catch SCREAMING_SNAKE names and whole quoted values.
# --------------------------------------------------------------------------- #
class TestRedactSnakeCaseSecrets(unittest.TestCase):
    def test_screaming_snake_env_secrets_redacted(self):
        for name in ("DB_PASSWORD", "API_TOKEN", "AWS_SECRET_KEY", "MY_API_KEY",
                     "SLACK_SECRET"):
            out = aegis.redact_sensitive("%s=CorrectHorseBatteryStaple9x" % name)
            self.assertNotIn("CorrectHorseBatteryStaple9x", out,
                             "%s value leaked: %r" % (name, out))
            self.assertIn("[REDACTED]", out)

    def test_plain_keyword_still_redacted(self):
        self.assertEqual(aegis.redact_sensitive("password=hunter2"),
                         "password=[REDACTED]")
        self.assertEqual(aegis.redact_sensitive("cookie=abc"), "cookie=[REDACTED]")

    def test_multi_word_quoted_value_fully_redacted(self):
        out = aegis.redact_sensitive(
            'node server.js --password "correct horse battery"')
        self.assertNotIn("horse", out)
        self.assertNotIn("battery", out)
        self.assertIn("[REDACTED]", out)

    def test_no_over_redaction(self):
        # `secret` is a substring of `secretary` but not a `_`-component of it;
        # `--token-count 5` is a flag whose keyword is not at the flag tail.
        self.assertEqual(aegis.redact_sensitive("secretary=Alice"),
                         "secretary=Alice")
        self.assertEqual(aegis.redact_sensitive("--token-count 5"),
                         "--token-count 5")
        self.assertEqual(aegis.redact_sensitive("broken=nope"), "broken=nope")

    def test_secret_does_not_reach_finding_detail(self):
        f = aegis.finding(
            "CRITICAL", "persistence", "Persistence item CHANGED",
            'com.evil.agent: env {"DB_PASSWORD": "CorrectHorseBatteryStaple9x"}',
            "persistence:changed:test")
        self.assertNotIn("CorrectHorseBatteryStaple9x", f["detail"])

    def test_redaction_is_linear_on_pathological_input(self):
        # No ReDoS in the broadened boundary: a long underscored run with no
        # closing separator must return well under a second.
        start = time.time()
        aegis.redact_sensitive(("AB_" * 4000) + "secret=x")
        aegis.redact_sensitive(("A" * 60000) + "_password=x")
        self.assertLess(time.time() - start, 1.0)


# --------------------------------------------------------------------------- #
# F3 — quarantine store confinement + protected-destination refusal.
# --------------------------------------------------------------------------- #
class _StateSandbox(unittest.TestCase):
    """Redirect the durable-state globals into a per-test tmp dir so the response
    verbs' ensure_state()/ensure_quarantine() never touch real ~/.aegis."""

    def setUp(self):
        import shutil
        self._shutil = shutil
        self.tmp = tempfile.mkdtemp(prefix="aegis_bt_")
        state = os.path.join(self.tmp, ".aegis")
        os.makedirs(state)
        self._saved = {}
        for k, v in (("STATE_DIR", state),
                     ("EVENT_DB", os.path.join(state, "aegis.db")),
                     ("QUARANTINE_DIR", os.path.join(state, "quarantine")),
                     ("QUARANTINE_MANIFEST", os.path.join(state, "quarantine",
                                                          "manifest.json")),
                     ("ACTION_LOG", os.path.join(state, "actions.jsonl")),
                     ("RUN_LOG", os.path.join(state, "run.log")),
                     ("HMAC_KEY_FILE", os.path.join(state, "hmac.key"))):
            if hasattr(aegis, k):
                self._saved[k] = getattr(aegis, k)
                setattr(aegis, k, v)

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(aegis, k, v)
        self._shutil.rmtree(self.tmp, ignore_errors=True)


class TestQuarantineQidConfinement(_StateSandbox):
    def test_escape_qids_are_refused(self):
        for bad in ("/tmp/evil", "../escape", "a/b", ".", "..", ""):
            with self.assertRaises(ValueError):
                aegis._quarantine_item(bad)

    def test_legit_qid_resolves_inside_store(self):
        qid = "20260812T120000123456-abcdef0123"
        p = aegis._quarantine_item(qid)
        self.assertEqual(os.path.dirname(p), aegis.QUARANTINE_DIR)
        self.assertEqual(os.path.basename(p), qid)

    def test_restore_and_destroy_reject_escape_qid(self):
        for fn, args in ((aegis.cmd_restore, ("/tmp/evil",)),
                         (aegis.cmd_destroy, ("../escape", True))):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = fn(*args)
            self.assertEqual(rc, 1)
            self.assertIn("no such quarantine id", buf.getvalue())


class TestRestoreRefusesProtectedDest(unittest.TestCase):
    """cmd_restore must never rename a payload INTO a protected path, even if the
    (forged/tampered) txn names one — the arbitrary-file-drop primitive."""

    def setUp(self):
        import shutil
        self._shutil = shutil
        self.tmp = tempfile.mkdtemp(prefix="aegis_bt_")
        state = os.path.join(self.tmp, ".aegis")
        os.makedirs(state)
        # Neutralize the parts of the flow that are not under test so we reach the
        # destination guard: recovery, unseal/seal, identity check, and audit.
        self._saved = {n: getattr(aegis, n) for n in
                       ("STATE_DIR", "QUARANTINE_DIR", "EVENT_DB",
                        "_recover_quarantine_locked", "_unseal", "_seal",
                        "_identity_matches", "log_action", "_quarantine_payload")}
        aegis.STATE_DIR = state
        aegis.QUARANTINE_DIR = os.path.join(state, "quarantine")
        aegis.EVENT_DB = os.path.join(state, "aegis.db")
        os.makedirs(aegis.QUARANTINE_DIR)
        aegis._recover_quarantine_locked = lambda: None
        aegis._unseal = lambda qid: None
        aegis._seal = lambda qid: None
        aegis._identity_matches = lambda a, b: True
        aegis.log_action = lambda *a, **k: True
        aegis._quarantine_payload = lambda qid: os.path.join(
            aegis._quarantine_item(qid), "payload")

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(aegis, n, v)
        self._shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_item(self, qid, original_path):
        item = aegis._quarantine_item(qid)
        os.makedirs(item)
        with open(aegis._quarantine_txn(qid), "w") as fh:
            json.dump({"schema": 1, "id": qid, "phase": "QUARANTINED",
                       "original_path": original_path,
                       "identity": {"digest": "sha256:0"}}, fh)

    def test_protected_dest_is_refused(self):
        qid = "20260812T000000000000-deadbeef01"
        # A SIP/system tree is protected on every platform's _PROTECTED_TREES/
        # TRUSTED_PREFIXES; aegis's own state dir is protected everywhere.
        self._make_item(qid, os.path.join(aegis.STATE_DIR, "evil"))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = aegis.cmd_restore(qid)
        self.assertEqual(rc, 1)
        self.assertIn("protected path", buf.getvalue())


# --------------------------------------------------------------------------- #
# F4 — a signal-0 liveness probe is not a coercion kill.
# --------------------------------------------------------------------------- #
class TestKillallSignalZeroCarveOut(unittest.TestCase):
    def _names(self, argv):
        return set(dict(aegis._argv_signals(argv)))

    def test_signal_zero_loop_not_flagged(self):
        argv = ("while true; do killall -0 SystemUIServer 2>/dev/null || "
                "open -a SystemUIServer; sleep 5; done")
        got = self._names(argv)
        self.assertNotIn("gui-kill-coercion", got)
        self.assertNotIn("gui-kill-loop-coercion", got)

    def test_signal_zero_oneshot_not_flagged(self):
        self.assertNotIn("gui-kill-coercion",
                         self._names("killall -0 SystemUIServer"))

    def test_real_kill_loop_still_critical(self):
        got = dict(aegis._argv_signals(
            "while true; do killall SystemUIServer; sleep 1; done"))
        self.assertEqual(got.get("gui-kill-coercion"), "HIGH")
        self.assertEqual(got.get("gui-kill-loop-coercion"), "CRITICAL")

    def test_real_oneshot_kill_still_high(self):
        self.assertEqual(
            dict(aegis._argv_signals("killall SystemUIServer")).get(
                "gui-kill-coercion"), "HIGH")


# --------------------------------------------------------------------------- #
# F5 — the /proc socket-inode walk runs once per scan, not per consumer.
# --------------------------------------------------------------------------- #
class TestSocketInodeScanCache(unittest.TestCase):
    def tearDown(self):
        aegis._SOCKET_INODE_SNAPSHOT = None

    def test_armed_cache_short_circuits_walk(self):
        walked = {"n": 0}
        real_listdir = os.listdir

        def counting_listdir(path):
            if str(path) == "/proc" or str(path).startswith("/proc/"):
                walked["n"] += 1
            return real_listdir(path) if os.path.exists(path) else []

        aegis._SOCKET_INODE_SNAPSHOT = {"42": "1000"}
        os.listdir = counting_listdir
        try:
            r1 = aegis._linux_socket_inode_pids()
            r2 = aegis._linux_socket_inode_pids()
        finally:
            os.listdir = real_listdir
        self.assertEqual(r1, {"42": "1000"})
        self.assertIs(r1, r2)
        self.assertEqual(walked["n"], 0, "cache should short-circuit the walk")

    def test_unarmed_cache_walks_live(self):
        aegis._SOCKET_INODE_SNAPSHOT = None
        # Returns a dict either way (empty on a host with no readable /proc).
        self.assertIsInstance(aegis._linux_socket_inode_pids(), dict)


# --------------------------------------------------------------------------- #
# F6 — the Windows netstat TCP table is spawned once per scan, not per consumer.
# --------------------------------------------------------------------------- #
class TestNetstatScanCache(unittest.TestCase):
    def tearDown(self):
        aegis._NETSTAT_SNAPSHOT = None

    def test_armed_cache_short_circuits_spawn(self):
        spawns = {"n": 0}
        real_run = aegis.run

        def spy_run(cmd, **k):
            if cmd and cmd[0] == "netstat":
                spawns["n"] += 1
            return ("header", "", 0)

        aegis.run = spy_run
        try:
            aegis._NETSTAT_SNAPSHOT = ("cached-table", 0)
            r1 = aegis._netstat_tcp_rows()
            r2 = aegis._netstat_tcp_rows()
        finally:
            aegis.run = real_run
        self.assertEqual(r1, ("cached-table", 0))
        self.assertEqual(r2, ("cached-table", 0))
        self.assertEqual(spawns["n"], 0, "armed cache must not spawn netstat")

    def test_unarmed_cache_spawns_once(self):
        spawns = {"n": 0}
        real_run = aegis.run

        def spy_run(cmd, **k):
            if cmd and cmd[0] == "netstat":
                spawns["n"] += 1
            return ("header", "", 0)

        aegis.run = spy_run
        try:
            aegis._NETSTAT_SNAPSHOT = None
            aegis._netstat_tcp_rows()
        finally:
            aegis.run = real_run
        self.assertEqual(spawns["n"], 1)


# --------------------------------------------------------------------------- #
# F7 — the three macOS `log show` harvests run once, concurrently, per scan.
# --------------------------------------------------------------------------- #
class TestLogShowScanCache(unittest.TestCase):
    def tearDown(self):
        aegis._LOG_SHOW_CACHE = None

    def _spy(self):
        calls = []

        def spy_run(cmd, timeout=15, extra_env=None):
            if cmd[:2] == ["log", "show"]:
                calls.append(cmd[cmd.index("--predicate") + 1])
            return ("OUT::" + cmd[cmd.index("--predicate") + 1], "", 0)

        return calls, spy_run

    def test_prewarm_covers_all_three_predicates(self):
        calls, spy_run = self._spy()
        real = aegis.run
        aegis.run = spy_run
        try:
            cache = aegis._prewarm_log_show()
        finally:
            aegis.run = real
        # One spawn per distinct predicate; cache holds all three, keyed by argv.
        self.assertEqual(sorted(calls), sorted(aegis._LOGSHOW_PREDICATES))
        self.assertEqual(len(cache), 3)

    def test_sensors_hit_cache_and_route_by_predicate(self):
        calls, spy_run = self._spy()
        real = aegis.run
        aegis.run = spy_run
        try:
            aegis._LOG_SHOW_CACHE = aegis._prewarm_log_show()
            calls.clear()
            o_xp, rc_xp = aegis._log_show(aegis._PRED_XPROTECT)
            o_sp, _ = aegis._log_show(aegis._PRED_SYSPOLICY)
            o_am, _ = aegis._log_show(aegis._PRED_AMFID)
        finally:
            aegis.run = real
        self.assertEqual(calls, [], "armed cache must not re-spawn log show")
        self.assertEqual(rc_xp, 0)
        # Each predicate's cached output is distinct (keyed on full argv, not a
        # shared/first-writer-wins entry).
        self.assertEqual(len({o_xp, o_sp, o_am}), 3)
        self.assertIn(aegis._PRED_XPROTECT, o_xp)

    def test_unarmed_cache_runs_live(self):
        calls, spy_run = self._spy()
        real = aegis.run
        aegis.run = spy_run
        try:
            aegis._LOG_SHOW_CACHE = None
            aegis._log_show(aegis._PRED_AMFID)
        finally:
            aegis.run = real
        self.assertEqual(calls, [aegis._PRED_AMFID])

    def test_log_show_argv_is_unchanged(self):
        # The refactor must build the exact command the sensors used before.
        seen = {}
        real = aegis.run

        def capture(cmd, timeout=15, extra_env=None):
            seen["cmd"] = cmd
            seen["timeout"] = timeout
            return ("", "", 0)

        aegis.run = capture
        try:
            aegis._LOG_SHOW_CACHE = None
            aegis._log_show(aegis._PRED_SYSPOLICY)
        finally:
            aegis.run = real
        self.assertEqual(seen["cmd"], [
            "log", "show", "--last", "6h", "--style", "ndjson",
            "--predicate", 'subsystem == "com.apple.syspolicy"'])
        self.assertEqual(seen["timeout"], 45)


# --------------------------------------------------------------------------- #
# H1 — the ld.so.preload argv idiom is tolerant of shell quote-splitting.
# --------------------------------------------------------------------------- #
class TestLdSoPreloadQuoteTolerant(unittest.TestCase):
    def _hit(self, argv):
        return any(name == "ld-so-preload-write" and rx.search(argv)
                   for rx, name in aegis._HOSTILE_CONTENT_RES)

    def test_verbatim_still_matches(self):
        self.assertTrue(self._hit("echo x > /etc/ld.so.preload"))

    def test_quote_split_is_caught(self):
        self.assertTrue(self._hit('echo x > /etc/ld.so.pre""load'))
        self.assertTrue(self._hit("sh -c 'printf x > /etc/ld.so.pr\"\"eload'"))

    def test_benign_text_not_flagged(self):
        self.assertFalse(self._hit("echo hello world"))
        self.assertFalse(self._hit("ldconfig -p | grep libssl"))


if __name__ == "__main__":
    unittest.main()
