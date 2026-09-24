#!/usr/bin/env python3
"""Provenance becomes a gate: a proven origin keeps an attribute-only finding
out of the interrupt tier.

Measured on the live store, 30 days to 2026-09-23: 190 of the 200 HIGH
interrupts the operator closed as noise carried `custody: null`. The custody
ladder existed and the interrupts never met it, for two reasons pinned here.

  * `_grade_binary` had no publisher rung. A valid Developer ID, App Store or
    Apple signature earned nothing on first sight -- `publisher-stable` is
    reachable only from a re-sign in place -- so a Developer-ID binary under
    $HOME beaconed HIGH on the one sensor whose predicate is an OR
    (`suspicious_sig(trust) or is_risky_location(path)`). In the corpus:
    Codex's SkyComputerUseService, an App-Translocated Obsidian Helper, the
    Chrome-app shim under ~/Applications.
  * Custody could only DEMOTE, one step, and nothing consulted it before the
    interrupt.

Every class pins the quieting AND the property that stops it becoming a blind
spot: attack-defined evidence, CRITICAL, and the tripwire fingerprints
(decoy:/latch:/canary:) interrupt under any custody; a weak rung still only
demotes; a vouch and a package receipt still answer first; and an ad-hoc,
broken, unsigned or unanchored signature earns nothing.
"""
import contextlib
import io
import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import SUSPICIOUS_TRUST, aegis                  # noqa: E402
from test_codesign_detritus import (CLEAN_VERIFY, DEV_ID_DV,   # noqa: E402
                                    TIMED_OUT)
from test_regression import Sandbox                           # noqa: E402
from test_routing_gate import NOW, GateSandbox                # noqa: E402

# Gated on BOTH, as test_signature_corpus is: CI runs a Linux leg with
# aegis.IS_MAC forced on, and that leg has no codesign to be right about.
REAL_MAC = sys.platform == "darwin" and aegis.IS_MAC

SPOTIFY = "/Applications/Spotify.app/Contents/MacOS/Spotify"
SKY = "/Users/op/.codex/computer-use/SkyComputerUseService"


PUBLISHER_NAME = "Example Publisher Ltd"


def _vendor_trust():
    """A publisher verdict in THIS body's vocabulary that belongs to a
    third-party vendor, and so is valid wherever the binary runs: Developer
    ID on macOS, a non-Microsoft Authenticode chain on Windows, a distro
    package on Linux (whose claim is already about the package's own path).
    Not conftest.PUBLISHER_TRUST: that is `apple` / `os-signed`, the
    platform's own signature, which earns the rung only in the system tree."""
    if aegis.IS_LINUX:
        return "os-managed"
    if aegis.IS_WIN:
        return "signed-valid"
    return "developer-id"


def _platform_trust():
    """The verdict that means "the OS vendor's own platform binary", or None
    on a body that has no such spelling."""
    if aegis.IS_LINUX:
        return None
    return "os-signed" if aegis.IS_WIN else "apple"


def _publisher_verdict():
    """A classify_signature() answer publisher_sig() accepts on THIS body at
    any location, naming its signer."""
    return {"trust": _vendor_trust(), "team": None,
            "authority": PUBLISHER_NAME}


def _process(sev="HIGH", custody="publisher-signed", fp=None, **extra):
    return aegis.finding(
        sev, "process", "Suspicious running process", "d",
        fp or "process:%s:adhoc:%s" % (SKY, "a" * 64),
        path=SKY, custody=custody, **extra)


class TheGate(GateSandbox):
    """route_findings consults custody before the notify floor."""

    def route(self, f):
        return aegis.route_findings([f], memory=None, seen={})[f["fingerprint"]]

    def test_a_proven_origin_high_goes_to_the_digest(self):
        v = self.route(_process())
        self.assertEqual(("digest", "provenance:publisher-signed"),
                         (v["route"], v["why"]))

    def test_every_self_and_vouched_rung_gates(self):
        for rung in aegis._SELF_CUSTODY + aegis._VOUCHED_CUSTODY:
            with self.subTest(rung=rung):
                v = self.route(_process(custody=rung))
                self.assertEqual(("digest", "provenance:" + rung),
                                 (v["route"], v["why"]))

    def test_the_agent_surface_spelling_gates_too(self):
        """The delegate-surface diff names the rung `provenance`."""
        v = self.route(_process(custody=None, provenance="self-committed"))
        self.assertEqual("provenance:self-committed", v["why"])

    def test_attack_defined_interrupts_under_publisher_custody(self):
        """Origin is not innocence: a vouched binary running an osascript
        password prompt is still an alarm."""
        v = self.route(_process(attack_defined=True))
        self.assertEqual(("interrupt", "new"), (v["route"], v["why"]))

    def test_critical_interrupts_under_any_custody(self):
        for rung in (aegis._SELF_CUSTODY + aegis._VOUCHED_CUSTODY
                     + aegis._WEAK_CUSTODY):
            with self.subTest(rung=rung):
                v = self.route(_process("CRITICAL", custody=rung))
                self.assertEqual("interrupt", v["route"])

    def test_tripwire_fingerprints_interrupt_under_any_custody(self):
        self.assertTrue({"decoy:", "latch:", "canary:"}
                        <= set(aegis._NEVER_TOLERATE_PREFIXES))
        for prefix in aegis._NEVER_TOLERATE_PREFIXES:
            with self.subTest(prefix=prefix):
                v = self.route(_process(fp=prefix + "tripped:" + SKY))
                self.assertEqual("interrupt", v["route"])

    def test_a_weak_rung_only_demotes(self):
        """build-output, supervised, copy-of-graded ... explain nothing at the
        gate; their one step happens in the grader, as before."""
        for rung in aegis._WEAK_CUSTODY:
            with self.subTest(rung=rung):
                self.assertEqual("interrupt",
                                 self.route(_process(custody=rung))["route"])

    def test_no_custody_still_interrupts(self):
        self.assertEqual("interrupt", self.route(_process(custody=None))["route"])

    def test_the_gate_is_asked_before_the_floor(self):
        """A demoted MEDIUM names the reason it is quiet, not merely that it
        is below the floor."""
        v = self.route(_process("MEDIUM"))
        self.assertEqual(("digest", "provenance:publisher-signed"),
                         (v["route"], v["why"]))

    def test_the_operator_allowlist_and_seen_ledger_still_answer_first(self):
        f = _process()
        v = aegis.route_findings([f], memory=None,
                                 seen={f["fingerprint"]: "t"})[f["fingerprint"]]
        self.assertEqual("seen", v["route"])


class TheRouteIsRecorded(GateSandbox):
    """The operator can see WHY a HIGH did not interrupt."""

    def test_the_scan_path_notifies_nobody_and_says_why(self):
        f = self.process(SKY, "c" * 64, custody="publisher-signed")
        routing, new_high = self.scan_path([f])
        self.assertEqual("provenance:publisher-signed",
                         routing[f["fingerprint"]]["why"])
        self.assertEqual([], new_high)
        self.assertEqual([], self.notified)
        self.assertEqual("digest: provenance publisher-signed", f["routed"])
        # Still a finding on the durable record -- digest, not erasure.
        with open(aegis.FINDINGS_LOG, encoding="utf-8") as log:
            self.assertIn("digest: provenance publisher-signed", log.read())
        opened = [i for i in self.incidents()
                  if i["correlation_key"] == "signal:" + f["case_fingerprint"]]
        self.assertEqual(1, len(opened))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            aegis.cmd_incident(opened[0]["id"])
        self.assertIn("digest: provenance publisher-signed", out.getvalue())

    def test_the_full_report_names_the_route(self):
        f = _process()
        aegis.route_findings([f], memory=None, seen={})
        md = aegis._full_report({"findings": [f]})
        self.assertIn("digest: provenance publisher-signed", md)

    def test_an_interrupt_carries_no_route_label(self):
        f = _process(custody=None)
        aegis.route_findings([f], memory=None, seen={})
        self.assertNotIn("routed", f)


class _RungSandbox(Sandbox):
    """_grade_binary with the classifier and the receipt probe stubbed."""

    def setUp(self):
        super().setUp()
        # setdefault, never assignment: on a Windows body Sandbox has already
        # pinned classify_signature and saved the REAL one; overwriting that
        # entry would "restore" Sandbox's stub at tearDown and leak it into
        # every later test (found by the simbody win leg on PR #60).
        for name in ("classify_signature", "_vouch_covers", "_package_receipt",
                     "_build_output_rung", "run"):
            self._saved.setdefault(name, getattr(aegis, name))
        aegis._CUSTODY_CARRY_CACHE.clear()
        aegis._GRADED_SHA_CACHE.clear()
        aegis._SIG_UNANSWERED.clear()
        aegis._package_receipt = lambda path: None
        self.bin = os.path.join(self.tmp, "SkyComputerUseService")
        with open(self.bin, "wb") as fh:
            fh.write(b"MACH-O-ish publisher-signed bytes " * 32)
        self.asked = []

    def tearDown(self):
        aegis._CUSTODY_CARRY_CACHE.clear()
        aegis._GRADED_SHA_CACHE.clear()
        aegis._SIG_UNANSWERED.clear()
        super().tearDown()

    def verdict(self, **sig):
        def fake(path):
            self.asked.append(path)
            return dict(sig)
        aegis.classify_signature = fake


class PublisherRung(_RungSandbox):
    """The rung on every body, in that body's own trust vocabulary."""

    def test_a_publisher_signature_earns_the_rung(self):
        self.verdict(**_publisher_verdict())
        sev, rung, note = aegis._grade_binary("HIGH", self.bin)
        self.assertEqual(("MEDIUM", "publisher-signed"), (sev, rung))
        self.assertIn(PUBLISHER_NAME, note, "the note must name the signer")
        self.assertEqual([self.bin], self.asked,
                         "the classifier is asked once per grading")

    def test_the_rung_is_recorded_in_the_custody_ledger(self):
        self.verdict(**_publisher_verdict())
        aegis._grade_binary("HIGH", self.bin)
        aegis._CUSTODY_CARRY_CACHE.clear()      # read the file, not the memo
        carried = aegis._custody_carried(aegis.sha256(self.bin))
        self.assertIsNotNone(carried)
        self.assertEqual("publisher-signed", carried[0])

    def test_unproven_signatures_earn_nothing(self):
        for trust in (SUSPICIOUS_TRUST, "broken", "unsigned", "signed-other",
                      "unknown", "missing", "unmanaged"):
            with self.subTest(trust=trust):
                self.verdict(trust=trust, team="2FNC3A47ZF",
                             authority=PUBLISHER_NAME)
                sev, rung, _note = aegis._grade_binary("HIGH", self.bin)
                self.assertEqual(("HIGH", None), (sev, rung))

    def test_a_publisher_verdict_that_names_no_signer_earns_nothing(self):
        self.verdict(trust=_vendor_trust(), team=None, authority=None)
        self.assertEqual(("HIGH", None),
                         aegis._grade_binary("HIGH", self.bin)[:2])

    def test_a_vouched_path_still_wins_first(self):
        aegis._vouch_covers = lambda path, endpoint=None: True
        self.verdict(**_publisher_verdict())
        self.assertEqual(("LOW", "operator-vouched"),
                         aegis._grade_binary("HIGH", self.bin)[:2])
        self.assertEqual([], self.asked, "a stronger rung answered; the "
                                         "classifier must not be asked")

    def test_a_package_receipt_still_wins_before_it(self):
        aegis._package_receipt = lambda path: "homebrew:tool@1.0"
        self.verdict(**_publisher_verdict())
        self.assertEqual("package-managed",
                         aegis._grade_binary("HIGH", self.bin)[1])
        self.assertEqual([], self.asked)

    def test_it_is_asked_before_build_output(self):
        aegis._build_output_rung = lambda path: True
        self.verdict(**_publisher_verdict())
        self.assertEqual("publisher-signed",
                         aegis._grade_binary("HIGH", self.bin)[1])
        self.verdict(trust=SUSPICIOUS_TRUST, team=None, authority=None)
        self.assertEqual("build-output",
                         aegis._grade_binary("HIGH", self.bin)[1])

    def test_the_platforms_no_withholds_the_rung(self):
        """A caller whose own evidence says the platform's control refused
        these bytes (the hot-dir sensor, after Gatekeeper rejected the
        bundle) withholds the rung, and the classifier is not even asked."""
        self.verdict(**_publisher_verdict())
        self.assertEqual(("HIGH", None),
                         aegis._grade_binary("HIGH", self.bin,
                                             publisher_ok=False)[:2])
        self.assertEqual([], self.asked)

    def test_a_vendor_signature_under_home_earns_the_rung(self):
        """The corpus shape: Codex's helper under ~/.codex, Developer ID."""
        aegis._build_output_rung = lambda path: None
        home_bin = os.path.join(aegis.HOME, ".codex", "computer-use",
                                "SkyComputerUseService")
        self.verdict(**_publisher_verdict())
        self.assertEqual(("MEDIUM", "publisher-signed"),
                         aegis._grade_binary("HIGH", home_bin)[:2])

    def test_attack_defined_evidence_earns_nothing(self):
        self.verdict(**_publisher_verdict())
        self.assertEqual(("HIGH", None, None),
                         aegis._grade_binary("HIGH", self.bin,
                                             attack_defined=True))

    def test_the_rung_is_a_vouched_origin_one_step_down(self):
        self.assertIn("publisher-signed", aegis._VOUCHED_CUSTODY)
        self.assertNotIn("publisher-signed",
                         aegis._SELF_CUSTODY + aegis._WEAK_CUSTODY)
        self.assertEqual("MEDIUM", aegis._demote("HIGH", "publisher-signed"))
        self.assertEqual("HIGH", aegis._demote("CRITICAL", "publisher-signed"))
        self.assertEqual(0.25, aegis._RISK_CUSTODY_WEIGHT["publisher-signed"])
        self.assertTrue(aegis._PROVENANCE_NOTE.get("publisher-signed"))


@unittest.skipIf(_platform_trust() is None,
                 "no platform-binary signature on this body")
class PlatformSignatureStaysInTheSystemTree(_RungSandbox):
    """`apple` / `os-signed` is the OS vendor's own binary. Where it runs
    from the sealed system tree its origin is proven; a copy of it anywhere
    else -- /tmp, $HOME, /Users/Shared, %TEMP% -- is the living-off-the-land
    shape, and the signature on the bytes says nothing about who put them
    there."""

    def setUp(self):
        super().setUp()
        aegis._build_output_rung = lambda path: None
        # Built from the tree itself rather than a known binary: on a
        # simulated body WIN_SYSTEMROOT is empty and the prefixes are the
        # host's, and the rule under test is "inside TRUSTED_PREFIXES".
        self.system_bin = os.path.join(aegis.TRUSTED_PREFIXES[0],
                                       "aegis-platform-probe")
        self.remembered = []
        self._saved.setdefault("_custody_remember", aegis._custody_remember)
        aegis._custody_remember = (
            lambda sha, rung, path: self.remembered.append((rung, path)))

    def platform(self):
        self.verdict(trust=_platform_trust(), team=None,
                     authority="Software Signing")

    def test_inside_the_system_tree_it_earns_the_rung(self):
        self.platform()
        self.assertEqual(("MEDIUM", "publisher-signed"),
                         aegis._grade_binary("HIGH", self.system_bin)[:2])

    def test_a_copy_outside_the_system_tree_earns_nothing(self):
        self.platform()
        for path in (self.bin, os.path.join(aegis.HOME, "Library", "nc")):
            with self.subTest(path=path):
                self.assertEqual(("HIGH", None),
                                 aegis._grade_binary("HIGH", path)[:2])

    def test_the_system_tree_rung_is_not_carried_to_a_copy(self):
        """Carried custody would otherwise hand a copy `copy-of-graded` on
        the strength of the original's location, so the rung is not written
        to the ledger. A vendor's signature, which is not about location,
        still is."""
        self.platform()
        self.assertEqual("publisher-signed",
                         aegis._grade_binary("HIGH", self.system_bin)[1])
        self.assertEqual([], self.remembered)
        self.verdict(**_publisher_verdict())
        aegis._grade_binary("HIGH", self.bin, sha="f" * 64)
        self.assertEqual([("publisher-signed", self.bin)], self.remembered)


class DeveloperIdRung(_RungSandbox):
    """The macOS half: a Developer ID verdict, and what codesign costs.

    Listed in conftest._MAC_ONLY_CLASSES: every assertion here is about the
    codesign vocabulary or _classify_mac, which no other body produces."""

    SPOTIFY_ID = {"trust": "developer-id", "team": "2FNC3A47ZF",
                  "authority": "Developer ID Application: Spotify (2FNC3A47ZF)"}

    def test_a_developer_id_earns_the_rung_and_names_the_team(self):
        self.verdict(**self.SPOTIFY_ID)
        sev, rung, note = aegis._grade_binary("HIGH", self.bin)
        self.assertEqual(("MEDIUM", "publisher-signed"), (sev, rung))
        self.assertTrue(note.startswith(
            "Signed by Developer ID team 2FNC3A47ZF (Spotify); Apple's "
            "notarization/revocation is the control that stands behind "
            "this rung."), note)

    def test_a_strict_detritus_verdict_still_qualifies(self):
        """S1: Finder detritus with an intact seal keeps the chain's trust."""
        self.verdict(strict="detritus", **self.SPOTIFY_ID)
        self.assertEqual("publisher-signed",
                         aegis._grade_binary("HIGH", self.bin)[1])

    def test_adhoc_and_broken_earn_nothing(self):
        for trust in ("adhoc", "broken"):
            with self.subTest(trust=trust):
                self.verdict(**dict(self.SPOTIFY_ID, trust=trust))
                self.assertEqual(("HIGH", None),
                                 aegis._grade_binary("HIGH", self.bin)[:2])

    def test_grading_after_the_sensor_costs_no_second_codesign(self):
        """The sensor classified the binary first; the rung reads the
        stat-keyed verdict cache, never codesign again."""
        aegis.classify_signature = self._saved["classify_signature"]
        calls = []
        real = self._saved["run"]

        def fake(cmd, timeout=15, extra_env=None, stdin_data=None):
            if list(cmd)[:1] == ["codesign"]:
                calls.append(list(cmd)[1])
                return ("", DEV_ID_DV, 0) if "-dv" in cmd else CLEAN_VERIFY
            return real(cmd, timeout=timeout, extra_env=extra_env,
                        stdin_data=stdin_data)
        aegis.run = fake
        self.assertEqual("developer-id",
                         aegis.classify_signature(self.bin)["trust"])
        probes = len(calls)
        self.assertEqual("publisher-signed",
                         aegis._grade_binary("HIGH", self.bin)[1])
        self.assertEqual(probes, len(calls), calls)

    def test_a_probe_that_did_not_answer_is_not_asked_again(self):
        """A non-answer is never cached, so without a per-scan record the
        rung would run codesign a second time on exactly the binary the
        sensor just failed to classify -- under load, a second timeout."""
        aegis.classify_signature = self._saved["classify_signature"]
        calls = []
        real = self._saved["run"]
        answer = [TIMED_OUT]

        def fake(cmd, timeout=15, extra_env=None, stdin_data=None):
            if list(cmd)[:1] == ["codesign"]:
                calls.append(list(cmd)[1])
                if "-dv" in cmd:
                    return answer[0]
                return CLEAN_VERIFY
            return real(cmd, timeout=timeout, extra_env=extra_env,
                        stdin_data=stdin_data)
        aegis.run = fake
        self.assertEqual("unknown", aegis.classify_signature(self.bin)["trust"])
        probes = len(calls)
        sev, rung, _note = aegis._grade_binary("HIGH", self.bin)
        self.assertEqual(("HIGH", None), (sev, rung))
        self.assertEqual(probes, len(calls), calls)
        # Different bytes are a different question, and are asked.
        with open(self.bin, "ab") as fh:
            fh.write(b" rebuilt")
        answer[0] = ("", DEV_ID_DV, 0)
        self.assertEqual("publisher-signed",
                         aegis._grade_binary("HIGH", self.bin)[1])
        self.assertGreater(len(calls), probes)


@unittest.skipUnless(REAL_MAC, "grades a real codesign answer; macOS only")
class LivePublisherRung(Sandbox):
    """A fixture cannot test a parser: the rung, against the real tool."""

    def setUp(self):
        super().setUp()
        aegis._CUSTODY_CARRY_CACHE.clear()
        aegis._GRADED_SHA_CACHE.clear()

    def tearDown(self):
        aegis._CUSTODY_CARRY_CACHE.clear()
        aegis._GRADED_SHA_CACHE.clear()
        super().tearDown()

    def test_a_copied_platform_binary_earns_nothing(self):
        """The real tool, both halves: /bin/ls in place is Apple's and earns
        the rung; the same bytes copied into a user-writable temp dir keep
        Apple's signature and earn nothing -- not even `copy-of-graded`."""
        self.assertEqual(("LOW", "publisher-signed"),
                         aegis._grade_binary("MEDIUM", "/bin/ls")[:2])
        copy = os.path.join(self.tmp, "ls")
        shutil.copyfile("/bin/ls", copy)
        os.chmod(copy, 0o755)
        self.assertEqual("apple", aegis.classify_signature(copy)["trust"],
                         "fixture: the copy should still verify as Apple's")
        self.assertTrue(aegis.is_risky_location(copy), copy)
        self.assertEqual(("HIGH", None),
                         aegis._grade_binary("HIGH", copy)[:2])

    def test_spotify_grades_publisher_signed(self):
        if not os.path.exists(SPOTIFY):
            self.skipTest("Spotify is not installed here")
        sev, rung, note = aegis._grade_binary("HIGH", SPOTIFY)
        self.assertEqual(("MEDIUM", "publisher-signed"), (sev, rung), note)
        team = aegis.classify_signature(SPOTIFY)["team"]
        self.assertTrue(team)
        self.assertIn("Developer ID team %s" % team, note)


class DigestOnlyIncidentsAreNeverEscalated(GateSandbox):
    """An incident opened only by digest-routed evidence -- the provenance
    gate, low confidence, anything below the interrupt tier -- is recorded
    as such, and no reminder ever turns it into a notification. It notifies
    only when evidence that would itself interrupt attaches to it."""

    def case(self, f):
        rows = [i for i in self.incidents()
                if i["correlation_key"] == "signal:" + f["case_fingerprint"]]
        self.assertEqual(1, len(rows), rows)
        return rows[0]

    def assert_never_reminded(self):
        for days in (0.05, 1, 3, 30):
            self.assertEqual(
                [], aegis.claim_due_incident_reminders(
                    now=NOW + int(days * 86400)), days)

    def test_a_provenance_digest_incident_is_never_reminded(self):
        f = self.process(SKY, "c" * 64, custody="publisher-signed")
        _routing, new_high = self.scan_path([f])
        self.assertEqual([], new_high)
        inc = self.case(f)
        self.assertEqual("provenance:publisher-signed", inc["digest_only"])
        self.assertIsNone(inc["next_reminder_at"])
        self.assertIsNone(inc["last_notified_at"])
        self.assert_never_reminded()
        self.assertEqual([], self.notified)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            aegis.cmd_incident(inc["id"])
        self.assertIn("digest only (provenance:publisher-signed)",
                      out.getvalue())

    def test_a_low_confidence_digest_incident_is_never_reminded(self):
        f = self.process(SKY, "e" * 64, confidence="low")
        _routing, new_high = self.scan_path([f])
        self.assertEqual([], new_high)
        self.assertEqual("low-confidence", self.case(f)["digest_only"])
        self.assert_never_reminded()
        self.assertEqual([], self.notified)

    def test_a_reopen_by_hand_does_not_arm_reminders(self):
        f = self.process(SKY, "c" * 64, custody="publisher-signed")
        self.scan_path([f])
        inc = self.case(f)
        self.assertTrue(aegis.transition_incident(inc["id"], "ACK", now=NOW))
        self.assertTrue(aegis.transition_incident(inc["id"], "RESOLVED",
                                                  now=NOW))
        self.assertTrue(aegis.transition_incident(inc["id"], "OPEN", now=NOW))
        self.assert_never_reminded()

    def test_a_seen_reobservation_does_not_escalate(self):
        f = self.process(SKY, "c" * 64, custody="publisher-signed")
        self.scan_path([f])
        self.scan_path([dict(f)])
        self.assertEqual("provenance:publisher-signed",
                         self.case(f)["digest_only"])
        self.assert_never_reminded()

    def test_an_interrupting_finding_escalates_it(self):
        quiet = self.process(SKY, "c" * 64, custody="publisher-signed")
        self.scan_path([quiet])
        loud = self.process(SKY, "d" * 64)     # same case, no custody
        routing, new_high = self.scan_path([loud])
        self.assertEqual("interrupt", routing[loud["fingerprint"]]["route"])
        self.assertEqual(1, len(new_high))
        inc = self.case(loud)
        self.assertIsNone(inc["digest_only"])
        self.assertEqual(NOW, inc["last_notified_at"])
        self.assertEqual(NOW + aegis._REMINDER_DELAYS[0],
                         inc["next_reminder_at"])
        due = aegis.claim_due_incident_reminders(
            now=NOW + aegis._REMINDER_DELAYS[0])
        self.assertEqual([inc["id"]], [d["id"] for d in due])

    def test_an_interrupt_opened_incident_still_reminds(self):
        f = self.process(SKY, "f" * 64)
        self.scan_path([f])
        inc = self.case(f)
        self.assertIsNone(inc["digest_only"])
        self.assertEqual(NOW + aegis._REMINDER_DELAYS[0],
                         inc["next_reminder_at"])
        due = aegis.claim_due_incident_reminders(
            now=NOW + aegis._REMINDER_DELAYS[0])
        self.assertEqual([inc["id"]], [d["id"] for d in due])

    def test_digest_evidence_does_not_mute_a_notified_incident(self):
        loud = self.process(SKY, "d" * 64)
        self.scan_path([loud])
        quiet = self.process(SKY, "c" * 64, custody="publisher-signed")
        self.scan_path([quiet])
        inc = self.case(loud)
        self.assertIsNone(inc["digest_only"])
        self.assertEqual(NOW + aegis._REMINDER_DELAYS[0],
                         inc["next_reminder_at"])

    def test_a_store_that_predates_the_mark_gains_it(self):
        aegis.EVENT_DB = os.path.join(self.tmp, "old.db")
        import sqlite3
        raw = sqlite3.connect(aegis.EVENT_DB)
        raw.executescript(
            "CREATE TABLE incidents (id INTEGER PRIMARY KEY, kind TEXT, "
            "correlation_key TEXT, title TEXT, severity TEXT, status TEXT, "
            "created_at INTEGER, first_seen INTEGER, last_seen INTEGER, "
            "updated_at INTEGER, reminder_count INTEGER DEFAULT 0, "
            "next_reminder_at INTEGER, last_notified_at INTEGER, "
            "resolution TEXT, subject_json TEXT, last_novel_at INTEGER);"
            "PRAGMA user_version=1;")
        raw.commit()
        raw.close()
        db = aegis._event_connection()
        try:
            cols = {r[1] for r in db.execute("PRAGMA table_info(incidents)")}
        finally:
            db.close()
        self.assertIn("digest_only", cols)


if __name__ == "__main__":
    unittest.main()
