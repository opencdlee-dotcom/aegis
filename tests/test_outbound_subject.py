"""The outbound sensor's subject identity: one finding per PROGRAM.

Measured cause, on the reference machine 2026-08-23: net-outbound was the
largest sensor in the report, and every one of its lines was the same handful
of facts wearing different endpoints. One `claude` binary reached three Google
frontends and was three LOW lines; syncthing's relay pool had left 30+ stored
fingerprints; and six extension updates of one program were six more.

The damage was not only readability. `_accumulate_risk` sums one weight per
DISTINCT fingerprint on an entity, so endpoint rotation MANUFACTURED risk score
out of a single fact — the "N signals across M sensors" in a risk incident's
title was counting sockets, not evidence.

The fix demotes the endpoint from identity to evidence. As with every other
suppression in this codebase, each class below pins the collapse AND the safety
property that keeps it from becoming a blind spot: the endpoints are still all
rendered, an uncovered endpoint still un-demotes its whole subject, a known-C2
endpoint stays endpoint-keyed, and net-beacon — whose detection IS persistence
at one fixed endpoint — keeps the endpoint in its key.
"""
import os
import sys
import sqlite3
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

CLAUDE_241 = ("/Users/x/.vscode/extensions/anthropic.claude-code-2.1.241-"
              "darwin-arm64/resources/native-binary/claude")
CLAUDE_233 = CLAUDE_241.replace("2.1.241", "2.1.233")


class _Stubbed(unittest.TestCase):
    """Pure over (path, ip, port): the platform probes and the custody ladder
    are stubbed so these assert the GROUPING, on every OS."""

    def setUp(self):
        self._saved = {n: getattr(aegis, n) for n in (
            "classify_signature", "is_risky_location", "_grade_binary",
            "_vouch_endpoint_deviation")}
        aegis.classify_signature = lambda p, **k: {"trust": "adhoc"}
        aegis.is_risky_location = lambda p: True
        aegis._grade_binary = lambda sev, path, **k: (sev, None, None)
        aegis._vouch_endpoint_deviation = lambda path, ep: (None, None)

    def tearDown(self):
        for name, fn in self._saved.items():
            setattr(aegis, name, fn)


class OneProgramIsOneFinding(_Stubbed):
    def test_three_frontends_collapse_to_one_finding(self):
        fs = aegis._outbound_findings([
            (CLAUDE_241, "160.79.104.10", "443"),
            (CLAUDE_241, "34.149.66.165", "443"),
            (CLAUDE_241, "35.190.46.17", "443")])
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["endpoint_count"], 3)

    def test_every_endpoint_is_still_named(self):
        """The safety half. Collapsing the ALERT must not hide the FACTS —
        each endpoint stays in the detail an operator reads and in the
        attribute a later query can filter on."""
        fs = aegis._outbound_findings([
            (CLAUDE_241, "160.79.104.10", "443"),
            (CLAUDE_241, "34.149.66.165", "443")])
        self.assertEqual(sorted(fs[0]["endpoints"]),
                         ["160.79.104.10:443", "34.149.66.165:443"])
        for ep in ("160.79.104.10:443", "34.149.66.165:443"):
            self.assertIn(ep, fs[0]["detail"])

    def test_two_versions_of_one_program_are_one_subject(self):
        """Six extension updates were six identities for one program."""
        fs = aegis._outbound_findings([(CLAUDE_241, "1.2.3.4", "443"),
                                       (CLAUDE_233, "1.2.3.4", "443")])
        self.assertEqual(len(fs), 1)
        self.assertNotIn("2.1.241", fs[0]["fingerprint"])

    def test_unrelated_programs_stay_apart(self):
        fs = aegis._outbound_findings([(CLAUDE_241, "1.2.3.4", "443"),
                                       ("/opt/other/bin/tool", "1.2.3.4", "443")])
        self.assertEqual(len(fs), 2)

    def test_rotation_no_longer_manufactures_risk_score(self):
        """_accumulate_risk weights one unit per DISTINCT fingerprint on an
        entity, so this identity — not the report — is where the score was
        being inflated. Thirty relay addresses are one fact about one program."""
        rows = [("/opt/st/bin/syncthing", "10.0.0.%d" % i, "22067")
                for i in range(30)]
        fs = aegis._outbound_findings(rows)
        self.assertEqual(len({f["fingerprint"] for f in fs}), 1)
        self.assertEqual(fs[0]["endpoint_count"], 30)

    def test_a_long_endpoint_list_never_reads_as_a_complete_one(self):
        rows = [("/opt/st/bin/syncthing", "10.0.0.%d" % i, "22067")
                for i in range(30)]
        detail = aegis._outbound_findings(rows)[0]["detail"]
        self.assertIn("30 live endpoint(s)", detail)
        self.assertIn("more)", detail)


class WorstEndpointGradesTheSubject(_Stubbed):
    """Custody is endpoint-scoped for network vouches, so grouping must take
    the WORST endpoint — otherwise one covered endpoint would launder an
    uncovered one, which is exactly the connection worth seeing."""

    def test_one_uncovered_endpoint_un_demotes_the_subject(self):
        aegis._grade_binary = lambda sev, path, endpoint=None, **k: (
            ("LOW", "operator-vouched", "covered")
            if endpoint == "1.1.1.1:443" else (sev, None, None))
        fs = aegis._outbound_findings([("/opt/w/bin/w", "1.1.1.1", "443"),
                                       ("/opt/w/bin/w", "9.9.9.9", "443")])
        self.assertEqual(fs[0]["severity"], "MEDIUM")
        self.assertIsNone(fs[0]["custody"])

    def test_an_all_covered_subject_keeps_its_demotion(self):
        aegis._grade_binary = lambda sev, path, **k: (
            "LOW", "operator-vouched", "covered")
        fs = aegis._outbound_findings([("/opt/w/bin/w", "1.1.1.1", "443"),
                                       ("/opt/w/bin/w", "1.1.1.2", "443")])
        self.assertEqual(fs[0]["severity"], "LOW")
        self.assertEqual(fs[0]["custody"], "operator-vouched")

    def test_a_deviating_endpoint_owns_the_case(self):
        aegis._vouch_endpoint_deviation = lambda path, ep: (
            ("vouched-endpoint:w", "deviated") if ep == "9.9.9.9:443"
            else (None, None))
        fs = aegis._outbound_findings([("/opt/w/bin/w", "1.1.1.1", "443"),
                                       ("/opt/w/bin/w", "9.9.9.9", "443")])
        self.assertEqual(fs[0]["case_fingerprint"], "vouched-endpoint:w")
        self.assertIn("deviated", fs[0]["detail"])


class TheGateIsUnchanged(unittest.TestCase):
    """Grouping changed WHICH findings are minted, never WHETHER a program
    qualifies. A signed binary in a system path is still silent."""

    def test_a_system_signed_binary_never_qualifies(self):
        saved = aegis.classify_signature
        aegis.classify_signature = lambda p, **k: {"trust": "system"}
        try:
            self.assertIsNone(aegis._outbound_candidate_trust("/bin/ls"))
            self.assertEqual(
                aegis._outbound_findings([("/bin/ls", "1.2.3.4", "80")]), [])
        finally:
            aegis.classify_signature = saved

    def test_an_unresolvable_process_name_never_qualifies(self):
        self.assertIsNone(aegis._outbound_candidate_trust("claude"))
        self.assertIsNone(aegis._outbound_candidate_trust(""))


class BeaconKeepsItsEndpoint(unittest.TestCase):
    """net-beacon's whole detection is persistence at ONE fixed endpoint, so
    it keeps the endpoint in its key. Only the version churn comes out."""

    def _rows(self, path, ip="1.2.3.4", port="443"):
        now = int(aegis.time.time())
        row = [path, ip, port, "adhoc"]
        hist = [(now - 4000, [row]), (now - 2500, [row]), (now - 100, [row])]
        return hist, [row]

    def test_the_signal_key_drops_the_version(self):
        hist, cur = self._rows(CLAUDE_241)
        fs = aegis._beacon_recurrence(hist, cur)
        self.assertEqual(len(fs), 1)
        self.assertNotIn("2.1.241", fs[0]["fingerprint"])
        self.assertIn("#", fs[0]["fingerprint"])
        # The literal path is still reported — only identity is normalized.
        self.assertEqual(fs[0]["path"], CLAUDE_241)

    def test_two_endpoints_are_still_two_beacons(self):
        now = int(aegis.time.time())
        rows = [[CLAUDE_241, "1.2.3.4", "443", "adhoc"],
                [CLAUDE_241, "9.9.9.9", "443", "adhoc"]]
        hist = [(now - 4000, rows), (now - 2500, rows), (now - 100, rows)]
        fs = aegis._beacon_recurrence(hist, rows)
        self.assertEqual(len({f["fingerprint"] for f in fs}), 2)


class NoMigrationIsNeeded(unittest.TestCase):
    """Deliberately NOT migrated, and this pins why.

    A case key change usually needs a one-time fold (see
    _merge_legacy_persistence_cases). This one does not: net-outbound sits
    BELOW the notify floor by design, so it has never opened an incident of its
    own — measured on the live store 2026-08-23, `signal:outbound:%` matched 0
    incidents of any status against 64 stored signals, while the HIGH beacon
    sensor beside it had 36. There is nothing keyed on the old shape to fold,
    and a migration guarding an empty set is code that can only ever be wrong.

    If that ever stops being true, the 7-day age-out tier already closes a
    stale signal case — no new mechanism is required."""

    def test_the_case_key_carries_no_endpoint(self):
        saved = (aegis.classify_signature, aegis.is_risky_location,
                 aegis._grade_binary, aegis._vouch_endpoint_deviation)
        aegis.classify_signature = lambda p, **k: {"trust": "adhoc"}
        aegis.is_risky_location = lambda p: True
        aegis._grade_binary = lambda sev, path, **k: (sev, None, None)
        aegis._vouch_endpoint_deviation = lambda path, ep: (None, None)
        try:
            fs = aegis._outbound_findings([("/opt/st/bin/st", "1.2.3.4", "22067"),
                                           ("/opt/st/bin/st", "5.6.7.8", "22067")])
        finally:
            (aegis.classify_signature, aegis.is_risky_location,
             aegis._grade_binary, aegis._vouch_endpoint_deviation) = saved
        self.assertEqual(fs[0]["case_fingerprint"], "outbound:/opt/st/bin/st")
        self.assertEqual(fs[0]["fingerprint"], fs[0]["case_fingerprint"])


if __name__ == "__main__":
    unittest.main()
