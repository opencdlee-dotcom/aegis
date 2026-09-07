"""A path cleaned up at emission was being denied an identity at learning.

`_program_subject` normalizes version churn when a sensor BUILDS a fingerprint
(aegis.py, the beacon emitter). `_tolerance_identity` then normalizes again and
returns None unless something changed. For every fingerprint the emitter had
already cleaned, nothing was left to change — so the identity came back None,
`_tolerance_memory` discarded the row, and the verdict counter never
incremented. A fix at emission was disabling the fix at learning, and the
symptom was precise: `beacon:.../bin.#/Runner.Worker:<ip>:443` could never
accumulate a verdict, while the byte-equivalent fingerprint carrying the RAW
`bin.2.336.0` generalized normally. Cleaning the path up cost it its identity.

Measured on the live ledger the day this shipped: nine identities recovered —
the operator's own VS Code Claude Code and Codex extensions (whose paths carry
an extension version) and his self-hosted Actions runner. Modest on purpose.
The 1297 findings behind the category gate are a SEPARATE question and are not
touched here.

Deliberately NOT the broader repair — dropping the `changed` requirement
outright. A beacon fingerprint carries no trust or content component, so an
attacker who replaces a vouched binary IN PLACE and reuses its endpoint
presents a byte-identical fingerprint. Granting tolerance to never-normalized
paths would hand that replacement the operator's own verdicts. Widening only
to ALREADY-normalized paths keeps the population exactly the one version
churn was always meant to cover, and the guard test below pins that boundary.

Platform-independent by construction: pure string identity, no sensors.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import aegis                                    # noqa: E402

RUNNER_RAW = ("beacon:/Users/c/actions-runners/os/bin.2.336.0/"
              "Runner.Worker:140.82.113.21:443")
RUNNER_NORM = ("beacon:/Users/c/actions-runners/os/bin.#/"
               "Runner.Worker:140.82.113.21:443")
EXT_NORM = ("beacon:/Users/c/.vscode/extensions/anthropic.claude-code-#-"
            "darwin-arm64/resources/native-binary/claude:160.79.104.10:443")
NEVER_NORMALIZED = "beacon:/Applications/Foo.app/Contents/MacOS/Foo:1.2.3.4:443"


class APreNormalizedPathKeepsItsIdentity(unittest.TestCase):
    def test_the_emitter_cleaning_the_path_does_not_cost_it_an_identity(self):
        # BEFORE THE FIX: None. The sensor builds this fingerprint through
        # _program_subject, so this is the form that actually reaches the
        # store -- the raw form below is the one that never occurs in practice.
        self.assertIsNotNone(
            aegis._tolerance_identity(RUNNER_NORM),
            "a fingerprint the emitter already normalized was denied the "
            "identity its un-normalized twin gets for free")

    def test_the_raw_and_cleaned_forms_agree(self):
        """The whole point of _program_subject is that these are one subject."""
        self.assertEqual(aegis._tolerance_identity(RUNNER_RAW),
                         aegis._tolerance_identity(RUNNER_NORM))

    def test_a_versioned_extension_path_is_learnable(self):
        self.assertIsNotNone(aegis._tolerance_identity(EXT_NORM))


class BTheBoundaryHolds(unittest.TestCase):
    def test_a_never_normalized_path_is_still_refused(self):
        """The narrow scope IS the safety argument. A beacon fingerprint has
        no trust or content field, so an attacker replacing a vouched binary
        in place reuses its fingerprint exactly; only paths that carry version
        churn -- the population _program_subject exists for -- may generalize."""
        self.assertIsNone(aegis._tolerance_identity(NEVER_NORMALIZED))

    def test_attack_defined_evidence_is_never_given_an_identity(self):
        for fp in ("decoy:/Users/c/.ssh/id_rsa:aaaaaaaaaaaa",
                   "latch:/Users/c/.aegis/x:bbbbbbbbbbbb",
                   "canary:/Users/c/Documents/y:cccccccccccc"):
            self.assertIsNone(aegis._tolerance_identity(fp), fp)

    def test_a_hash_marker_outside_a_path_field_does_not_qualify(self):
        """The '#' test is scoped to path-like fields, exactly as the version
        regex is. An endpoint or verdict field carrying one is not a path."""
        self.assertIsNone(
            aegis._tolerance_identity("beacon:notapath:#ip:443"))

    def test_two_versions_of_one_program_stay_one_identity(self):
        a = "beacon:/Users/c/.vscode/extensions/x.y-1.2.3/bin/z:9.9.9.9:443"
        b = "beacon:/Users/c/.vscode/extensions/x.y-1.2.4/bin/z:9.9.9.9:443"
        self.assertEqual(aegis._tolerance_identity(a),
                         aegis._tolerance_identity(b))

    def test_two_different_programs_stay_different_identities(self):
        a = "beacon:/Users/c/.vscode/extensions/x.y-#/bin/good:9.9.9.9:443"
        b = "beacon:/Users/c/.vscode/extensions/x.y-#/bin/evil:9.9.9.9:443"
        self.assertNotEqual(aegis._tolerance_identity(a),
                            aegis._tolerance_identity(b))

    def test_a_new_endpoint_is_still_a_new_fact(self):
        """The file's stated rule, unchanged: only hash and version churn
        generalize. A different address is a different identity."""
        other = RUNNER_NORM.replace("140.82.113.21", "203.0.113.9")
        self.assertNotEqual(aegis._tolerance_identity(RUNNER_NORM),
                            aegis._tolerance_identity(other))


if __name__ == "__main__":
    unittest.main()


class CTheTwoDerivationsAgree(unittest.TestCase):
    """ONE memory. `_subject_identity` never handled kind == "beacon" -- every
    beacon subject fell through to None. That stayed invisible only because
    the string side ALSO returned None for the same rows, so the two agreed by
    shared brokenness. Teaching the string side to key on a pre-normalized
    path broke that agreement, and a split memory is worse than no memory:
    verdicts would accumulate in two places and neither would reach the floor.
    """

    @staticmethod
    def _beacon(path, ip, port):
        return aegis.finding(
            "HIGH", "net-beacon", "b", "d",
            "beacon:%s:%s:%s" % (aegis._program_subject(path), ip, port),
            subject=aegis._subject("beacon", path, ip=ip, port=port))

    def test_a_beacon_subject_renders_an_identity_at_all(self):
        f = self._beacon("/Users/c/.vscode/extensions/pub.tool-1.4.2/bin/t",
                         "1.2.3.4", "443")
        # BEFORE THE FIX: None -- kind == "beacon" fell off the end.
        self.assertIsNotNone(aegis._finding_identity(f))

    def test_subject_and_string_render_the_same_bytes(self):
        for path, ip, port in (
                ("/Users/c/.vscode/extensions/pub.tool-1.4.2/bin/t",
                 "1.2.3.4", "443"),
                ("/Users/c/actions-runners/os/bin.2.336.0/Runner.Worker",
                 "140.82.113.21", "443"),
                ("/opt/homebrew/opt/syncthing/bin/syncthing",
                 "fd7a:115c:a1e0::", "22000"),
                ("/Applications/Foo.app/Contents/MacOS/Foo", "9.9.9.9", "443")):
            f = self._beacon(path, ip, port)
            self.assertEqual(aegis._finding_identity(f),
                             aegis._tolerance_identity(f["fingerprint"]),
                             path)

    def test_a_beacon_with_nothing_to_generalize_still_renders_none(self):
        """The boundary holds on the subject side too."""
        f = self._beacon("/Applications/Foo.app/Contents/MacOS/Foo",
                         "9.9.9.9", "443")
        self.assertIsNone(aegis._finding_identity(f))
