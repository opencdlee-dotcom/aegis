#!/usr/bin/env python3
"""An operator-confirmed SSH key/origin stops re-alerting like a stranger's.

Aegis had no notion of "known good actor": a changed authorized_keys or a new
remote login session from the operator's OWN other machine looked identical to
an attacker's, on every scan, forever (see the 2026-08-30 trust-modeling
research in the project brief — 281 incidents, ~0 true positives, largely this
gap). `trusted_identities` plus `_apply_identity_trust` fix that: an operator
verdict (`aegis.py identity trust ...`, or a `benign-positive` on the incident
it raised) is a durable, local, per-fingerprint allowlist that downgrades a
recurrence to LOW/low-confidence — routed to the digest, never deleted, so a
later-compromised trust anchor stays reviewable rather than invisible.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aegis  # noqa: E402
from test_regression import Sandbox  # noqa: E402


def auth_session(origin, key=None):
    key = key or ("charlie@%s:ttys001" % origin)
    return aegis.finding(
        "HIGH", "auth-session", "New remote login session",
        "%s — a remote session appeared from %s." % (key, origin),
        "auth-session:%s" % key, session=key, origin=origin,
        confidence="medium", markers=["remote-access"])


def authorized_keys_finding(path, file_hash="deadbeef", severity="MEDIUM"):
    return aegis.finding(
        severity, "persistence", "New system-persistence file",
        "%s appeared" % path, "xpersist:new:%s:%s" % (path, file_hash),
        path=path, sha256=file_hash, hostile=[])


class SshKeyFingerprintParsing(unittest.TestCase):
    """The identity primitive itself, before any DB or sensor is involved."""

    ED25519_BLOB = (
        "AAAAC3NzaC1lZDI1NTE5AAAAIBaZLgtsWyYAdmvvzIkAg8TVDLb+7NqZlSl4h4Kg"
        "Mflz")

    def test_fingerprint_matches_openssh_format(self):
        fp = aegis._ssh_key_fingerprint(self.ED25519_BLOB)
        self.assertTrue(fp.startswith("SHA256:"))
        # unpadded base64 of a 32-byte sha256 digest is exactly 43 chars
        self.assertEqual(43, len(fp) - len("SHA256:"))

    def test_fingerprint_is_deterministic(self):
        a = aegis._ssh_key_fingerprint(self.ED25519_BLOB)
        b = aegis._ssh_key_fingerprint(self.ED25519_BLOB)
        self.assertEqual(a, b)

    def test_different_keys_fingerprint_differently(self):
        other = self.ED25519_BLOB[:-4] + "abcd"
        self.assertNotEqual(aegis._ssh_key_fingerprint(self.ED25519_BLOB),
                            aegis._ssh_key_fingerprint(other))

    def test_malformed_base64_returns_none_not_a_false_fingerprint(self):
        self.assertIsNone(aegis._ssh_key_fingerprint("not-valid-base64!!!"))
        self.assertIsNone(aegis._ssh_key_fingerprint(""))

    @unittest.skipUnless(shutil.which("ssh-keygen"),
                         "no ssh-keygen on this runner")
    def test_fingerprint_matches_ssh_keygen_independently(self):
        """Independent oracle: generate a real key, ask ssh-keygen for ITS
        fingerprint, and confirm our implementation agrees — not just that it
        is internally consistent with itself."""
        tmp = tempfile.mkdtemp(prefix="aegis_sshkey_")
        try:
            keyfile = os.path.join(tmp, "id_ed25519")
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keyfile],
                check=True, timeout=15)
            with open(keyfile + ".pub", encoding="utf-8") as f:
                pub_line = f.read().strip()
            blob = pub_line.split()[1]
            ours = aegis._ssh_key_fingerprint(blob)
            out = subprocess.run(
                ["ssh-keygen", "-lf", keyfile + ".pub"],
                check=True, timeout=15, capture_output=True, text=True).stdout
            # "256 SHA256:xxxxx comment (ED25519)"
            theirs = out.split()[1]
            self.assertEqual(theirs, ours)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_parses_multiple_keys_skipping_blanks_and_comments(self):
        text = "\n".join([
            "# a comment",
            "",
            "ssh-ed25519 %s laptop@home" % self.ED25519_BLOB,
            'from="10.0.0.0/8",no-pty ssh-ed25519 %s work-vpn' %
            self.ED25519_BLOB[:-4] + "abcd",
        ])
        keys = aegis._parse_authorized_keys(text)
        self.assertEqual(2, len(keys))
        self.assertEqual("laptop@home", keys[0][2])
        # the options-prefixed line's key type/blob were still found
        self.assertEqual("ssh-ed25519", keys[1][0])

    def test_unparseable_line_is_skipped_not_fatal(self):
        text = "ssh-ed25519 %s ok\ngarbage line with no key type\n" % \
            self.ED25519_BLOB
        keys = aegis._parse_authorized_keys(text)
        self.assertEqual(1, len(keys))


class IdentityTrustDowngradesAuthSession(Sandbox):
    def test_untrusted_origin_is_left_alone(self):
        f = auth_session("stranger.example.com")
        aegis._apply_identity_trust([f])
        self.assertEqual("HIGH", f["severity"])
        self.assertNotIn("known_identity", f)

    def test_trusted_origin_downgrades_to_low(self):
        aegis.trust_identity("ssh-origin", "laptop.local", "trusted",
                             label="my other laptop")
        f = auth_session("laptop.local")
        aegis._apply_identity_trust([f], now=1_700_000_000)
        self.assertEqual("LOW", f["severity"])
        self.assertEqual("low", f["confidence"])
        self.assertTrue(f["known_identity"])
        row = aegis.list_identities()[0]
        self.assertEqual(1_700_000_000, row["last_seen"])

    def test_blocked_origin_escalates_to_critical(self):
        aegis.trust_identity("ssh-origin", "evil.example.com", "blocked")
        f = auth_session("evil.example.com")
        aegis._apply_identity_trust([f])
        self.assertEqual("CRITICAL", f["severity"])
        self.assertTrue(f["known_identity_blocked"])

    def test_trust_routes_to_digest_not_interrupt(self):
        """The point of the whole mechanism: a trusted recurrence must not
        just be labeled LOW, it must actually stop interrupting."""
        aegis.trust_identity("ssh-origin", "laptop.local", "trusted")
        f = auth_session("laptop.local")
        aegis._apply_identity_trust([f])
        routing = aegis.route_findings([f])
        self.assertEqual(aegis.ROUTE_DIGEST, routing[f["fingerprint"]]["route"])


class IdentityTrustDowngradesAuthorizedKeys(Sandbox):
    KEY_A = ("AAAAC3NzaC1lZDI1NTE5AAAAIBaZLgtsWyYAdmvvzIkAg8TVDLb+7NqZlSl4"
            "h4KgMflz")
    KEY_B = ("AAAAC3NzaC1lZDI1NTE5AAAAIBaZLgtsWyYAdmvvzIkAg8TVDLb+7NqZlSl4"
            "h4Kgabcd")

    def _write_authorized_keys(self, *blobs):
        ssh_dir = os.path.join(self.tmp, ".ssh")
        os.makedirs(ssh_dir, exist_ok=True)
        path = os.path.join(ssh_dir, "authorized_keys")
        with open(path, "w", encoding="utf-8") as f:
            for b in blobs:
                f.write("ssh-ed25519 %s device\n" % b)
        return path

    def test_no_keys_trusted_leaves_severity_and_flags_unrecognized(self):
        path = self._write_authorized_keys(self.KEY_A, self.KEY_B)
        f = authorized_keys_finding(path)
        aegis._apply_identity_trust([f])
        self.assertEqual("MEDIUM", f["severity"])
        self.assertEqual(2, len(f["unrecognized_key_fingerprints"]))

    def test_partial_trust_still_flags_only_the_unrecognized_key(self):
        path = self._write_authorized_keys(self.KEY_A, self.KEY_B)
        trusted_fp = aegis._ssh_key_fingerprint(self.KEY_A)
        aegis.trust_identity("ssh-key", trusted_fp, "trusted")
        f = authorized_keys_finding(path)
        aegis._apply_identity_trust([f])
        self.assertEqual("MEDIUM", f["severity"], "one unrecognized key "
                         "present — must not be silently downgraded")
        self.assertEqual([aegis._ssh_key_fingerprint(self.KEY_B)],
                         f["unrecognized_key_fingerprints"])

    def test_every_key_trusted_downgrades_to_low(self):
        path = self._write_authorized_keys(self.KEY_A, self.KEY_B)
        for blob in (self.KEY_A, self.KEY_B):
            aegis.trust_identity("ssh-key", aegis._ssh_key_fingerprint(blob),
                                 "trusted")
        f = authorized_keys_finding(path)
        aegis._apply_identity_trust([f])
        self.assertEqual("LOW", f["severity"])
        self.assertTrue(f["known_identity"])

    def test_one_blocked_key_escalates_regardless_of_others_trusted(self):
        path = self._write_authorized_keys(self.KEY_A, self.KEY_B)
        aegis.trust_identity("ssh-key", aegis._ssh_key_fingerprint(self.KEY_A),
                             "trusted")
        aegis.trust_identity("ssh-key", aegis._ssh_key_fingerprint(self.KEY_B),
                             "blocked")
        f = authorized_keys_finding(path)
        aegis._apply_identity_trust([f])
        self.assertEqual("CRITICAL", f["severity"])
        self.assertTrue(f["known_identity_blocked"])


class IdentityCli(Sandbox):
    def test_trust_then_list_round_trips(self):
        self.assertEqual(0, aegis.cmd_identity(
            ["aegis.py", "identity", "trust", "ssh-origin", "laptop.local",
             "my", "laptop"]))
        rows = aegis.list_identities()
        self.assertEqual(1, len(rows))
        self.assertEqual("trusted", rows[0]["disposition"])
        self.assertEqual("my laptop", rows[0]["label"])

    def test_block_then_forget(self):
        aegis.cmd_identity(["aegis.py", "identity", "block", "ssh-key", "SHA256:x"])
        self.assertEqual(1, len(aegis.list_identities()))
        self.assertEqual(0, aegis.cmd_identity(
            ["aegis.py", "identity", "forget", "ssh-key", "SHA256:x"]))
        self.assertEqual([], aegis.list_identities())

    def test_unknown_kind_is_rejected(self):
        self.assertEqual(2, aegis.cmd_identity(
            ["aegis.py", "identity", "trust", "carrier-pigeon", "x"]))
        self.assertEqual([], aegis.list_identities())

    def test_forgetting_an_unknown_identity_reports_failure(self):
        self.assertEqual(1, aegis.cmd_identity(
            ["aegis.py", "identity", "forget", "ssh-key", "SHA256:nope"]))


class ConfirmOnceViaBenignPositive(Sandbox):
    """The other entry point into trusted_identities: reusing the incident
    lifecycle's own `benign-positive` verb instead of a second UI."""

    def test_benign_positive_on_auth_session_trusts_its_origin(self):
        f = auth_session("laptop.local")
        aegis.record_security_state([f], now=1_700_000_000)
        incidents = aegis.list_incidents()
        self.assertEqual(1, len(incidents))

        self.assertEqual(0, aegis.cmd_incident(
            str(incidents[0]["id"]), "benign-positive"))

        rows = aegis.list_identities()
        self.assertEqual(1, len(rows))
        self.assertEqual(("ssh-origin", "laptop.local", "trusted"),
                         (rows[0]["kind"], rows[0]["fingerprint"],
                          rows[0]["disposition"]))

        # The actual point: the SAME actor recurring now downgrades.
        later = auth_session("laptop.local")
        aegis._apply_identity_trust([later], now=1_700_003_600)
        self.assertEqual("LOW", later["severity"])

    def test_benign_positive_on_authorized_keys_trusts_the_new_key(self):
        blob = ("AAAAC3NzaC1lZDI1NTE5AAAAIBaZLgtsWyYAdmvvzIkAg8TVDLb+7NqZ"
                "lSl4h4KgMflz")
        ssh_dir = os.path.join(self.tmp, ".ssh")
        os.makedirs(ssh_dir, exist_ok=True)
        path = os.path.join(ssh_dir, "authorized_keys")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("ssh-ed25519 %s new-laptop\n" % blob)
        # HIGH, as a real "changed" authorized_keys finding is (_mk in
        # diff_extra_persistence) — only HIGH+ findings open a standalone
        # incident at all (_apply_correlations), so this is the realistic
        # case a human would actually be triaging with benign-positive.
        f = authorized_keys_finding(path, severity="HIGH")
        # Mirror what a real scan does: identity-trust runs before storage,
        # so the stored finding already carries unrecognized_key_fingerprints.
        aegis._apply_identity_trust([f])
        aegis.record_security_state([f], now=1_700_000_000)
        incidents = aegis.list_incidents()
        self.assertEqual(1, len(incidents))

        aegis.cmd_incident(str(incidents[0]["id"]), "benign-positive")

        expected_fp = aegis._ssh_key_fingerprint(blob)
        rows = aegis.list_identities()
        self.assertEqual(1, len(rows))
        self.assertEqual(("ssh-key", expected_fp, "trusted"),
                         (rows[0]["kind"], rows[0]["fingerprint"],
                          rows[0]["disposition"]))


if __name__ == "__main__":
    unittest.main()
