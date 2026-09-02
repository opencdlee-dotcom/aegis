"""A content hash glued into a field with '|' must strip like a trailing one.

`_exec_identity` builds agent-surface exec keys as `<cmd>|<sha12>`, so the
fingerprint's LAST ':'-field carries the hash INSIDE it — and
`_TOLERANCE_HASH_RE.match(parts[-1])` can never match, so the hash-strip half
of tolerance never applies. The process sensor emits its sha as its own
':'-field, so version + hash compose there (pinned by test_tolerance.py);
the identical churn shape on an agent surface could not: a versioned
extension path plus a rebuilt binary presented a fresh identity on every
release, and the >=3-matching-verdicts bar was unreachable by construction.

Latent, not live — no open incident is in the versioned-path state — but it
is the same defect family that kept the live queue unjudgeable: an identity
that mutates faster than verdicts can accumulate acquires nothing.

Platform-independent by construction: pure string identities.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import aegis                                    # noqa: E402

EXT = "/u/.vscode/extensions/openai.chatgpt-%s-darwin-arm64/mcp.json"


class GluedHashStripsLikeATrailingOne(unittest.TestCase):
    def test_version_and_glued_hash_compose_for_newexec(self):
        """The agent-surface mirror of
        test_version_and_hash_compose_for_process_fingerprints."""
        a = aegis._tolerance_identity(
            "agent-surface:newexec:%s:node srv.js|aaaaaaaaaaaa"
            % (EXT % "26.818.31338"))
        b = aegis._tolerance_identity(
            "agent-surface:newexec:%s:node srv.js|bbbbbbbbbbbb"
            % (EXT % "26.814.41407"))
        self.assertIsNotNone(a, "no identity produced at all")
        self.assertEqual(a, b,
                         "the same extension across two releases minted two "
                         "identities — tolerance can never accumulate")

    def test_a_target_fingerprint_composes_both_hash_forms(self):
        """agent-surface:target carries a trailing pure-hash field AND a glued
        one: `...:<cmd>|<sha12>:<newsha12>`. Both must strip, or the identity
        still churns with every rebuild."""
        a = aegis._tolerance_identity(
            "agent-surface:target:%s:node srv.js|aaaaaaaaaaaa:cccccccccccc"
            % (EXT % "26.818.31338"))
        b = aegis._tolerance_identity(
            "agent-surface:target:%s:node srv.js|bbbbbbbbbbbb:dddddddddddd"
            % (EXT % "26.814.41407"))
        self.assertIsNotNone(a)
        self.assertEqual(a, b)

    def test_a_pipe_that_is_not_a_hash_does_not_strip(self):
        """`sh -c 'grep x | wc'` is a shell pipe, not a content hash. With no
        version in the path and no real hash anywhere, NOTHING generalizes —
        the identity must stay None, not have its pipe tail eaten."""
        self.assertIsNone(aegis._tolerance_identity(
            "agent-surface:newexec:/stable/path/cfg.json:sh -c grep x | wc"),
            "a shell pipe was read as a strippable content hash")

    def test_different_commands_stay_different(self):
        """Stripping the hash must not merge distinct exec entries."""
        a = aegis._tolerance_identity(
            "agent-surface:newexec:%s:node srv.js|aaaaaaaaaaaa"
            % (EXT % "26.818.31338"))
        b = aegis._tolerance_identity(
            "agent-surface:newexec:%s:python evil.py|aaaaaaaaaaaa"
            % (EXT % "26.818.31338"))
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    unittest.main()
