#!/usr/bin/env python3
"""The signature classifier is tested against REAL binaries, not fixtures.

On 2026-09-17 the reference Mac held 110 open incidents. The largest single
cause was one line: `_classify_mac` decided a binary was Apple's own with

    elif leaf == "Software Signing":

and Apple renames that leaf authority between major releases -- "Software
Signing" through macOS 15, "macOS Software Signing" from macOS 26. On upgrade
day the equality stopped matching and every platform binary on the host fell
through to `signed-other`, "signed, but by nobody I recognize". Measured at
macOS 27.0 (26A428): 109 of 123 binaries under /usr/bin carried the new
string, and NOT ONE classified `apple`. The tier was dead, silently, for as
long as the machine had been upgraded.

Nothing caught it, and the reason is the point of this file. Two tests
referenced "Software Signing" and both INJECTED it:

    {"trust": PUBLISHER_TRUST, "authority": "Software Signing", ...}

A fixture like that proves the callers read the verdict correctly. It cannot
prove the parser still produces it, because it replaces the parser. Every
input-parsing bug in a vendor-format reader is invisible to a suite that mocks
the reader -- the same lesson as `simbody`'s: a simulated body cannot fail on
what only a real one produces.

So this file classifies binaries that actually exist on the running machine and
asserts the tier each one lands in. It is a RATCHET: the next time Apple
renames a certificate, or `codesign` changes its output, a test fails on that
machine instead of a trust tier quietly emptying. It skips off macOS rather
than simulating -- a simulated answer here would be the very thing that failed.

The classifier must stay CONJUNCTIVE to be safe. `_is_apple_os_signing`
generalizes the leaf NAME, so the test below pins the thing it must not
generalize: the issuing CA. A leaf called "Software Signing" chained to
anything but Apple's OS-signing intermediate is not Apple, or the rename
tolerance becomes a forgery tolerance.
"""
import os
import re
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

# Gated on BOTH, deliberately. CI runs a Linux leg with aegis.IS_MAC forced on
# to exercise mac code paths, and that leg has no codesign to be right about.
REAL_MAC = sys.platform == "darwin" and aegis.IS_MAC

# Guaranteed present on every macOS, and platform-signed on every macOS.
PLATFORM_ANCHORS = ["/bin/sh", "/bin/bash", "/usr/bin/codesign", "/usr/bin/true"]


def _leaf_and_chain(path):
    out = subprocess.run(["codesign", "-dv", "--verbose=4", path],
                         capture_output=True, text=True)
    text = (out.stdout or "") + (out.stderr or "")
    auth = [a.strip() for a in re.findall(r"Authority=(.+)", text)]
    return (auth[0] if auth else None), auth


@unittest.skipUnless(REAL_MAC, "classifies real codesign output; macOS only")
class AppleTierIsReachable(unittest.TestCase):
    """The `apple` tier must be produced by real binaries, not just defined.

    This is the assertion whose absence cost the 110-incident batch. It is
    phrased as "reachable at all" on purpose: the failure mode was not one
    misclassified binary, it was a tier that no input on the machine could
    reach any more.
    """

    def setUp(self):
        aegis._sigcache = {}  # a stale entry would answer for the parser

    def test_platform_binaries_classify_apple(self):
        for path in PLATFORM_ANCHORS:
            if not os.path.exists(path):
                continue
            trust = aegis.classify_signature(path)["trust"]
            self.assertEqual(
                trust, "apple",
                "%s classified %r, not 'apple'. Its leaf authority is %r. "
                "If Apple renamed the certificate again, widen "
                "_APPLE_OS_SIGNING_LEAF_RE -- do NOT drop the CA conjunct."
                % (path, trust, _leaf_and_chain(path)[0]))

    def test_system_binary_corpus_is_overwhelmingly_apple(self):
        """A per-file assertion can be satisfied by a lucky special case; the
        tier is only alive if it holds across the population. The 2026-09-15
        state scored 0%."""
        corpus = [os.path.join("/usr/bin", n)
                  for n in sorted(os.listdir("/usr/bin"))[:60]]
        corpus = [p for p in corpus if os.path.isfile(p)]
        apple = [p for p in corpus
                 if aegis.classify_signature(p)["trust"] == "apple"]
        self.assertGreater(
            len(apple), 0.9 * len(corpus),
            "only %d of %d /usr/bin binaries classified 'apple'; the platform "
            "trust tier is effectively dead" % (len(apple), len(corpus)))


@unittest.skipUnless(REAL_MAC, "classifies real codesign output; macOS only")
class TierBoundariesHold(unittest.TestCase):
    """Widening the Apple leaf match must not swallow the other tiers."""

    def setUp(self):
        aegis._sigcache = {}

    def test_developer_id_is_not_apple(self):
        found = False
        for app in sorted(os.listdir("/Applications"))[:40]:
            path = os.path.join("/Applications", app)
            leaf, _ = _leaf_and_chain(path)
            if not (leaf or "").startswith("Developer ID Application"):
                continue
            found = True
            trust = aegis.classify_signature(path)["trust"]
            # `broken` is a legitimate verdict here and not a miss: the
            # classifier runs `codesign --verify --strict` last and lets a
            # failed integrity check override the tier. The claim under test is
            # only that a Developer-ID leaf never lands in the APPLE tier.
            self.assertNotEqual(trust, "apple", path)
            self.assertIn(trust, ("developer-id", "broken"), path)
        if not found:
            self.skipTest("no Developer-ID app on this host")

    def test_apple_tier_requires_apples_own_ca(self):
        """The rename tolerance must not become a forgery tolerance.

        `_is_apple_os_signing` matches the leaf NAME by pattern, so the only
        thing standing between it and a hand-rolled "Software Signing" leaf is
        the issuing CA. Pin that.
        """
        self.assertTrue(aegis._is_apple_os_signing(
            "macOS Software Signing",
            ["macOS Software Signing",
             "Apple Code Signing Certification Authority", "Apple Root CA"]))
        self.assertTrue(aegis._is_apple_os_signing(
            "Software Signing",
            ["Software Signing",
             "Apple Code Signing Certification Authority", "Apple Root CA"]))
        # Right name, wrong issuer: a self-signed chain, and a Developer-ID
        # chain, which any paid account can obtain.
        self.assertFalse(aegis._is_apple_os_signing(
            "Software Signing", ["Software Signing"]))
        self.assertFalse(aegis._is_apple_os_signing(
            "macOS Software Signing",
            ["macOS Software Signing", "Developer ID Certification Authority",
             "Apple Root CA"]))
        # Not the OS-signing family at all.
        self.assertFalse(aegis._is_apple_os_signing(
            "Apple Mac OS Application Signing",
            ["Apple Mac OS Application Signing",
             "Apple Code Signing Certification Authority"]))
        self.assertFalse(aegis._is_apple_os_signing(None, []))


if __name__ == "__main__":
    unittest.main()
