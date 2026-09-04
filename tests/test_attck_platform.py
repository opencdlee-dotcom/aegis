#!/usr/bin/env python3
"""`attck` claimed coverage it did not have, on every body.

Every technique that had not fired went into one bucket, "wired but quiet".
On this Mac that listed Registry Run Keys, WMI Event Subscription, Winlogon
Helper DLL and Windows Service as covered — which reads as coverage and means
"the sensor for this lives on a different operating system".

The sharpest case was T1574.006, Dynamic Linker Hijacking: it mapped ONLY to
the Linux ld-preload markers, so a Mac reported the technique wired while
having no DYLD coverage at all. And macOS credential dumping had three argv
markers (keychain-dump, keychain-db-access, keychain-security-dump) that
reached no technique, so T1003 read as Windows-only on a Mac whose sensors
for it were sitting in the table.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


class TestPlatformAttributionIsComplete(unittest.TestCase):
    """The table is explicit, so it can drift. This is what stops it."""

    def test_every_technique_has_a_body(self):
        missing = [t for t in aegis.ATTCK_TECHNIQUES
                   if t not in aegis._TECHNIQUE_BODIES]
        self.assertEqual([], missing,
                         "a technique with no platform entry silently claims "
                         "coverage on every body: %s" % missing)

    def test_no_body_entry_without_a_technique(self):
        extra = [t for t in aegis._TECHNIQUE_BODIES
                 if t not in aegis.ATTCK_TECHNIQUES]
        self.assertEqual([], extra)

    def test_bodies_are_spelled_the_way_this_body_reports_itself(self):
        valid = {"mac", "linux", "win"}
        for tech, bodies in aegis._TECHNIQUE_BODIES.items():
            self.assertTrue(bodies, "%s claims no platform at all" % tech)
            self.assertEqual(set(), set(bodies) - valid,
                             "%s: %r" % (tech, bodies))
        self.assertIn(aegis._this_body(), valid)

    def test_an_unmapped_technique_reads_as_claimed_not_as_hidden(self):
        """Direction of failure. A mapping gap must make the report OVER-claim
        so the completeness test above fails loudly — under-claiming would
        quietly shrink coverage and look like an improvement."""
        self.assertTrue(aegis._wired_here("T9999.999"))


class TestWindowsTechniquesAreNotClaimedOnMac(unittest.TestCase):
    WINDOWS_ONLY = ("T1547.001", "T1547.004", "T1546.003", "T1546.013",
                    "T1543.003", "T1053.005", "T1218")
    LINUX_ONLY = ("T1014", "T1543.002", "T1547.006", "T1547.013")

    def _with_body(self, mac, linux, win):
        saved = (aegis.IS_MAC, aegis.IS_LINUX, aegis.IS_WIN)
        self.addCleanup(_restore, saved)
        aegis.IS_MAC, aegis.IS_LINUX, aegis.IS_WIN = mac, linux, win

    def test_mac_does_not_claim_windows_techniques(self):
        self._with_body(True, False, False)
        for t in self.WINDOWS_ONLY + self.LINUX_ONLY:
            self.assertFalse(aegis._wired_here(t), t)

    def test_windows_does_not_claim_launchd(self):
        self._with_body(False, False, True)
        for t in ("T1543.001", "T1543.004", "T1546.004", "T1098.004"):
            self.assertFalse(aegis._wired_here(t), t)
        for t in self.WINDOWS_ONLY:
            self.assertTrue(aegis._wired_here(t), t)

    def test_linux_claims_its_own_and_not_the_others(self):
        self._with_body(False, True, False)
        for t in self.LINUX_ONLY:
            self.assertTrue(aegis._wired_here(t), t)
        for t in self.WINDOWS_ONLY:
            self.assertFalse(aegis._wired_here(t), t)

    def test_dynamic_linker_hijacking_is_claimed_on_both_unix_bodies(self):
        """The specific over-claim that started this: mac reported T1574.006
        wired with only a Linux marker behind it."""
        self.assertEqual(("mac", "linux"),
                         aegis._TECHNIQUE_BODIES["T1574.006"])
        self.assertIn("T1574.006", aegis._MARKER_TECHNIQUES["dyld-inject"])
        self.assertIn("T1574.006",
                      aegis._MARKER_TECHNIQUES["ld-preload-injection"])


class TestMacCredentialDumpingReachesATechnique(unittest.TestCase):
    """Three markers existed and mapped to nothing, so T1003 read Windows-only
    on a Mac. A marker that names an exact rule and reaches no technique is a
    reporting gap, not a detection gap — the finding always fired."""

    MARKERS = ("keychain-dump", "keychain-db-access", "keychain-security-dump")

    def test_each_keychain_marker_maps_to_credential_dumping(self):
        for m in self.MARKERS:
            self.assertIn("T1003", aegis._MARKER_TECHNIQUES.get(m, ()), m)

    def test_the_markers_are_real_rule_names_not_invented_here(self):
        """A mapping for a marker no rule ever sets would be dead weight that
        still reads as coverage."""
        emitted = set()
        for entry in aegis._HOSTILE_ARGV_RES:
            emitted.add(entry[1])
        for entry in aegis._HOSTILE_CONTENT_RES:
            emitted.add(entry[1])
        for m in self.MARKERS:
            self.assertIn(m, emitted, "%s is mapped but never emitted" % m)

    def test_a_finding_carrying_the_marker_classifies(self):
        f = {"category": "behavior", "markers": ["keychain-security-dump"],
             "fingerprint": "behavior:security:keychain-security-dump:abc"}
        self.assertIn("T1003", aegis._finding_techniques(f))


def _restore(saved):
    aegis.IS_MAC, aegis.IS_LINUX, aegis.IS_WIN = saved


if __name__ == "__main__":
    unittest.main()
