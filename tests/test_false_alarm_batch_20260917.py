#!/usr/bin/env python3
"""The 2026-09-17 batch: 110 open incidents, four root causes, ~15 facts.

The live reference Mac held 110 OPEN incidents (104 HIGH, 2 CRITICAL, 4
MEDIUM) against 365 already adjudicated FALSE_POSITIVE. Counted by distinct
underlying fact rather than by row, the open set was roughly fifteen things.
Three clusters carried it, and each had its own cause:

  37  Persistence item CHANGED    all at ONE timestamp, 2026-09-15 22:51:48.
                                  Five facts: /bin/bash, /usr/bin/open,
                                  /usr/bin/python3, /bin/date, /usr/bin/ssh,
                                  replaced together by the macOS 27.0 update
                                  (identical mtime Sep 3 03:34). /bin/bash
                                  alone accounted for 29 incidents because 29
                                  launchd jobs invoke it.
  42  Suspicious running process  26 distinct binaries. One build of the
                                  operator's own app was byte-identical at
                                  /Applications, ~/Downloads and four agent
                                  worktree staging trees (sha f0dddc74…).
  22  Persistent outbound         17 endpoint keys, EVERY one resolving to
      connection (beacon shape)   ec2-*.compute-1.amazonaws.com -- one service
                                  behind rotating addresses. 13 of them were
                                  one binary.

Underneath sat a fourth cause that made the first cluster possible at all, and
it is the one worth remembering: `_classify_mac` identified Apple's own
binaries by `leaf == "Software Signing"`, an exact match on a string Apple
renames between major releases. From macOS 26 it is "macOS Software Signing",
so on upgrade day the `apple` trust tier emptied -- 109 of 123 /usr/bin
binaries carried the new string and not one classified `apple`. See
test_signature_corpus.py, which is the ratchet for that class of bug.

The shared shape of the three clusters is worth naming, because this monitor
has now re-solved it once per surface for a month: a finding's case was keyed
on WHERE something was seen rather than on WHAT was seen. A path, a plist, a
socket. So one fact observed at N places became N incidents, each demanding
its own adjudication. The fix is never suppression -- every cluster below
still reaches the report -- it is making the N places EVIDENCE on one case.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


def plist(label, program, sha, path=None):
    return {
        "label": label, "program": program, "sha256": sha,
        "trust": "apple", "env": None, "args": [program, "/tmp/x.sh"],
        "run_at_load": True,
        "path": path or ("/Users/x/Library/LaunchAgents/%s.plist" % label),
    }


class OneOsUpdateIsOneFinding(unittest.TestCase):
    """29 jobs invoking /bin/bash is still one /bin/bash."""

    def setUp(self):
        self._mac, self._sip = aegis.IS_MAC, aegis._SIP_STATE
        aegis.IS_MAC, aegis._SIP_STATE = True, True

    def tearDown(self):
        aegis.IS_MAC, aegis._SIP_STATE = self._mac, self._sip

    def _snaps(self, n=29, program="/bin/bash", trust="apple", tag=""):
        base, cur = {}, {}
        for i in range(n):
            p = ("/Users/x/Library/LaunchAgents/com.example%s.job%d.plist"
                 % (tag, i))
            rec = plist("com.example%s.job%d" % (tag, i), program, "OLD", p)
            rec["trust"] = trust
            base[p] = dict(rec)
            new = dict(rec, sha256="NEW")
            cur[p] = new
        return base, cur

    def test_twenty_nine_referrers_collapse_to_one(self):
        base, cur = self._snaps()
        out = aegis.check_persistence(base, cur)
        changed = [f for f in out if f["title"].startswith("Persistence item")]
        updates = [f for f in out if "OS program" in f["title"]]
        self.assertEqual(changed, [], "per-plist findings should be gone")
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0]["severity"], "LOW")

    def test_the_referrers_survive_as_evidence(self):
        """Collapsing must not destroy information. The single finding knows
        more than any of the 29 it replaces: all 29 referrers."""
        base, cur = self._snaps()
        f = [x for x in aegis.check_persistence(base, cur)
             if "OS program" in x["title"]][0]
        self.assertEqual(f["referrer_count"], 29)
        self.assertEqual(len(f["referrers"]), 29)
        self.assertEqual(f["path"], "/bin/bash")

    def test_distinct_programs_stay_distinct(self):
        """Five OS binaries updating is five facts, not one and not 37."""
        base, cur = {}, {}
        for prog in ("/bin/bash", "/usr/bin/open", "/usr/bin/python3",
                     "/bin/date", "/usr/bin/ssh"):
            b, c = self._snaps(n=4, program=prog, tag=prog.replace("/", "-"))
            base.update(b)
            cur.update(c)
        updates = [f for f in aegis.check_persistence(base, cur)
                   if "OS program" in f["title"]]
        self.assertEqual(sorted(f["path"] for f in updates),
                         ["/bin/bash", "/bin/date", "/usr/bin/open",
                          "/usr/bin/python3", "/usr/bin/ssh"])

    def test_next_update_is_not_a_silenced_recurrence(self):
        """The signal key carries the new sha, so a later update re-alerts."""
        base, cur = self._snaps(n=2)
        first = [f for f in aegis.check_persistence(base, cur)
                 if "OS program" in f["title"]][0]
        base2 = {k: dict(v, sha256="NEW") for k, v in base.items()}
        cur2 = {k: dict(v, sha256="NEWER") for k, v in cur.items()}
        second = [f for f in aegis.check_persistence(base2, cur2)
                  if "OS program" in f["title"]][0]
        self.assertNotEqual(first["fingerprint"], second["fingerprint"])
        self.assertEqual(first["case_fingerprint"], second["case_fingerprint"])


class TheGuardRefusesEverythingItShould(unittest.TestCase):
    """Each conjunct in _os_program_update, pinned by the attack it stops.

    A quieting rule is only as good as its refusals, so these are spelled out
    one per attack rather than folded into a table.
    """

    def setUp(self):
        self._mac, self._sip = aegis.IS_MAC, aegis._SIP_STATE
        aegis.IS_MAC, aegis._SIP_STATE = True, True

    def tearDown(self):
        aegis.IS_MAC, aegis._SIP_STATE = self._mac, self._sip

    def _call(self, old, rec, **kw):
        flags = {"prog_changed": True, "env_changed": False,
                 "args_changed": False, "target_changed": False}
        flags.update(kw)
        return aegis._os_program_update(old, rec, **flags)

    def test_accepts_the_real_case(self):
        old = plist("j", "/bin/bash", "OLD")
        self.assertEqual(self._call(old, dict(old, sha256="NEW")), "/bin/bash")

    def test_refuses_a_dylib_injection_riding_along(self):
        old = plist("j", "/bin/bash", "OLD")
        rec = dict(old, sha256="NEW", env={"DYLD_INSERT_LIBRARIES": "/tmp/e.dylib"})
        self.assertIsNone(self._call(old, rec, env_changed=True))

    def test_refuses_a_rewritten_payload_riding_along(self):
        old = plist("j", "/bin/bash", "OLD")
        self.assertIsNone(self._call(old, dict(old, sha256="NEW"),
                                     target_changed=True))
        self.assertIsNone(self._call(old, dict(old, sha256="NEW"),
                                     args_changed=True))

    def test_refuses_a_repointed_program(self):
        """The job now runs something else. That is the attack, not an update."""
        old = plist("j", "/bin/bash", "OLD")
        rec = dict(old, program="/tmp/evil", sha256="NEW")
        self.assertIsNone(self._call(old, rec))

    def test_refuses_operator_writable_prefixes(self):
        """/usr/local and /opt/homebrew are NOT the sealed volume; both are in
        RISKY_PREFIXES precisely because anyone can write there."""
        for prog in ("/usr/local/bin/bash", "/opt/homebrew/bin/bash",
                     "/Users/x/bin/bash"):
            old = plist("j", prog, "OLD")
            self.assertIsNone(self._call(old, dict(old, sha256="NEW")), prog)

    def test_refuses_a_non_apple_signature(self):
        """A Developer-ID or adhoc binary sitting in /usr/bin is exactly the
        supply-chain swap the original rule was written for."""
        for trust in ("developer-id", "signed-other", "adhoc", "unsigned",
                      "broken", "app-store", None):
            old = plist("j", "/usr/bin/open", "OLD")
            old["trust"] = trust
            self.assertIsNone(self._call(old, dict(old, sha256="NEW")), trust)

    def test_refuses_when_sip_is_off(self):
        """The whole argument is "nothing as the operator can write there".
        With SIP off that is false, so the guard must vanish."""
        aegis._SIP_STATE = False
        old = plist("j", "/bin/bash", "OLD")
        self.assertIsNone(self._call(old, dict(old, sha256="NEW")))

    def test_sip_unknown_reads_as_off(self):
        """Fails closed: an unreadable csrutil keeps the alarm."""
        aegis._SIP_STATE = None
        real = aegis.run
        aegis.run = lambda *a, **k: ("", "csrutil: not found", 127)
        try:
            self.assertFalse(aegis._sip_enabled())
        finally:
            aegis.run = real
            aegis._SIP_STATE = True


class RotatingEndpointsAreOneRelationship(unittest.TestCase):
    """13 addresses on one port from one binary is one service, not 13 beacons.

    Every one of the 17 live endpoint keys resolved to
    ec2-*.compute-1.amazonaws.com. The sensor's premise is that a beacon's
    endpoint does NOT move, so a program spread across many addresses is
    evidence AGAINST the hypothesis the sensor is testing -- and it was being
    turned into the fan-out key, which multiplied both the incident count and
    the per-entity risk weight.
    """

    def _rows(self, n, path="/Users/x/app/staging/A.app/Contents/MacOS/a",
              port="443"):
        return [(path, "203.0.113.%d" % (i + 1), port, "adhoc")
                for i in range(n)]

    def _run(self, rows):
        now = 1_000_000
        stamps = tuple(now + i * 3600 for i in range(aegis.BEACON_MIN_SCANS + 2))
        sightings = {(r[0], r[1], r[2]): stamps for r in rows}
        return aegis._beacon_from_sightings(sightings, rows)

    def test_many_addresses_collapse_to_one_finding(self):
        out = self._run(self._rows(13))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["title"],
                         "Persistent outbound connection (rotating endpoints)")
        self.assertEqual(out[0]["endpoint_count"], 13)
        self.assertEqual(len(out[0]["endpoints"]), 13)

    def test_a_fixed_endpoint_keeps_the_full_alarm(self):
        """The real beacon shape must be untouched -- this is the detection."""
        out = self._run(self._rows(1))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["title"],
                         "Persistent outbound connection (beacon shape)")

    def test_a_short_fallback_list_keeps_the_full_alarm(self):
        """A C2 fallback list is characteristically 2-3 addresses. The
        threshold sits deliberately above it."""
        for n in (2, 3):
            out = self._run(self._rows(n))
            self.assertEqual(len(out), n, "%d addresses" % n)
            for f in out:
                self.assertEqual(
                    f["title"], "Persistent outbound connection (beacon shape)")

    def test_dispersion_demotes_exactly_one_step_and_is_not_dropped(self):
        out = self._run(self._rows(13))
        self.assertEqual(out[0]["severity"], "MEDIUM")  # one step from HIGH
        self.assertIn("every address is listed here", out[0]["detail"])

    def test_different_ports_stay_different_relationships(self):
        rows = self._rows(5, port="443") + self._rows(5, port="8443")
        out = self._run(rows)
        self.assertEqual(sorted(f["port"] for f in out), ["443", "8443"])

    def test_different_programs_stay_different(self):
        rows = (self._rows(5, path="/Users/x/a/staging/A.app/Contents/MacOS/a")
                + self._rows(5, path="/Users/x/b/staging/B.app/Contents/MacOS/b"))
        self.assertEqual(len(self._run(rows)), 2)


class BuildOutputIsARung(unittest.TestCase):
    """A generated artifact of the operator's own repo can finally be graded.

    `_grade_binary` asked exactly two questions -- is there a hand-signed
    vouch, is there a package receipt -- and a developer's machine answers no
    to both for everything it builds. This is the missing rung, not a missing
    wire.
    """

    def setUp(self):
        aegis._BUILD_OUTPUT_CACHE.clear()
        aegis._REPO_SELFNESS_CACHE.clear()

    tearDown = setUp

    def test_it_is_weak_by_construction(self):
        """One step, never suppression, still corroborating at half weight."""
        self.assertIn("build-output", aegis._WEAK_CUSTODY)
        self.assertEqual(aegis._RISK_CUSTODY_WEIGHT["build-output"], 0.5)
        self.assertEqual(aegis._demote("HIGH", "build-output"), "MEDIUM")
        self.assertEqual(aegis._demote("CRITICAL", "build-output"), "HIGH")
        self.assertIn("build-output", aegis._PROVENANCE_NOTE)

    def test_attack_defined_evidence_is_never_graded_by_it(self):
        self.assertEqual(
            aegis._demote("HIGH", "build-output", attack_defined=True), "HIGH")

    def test_a_path_with_no_repo_gets_nothing(self):
        self.assertIsNone(aegis._build_output_rung("/tmp/nope/not-a-repo-bin"))
        self.assertIsNone(aegis._build_output_rung(""))
        self.assertIsNone(aegis._build_output_rung(None))

    def test_a_tracked_file_in_our_own_repo_gets_nothing(self):
        """The rung is "the repo says it GENERATES this", not "the repo knows
        about it". aegis.py is committed, so it must not qualify."""
        here = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "aegis.py")
        self.assertIsNone(aegis._build_output_rung(here))


if __name__ == "__main__":
    unittest.main()
