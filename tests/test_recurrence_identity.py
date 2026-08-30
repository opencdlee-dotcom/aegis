#!/usr/bin/env python3
"""A rotating endpoint is one recurring fact, not an endless stream of new ones.

Three places ask "has this incident already seen this evidence?" and all three
answered with the RAW fingerprint. A beacon fingerprint names the endpoint it
was seen talking to, so any program that rotates destinations — a CDN client, a
sync daemon, an update channel, an editor extension — presents a fingerprint
nothing has ever seen on every single scan. Measured on the reference store:
85 beacon fingerprints over 30 days were 27 actual (program, port) pairs, and
Zotero's eight were one.

Each consumer failed differently, which is why this reads as four unrelated
complaints rather than one bug:

  * `_mark_novelty` refreshed `last_novel_at` forever, so age-out could never
    retire the incident it was written to retire.
  * the FALSE_POSITIVE reattachment subset test never matched, so a `risk:`
    incident the operator had judged benign re-opened under the SAME
    correlation key — `risk:765ed268822cb174` did it three times.
  * `_accumulate_risk` counted each rotated address as another distinct signal,
    so churn alone carried an entity past RISK_MIN_SIGNALS and RISK_THRESHOLD.

The identity used here is the one the tolerance layer already trusts
(`_finding_endpoint_classes`): same program, same port, rotating address.
Anything without an endpoint class keeps its exact fingerprint, so nothing
else in the store generalizes by accident.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aegis  # noqa: E402
from test_regression import Sandbox  # noqa: E402

ZOTERO = "/Applications/Zotero.app/Contents/MacOS/Zotero"


def beacon(path, ip, port="443", sev="MEDIUM"):
    """A beacon finding shaped exactly as the sensor emits one."""
    return aegis.finding(
        sev, "net-beacon", "periodic connection", "d",
        "beacon:%s:%s:%s" % (path, ip, port),
        path=path, confidence="medium",
        subject=aegis._subject("beacon", path, ip=ip, port=port))


class RecurrenceIdentityCollapsesRotation(unittest.TestCase):
    """The identity itself, before any consumer uses it."""

    def test_rotating_address_is_one_identity(self):
        ids = {aegis._recurrence_identity(beacon(ZOTERO, "10.0.0.%d" % i))
               for i in range(30)}
        self.assertEqual(1, len(ids),
                         "thirty addresses on one port are one fact")

    def test_a_different_port_stays_a_different_fact(self):
        a = aegis._recurrence_identity(beacon(ZOTERO, "10.0.0.1", "443"))
        b = aegis._recurrence_identity(beacon(ZOTERO, "10.0.0.1", "22067"))
        self.assertNotEqual(a, b, "the port is not churn — it is the service")

    def test_a_different_program_stays_a_different_fact(self):
        a = aegis._recurrence_identity(beacon(ZOTERO, "10.0.0.1"))
        b = aegis._recurrence_identity(beacon("/opt/other/bin/tool", "10.0.0.1"))
        self.assertNotEqual(a, b)

    def test_a_finding_with_no_endpoint_keeps_its_exact_fingerprint(self):
        """The blast radius. Only an endpoint class generalizes; every other
        sensor's identity must survive this change byte-for-byte."""
        for cat, fp in (("persistence", "persistence:new:/x/y:abc"),
                        ("process", "process:/bin/thing:adhoc:def"),
                        ("agent-surface", "agent-surface:newexec:/a/b:cmd|1234"),
                        ("hot-dir", "hotdir:/tmp/x:adhoc:99")):
            f = aegis.finding("MEDIUM", cat, "t", "d", fp, path="/x/y")
            self.assertEqual(fp, aegis._recurrence_identity(f), cat)

    def test_a_legacy_row_without_a_subject_still_collapses(self):
        """Rows written before subjects carry only the string; the parser the
        tolerance layer uses on them has to apply here too, or the fix would
        skip every incident that predates it."""
        f = aegis.finding("MEDIUM", "net-beacon", "t", "d",
                          "beacon:%s:10.0.0.7:443" % ZOTERO, path=ZOTERO)
        self.assertEqual(aegis._recurrence_identity(f),
                         aegis._recurrence_identity(beacon(ZOTERO, "10.0.0.9")))


class RotationDoesNotManufactureRisk(Sandbox):
    def _risk(self):
        return [i for i in aegis.list_incidents()
                if i["title"].startswith("Accumulated risk")]

    def test_rotation_alone_does_not_open_a_risk_incident(self):
        """Four addresses from one program on one port is one signal, and one
        signal never clears RISK_MIN_SIGNALS."""
        aegis.record_security_state(
            [beacon(ZOTERO, "34.231.186.%d" % i) for i in range(4)])
        self.assertEqual([], self._risk(),
                         "endpoint churn manufactured a risk incident")

    def test_genuinely_distinct_signals_still_accumulate(self):
        """The control: the detector must still do its job. Three DIFFERENT
        sensors on one entity is the case risk accumulation exists for."""
        p = "/Users/Shared/thing"
        fs = [aegis.finding("MEDIUM", c, "s%d" % i, "d", "fp-%d" % i,
                            path=p, confidence="medium")
              for i, c in enumerate(("hot-dir", "staging", "behavior"))]
        aegis.record_security_state(fs)
        self.assertTrue(self._risk(), "real corroboration must still escalate")


class AJudgedPileStaysJudged(Sandbox):
    def _active_risk(self):
        return [i for i in aegis.list_incidents()
                if i["title"].startswith("Accumulated risk")
                and i.get("status") != "FALSE_POSITIVE"]

    def test_rotation_does_not_reopen_a_judged_risk_incident(self):
        """The defect that cost the operator three verdicts on one fact:
        `risk:765ed268822cb174` was judged benign, and re-opened under the
        identical key on the next rotation, twice."""
        p = "/Users/Shared/rotator"
        t0 = 1_700_000_000
        first = [beacon(p, "10.0.0.1"),
                 aegis.finding("MEDIUM", "process", "exec", "d",
                               "process:%s:adhoc:aaa" % p, path=p),
                 aegis.finding("MEDIUM", "net-outbound", "out", "d",
                               "outbound:%s" % p, path=p)]
        aegis.record_security_state(first, now=t0)
        risk = self._active_risk()
        self.assertEqual(1, len(risk), "setup: three sensors should escalate")
        aegis.transition_incident(risk[0]["id"], "FALSE_POSITIVE",
                                  reason_code="benign-positive")

        rotated = [beacon(p, "10.0.0.2"),
                   aegis.finding("MEDIUM", "process", "exec", "d",
                                 "process:%s:adhoc:aaa" % p, path=p),
                   aegis.finding("MEDIUM", "net-outbound", "out", "d",
                                 "outbound:%s" % p, path=p)]
        aegis.record_security_state(rotated, now=t0 + 60)
        self.assertEqual([], self._active_risk(),
                         "a rotated address re-opened a judged incident")

    def test_a_genuinely_new_signal_still_opens(self):
        """The other pole, and the one that keeps this safe: collapsing
        rotation must not blind the tool to a NEW kind of evidence on an
        entity the operator has already forgiven."""
        p = "/Users/Shared/rotator2"
        t0 = 1_700_000_000
        first = [beacon(p, "10.0.0.1"),
                 aegis.finding("MEDIUM", "process", "exec", "d",
                               "process:%s:adhoc:aaa" % p, path=p),
                 aegis.finding("MEDIUM", "net-outbound", "out", "d",
                               "outbound:%s" % p, path=p)]
        aegis.record_security_state(first, now=t0)
        risk = self._active_risk()
        self.assertEqual(1, len(risk))
        aegis.transition_incident(risk[0]["id"], "FALSE_POSITIVE",
                                  reason_code="benign-positive")

        later = [aegis.finding("MEDIUM", c, "s%d" % i, "d", "fresh-%d" % i,
                               path=p, confidence="medium")
                 for i, c in enumerate(("persistence", "hot-dir", "behavior"))]
        aegis.record_security_state(later, now=t0 + 30 * 86400)
        self.assertEqual(1, len(self._active_risk()),
                         "new evidence on a forgiven entity was swallowed")


class RotationDoesNotRefreshTheNoveltyClock(Sandbox):
    """Age-out measures `last_novel_at` — "when did this last tell me something
    I did not already know". A rotating address answered "just now" on every
    scan, so the long-lived entity-keyed incidents age-out exists to retire
    were exactly the ones it could never reach.

    It has to be an ENTITY-keyed incident to show this. A signal incident
    embeds the endpoint in its correlation key, so a rotated address opens a
    separate case instead of re-touching the first one — the novelty clock is
    never consulted there, and a test built on one would pass against the
    defect."""

    def _novel_at(self, incident_id):
        db = aegis._event_connection()
        try:
            return db.execute("SELECT last_novel_at FROM incidents WHERE id=?",
                              (incident_id,)).fetchone()[0]
        finally:
            db.close()

    def test_a_rotated_address_is_not_novelty(self):
        p = "/Users/Shared/beaconer"
        t0 = 1_700_000_000

        def batch(ip):
            return [beacon(p, ip),
                    aegis.finding("MEDIUM", "process", "exec", "d",
                                  "process:%s:adhoc:aaa" % p, path=p),
                    aegis.finding("MEDIUM", "net-outbound", "out", "d",
                                  "outbound:%s" % p, path=p)]

        aegis.record_security_state(batch("10.0.0.1"), now=t0)
        risk = [i for i in aegis.list_incidents()
                if i["title"].startswith("Accumulated risk")]
        self.assertEqual(1, len(risk), "setup: three sensors should escalate")
        before = self._novel_at(risk[0]["id"])

        # Same three facts an hour later, one of them from a new address.
        aegis.record_security_state(batch("10.0.0.2"), now=t0 + 3600)
        self.assertEqual(before, self._novel_at(risk[0]["id"]),
                         "rotation refreshed the novelty clock, so this "
                         "incident can never age out")

    def test_a_genuinely_new_fact_still_counts_as_novelty(self):
        """The control. Collapsing rotation must not freeze the clock against
        evidence that really is new, or age-out would retire live incidents."""
        p = "/Users/Shared/beaconer2"
        t0 = 1_700_000_000
        base = [beacon(p, "10.0.0.1"),
                aegis.finding("MEDIUM", "process", "exec", "d",
                              "process:%s:adhoc:aaa" % p, path=p),
                aegis.finding("MEDIUM", "net-outbound", "out", "d",
                              "outbound:%s" % p, path=p)]
        aegis.record_security_state(base, now=t0)
        risk = [i for i in aegis.list_incidents()
                if i["title"].startswith("Accumulated risk")]
        self.assertEqual(1, len(risk))
        before = self._novel_at(risk[0]["id"])

        fresh = base + [aegis.finding("MEDIUM", "persistence", "job", "d",
                                      "persistence:new:%s:zzz" % p, path=p)]
        aegis.record_security_state(fresh, now=t0 + 3600)
        self.assertEqual(t0 + 3600, self._novel_at(risk[0]["id"]),
                         "a genuinely new fact must still advance the clock")


if __name__ == "__main__":
    unittest.main()


class PortRotationIsBreadthEarnedInsideTheIncident(unittest.TestCase):
    """Collapsing the address left the PORT doing what the address used to.

    Syncthing re-opened a judged `risk:` case on ports 50695 and 62429 hours
    after the address fix landed, because a peer-to-peer client varies address
    and port together by design. The incident that had already watched it on
    sixteen ports is the one entitled to say a seventeenth is not news.
    """

    def held(self, prog, ports):
        return {"beacon:%s:#ip:%s" % (prog, p) for p in ports}

    def test_a_program_watched_across_many_ports_absorbs_another(self):
        held = self.held("/opt/st/syncthing", ("22000", "22067", "49803", "54842"))
        self.assertFalse(aegis._carries_new_evidence(
            {"beacon:/opt/st/syncthing:#ip:50695"}, held))

    def test_two_ports_is_not_yet_rotation(self):
        """The discriminating case, and the reason the bar is not
        `_ROTATING_MIN_PORTS`: an ordinary service answering on 80 and 443 has
        demonstrated nothing, and its next port is the new fact it is."""
        held = self.held("/opt/app/svc", ("80", "443"))
        self.assertTrue(aegis._carries_new_evidence(
            {"beacon:/opt/app/svc:#ip:4444"}, held))

    def test_rotation_is_established_per_program_not_per_incident(self):
        held = self.held("/opt/st/syncthing", ("22000", "22067", "49803"))
        self.assertTrue(aegis._carries_new_evidence(
            {"beacon:/opt/other/tool:#ip:4444"}, held),
            "one program's rotation must not cover another's new port")

    def test_a_rotating_program_doing_something_else_still_alerts(self):
        """The safety pole. Absorbing ports must not absorb the program."""
        held = self.held("/opt/st/syncthing", ("22000", "22067", "49803"))
        self.assertTrue(aegis._carries_new_evidence(
            {"persistence:new:/opt/st/syncthing:abc"}, held))

    def test_an_empty_incoming_set_is_never_new(self):
        self.assertFalse(aegis._carries_new_evidence(set(), self.held("/x", ("1",))))


class AJudgedRotatorStaysJudged(Sandbox):
    """End to end, on the shape that actually recurred on the reference
    machine: a peer-to-peer client judged benign must not re-open its case
    every time it picks a fresh ephemeral port."""

    def _active_risk(self):
        return [i for i in aegis.list_incidents()
                if i["title"].startswith("Accumulated risk")
                and i.get("status") != "FALSE_POSITIVE"]

    def _batch(self, p, port, host=1):
        # Distinct, VALID addresses: a leading zero ("10.0.0.03") is rejected
        # by ipaddress, so such a beacon yields no endpoint class at all and
        # the rotation this test is about would never be established.
        return [beacon(p, "10.0.0.%d" % host, port),
                aegis.finding("MEDIUM", "process", "exec", "d",
                              "process:%s:adhoc:aaa" % p, path=p),
                aegis.finding("MEDIUM", "net-outbound", "out", "d",
                              "outbound:%s" % p, path=p)]

    def test_a_new_ephemeral_port_does_not_reopen_the_judged_case(self):
        p = "/opt/st/syncthing"
        t0 = 1_700_000_000
        for i, port in enumerate(("22000", "22067", "49803")):
            aegis.record_security_state(self._batch(p, port, host=i + 1),
                                        now=t0 + i * 60)
        risk = self._active_risk()
        self.assertEqual(1, len(risk), "setup: the rotator should escalate once")
        aegis.transition_incident(risk[0]["id"], "FALSE_POSITIVE",
                                  reason_code="benign-positive")

        aegis.record_security_state(self._batch(p, "50695", host=9),
                                    now=t0 + 3600)
        self.assertEqual([], self._active_risk(),
                         "a fresh ephemeral port re-opened a judged case")

    def test_a_new_SENSOR_on_the_same_rotator_still_opens(self):
        p = "/opt/st/syncthing2"
        t0 = 1_700_000_000
        for i, port in enumerate(("22000", "22067", "49803")):
            aegis.record_security_state(self._batch(p, port, host=i + 1),
                                        now=t0 + i * 60)
        risk = self._active_risk()
        self.assertEqual(1, len(risk))
        aegis.transition_incident(risk[0]["id"], "FALSE_POSITIVE",
                                  reason_code="benign-positive")

        fresh = [aegis.finding("MEDIUM", c, "s%d" % i, "d", "new-%d" % i,
                               path=p, confidence="medium")
                 for i, c in enumerate(("persistence", "hot-dir", "behavior"))]
        aegis.record_security_state(fresh, now=t0 + 30 * 86400)
        self.assertEqual(1, len(self._active_risk()),
                         "new evidence on a forgiven rotator was swallowed")


class AFamilyOfOneDoesNotClaimAnIdentity(unittest.TestCase):
    """`families` groups incidents by an identity tolerance already keys on,
    and lists whatever cannot generalize on its own. The synthetic key it mints
    for those is unique to one row by construction — but it was rendered through
    the generic "N incident(s) sharing <key>" branch, so the command reported
    nine of fourteen live rows as sharing an identity none of them had."""

    def test_the_ungrouped_key_is_never_rendered_as_shared(self):
        label = aegis._family_label("%s285" % aegis._FAMILY_UNGROUPED_PREFIX,
                                    [{"id": 285}])
        self.assertNotIn("sharing", label)
        self.assertIn("no shared identity", label)

    def test_a_real_shared_identity_still_says_so(self):
        rows = [{"id": 1}, {"id": 2}]
        label = aegis._family_label("behavior:bash:fileless-fetch-exec", rows)
        self.assertIn("sharing", label)
        self.assertIn("2 incident(s)", label)

    def test_an_endpoint_family_still_names_its_program(self):
        label = aegis._family_label("beacon:/opt/st/syncthing:#ip:443",
                                    [{"id": 1}, {"id": 2}])
        self.assertIn("/opt/st/syncthing", label)
        self.assertIn("endpoint(s) of one program", label)
