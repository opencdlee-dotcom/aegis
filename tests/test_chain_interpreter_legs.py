#!/usr/bin/env python3
"""Precision plan S3, 2026-09-23: a chain was manufactured from two facts that
had each already been explained.

Live incident #538, MEDIUM, `Persistence followed by execution`, keyed
`chain:persistence-execution:b1fd29aea4dad2af` -- the hash of `/bin/bash`:

  left   `OS program referenced by persistence items was updated`. macOS 27
         replaced /bin/bash on the sealed system volume; the persistence
         sensor graded it `custody=os-vendor`, LOW, and keyed it on the
         PROGRAM, so its primary entity is `/bin/bash`.
  right  `Suspicious process behavior` on a command the operator's agent
         harness ran through `/bin/bash`. Primary entity: `/bin/bash`.

`_entities()` has always said a chain must never join on a shared interpreter,
and names /bin/bash as the sharpest case. The exclusion was only ever applied
to the SECONDARY entities; the primary was returned unconditionally, and here
the primary IS the interpreter, on both sides. #517 (`chain:clickfix`, the same
hash) was the same join under an attack-defined rule.

Two rules, both in the correlation tier:

  1. an interpreter is never the shared entity of a chain, from either side;
  2. a finding whose custody is in the self or vouched tier cannot TRIGGER a
     chain. It may still be the other leg of one an unexplained finding
     triggers -- the same shape the tolerated/allowlisted events already have
     -- and attack-defined evidence is never excluded.

Plus the exit: a one-time store migration closes the open chains the two rules
would not have formed.
"""
import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling import
import aegis  # noqa: E402
from test_regression import Sandbox  # noqa: E402


T0 = 1_790_161_643          # #538's created_at on the live store


def _entity_hash(value):
    """The entity half of a chain key, computed the way correlate() does."""
    return hashlib.sha256(aegis._canon_entity_path(value).encode(
        "utf-8", "replace")).hexdigest()[:16]


def _os_update_leg(fp="persistence:os-program-update:/bin/bash:sha1"):
    """Leg A of #538, as check_persistence emits it -- minus `trust`, which
    no correlation rule reads and whose value here is macOS vocabulary."""
    return aegis.finding(
        "LOW", "persistence",
        "OS program referenced by persistence items was updated",
        "/bin/bash is Apple-platform-signed on the sealed system volume",
        fp, case_fingerprint="persistence:os-program-update:/bin/bash",
        path="/bin/bash", program="/bin/bash",
        custody="os-vendor", referrer_count=29, referrers=["com.x.job"])


def _harness_leg(fp="behavior:bash:eval-subshell:0001", markers=None,
                 severity="MEDIUM"):
    """Leg B of #538: a behavior finding on a command bash ran."""
    return aegis.finding(
        severity, "behavior", "Suspicious process behavior",
        "bash triggered [eval-subshell]", fp,
        program="/bin/bash", pid="28973",
        markers=markers or ["eval-subshell"])


class ChainMixin(object):

    def chains(self, prefix="chain:"):
        return [i for i in aegis.list_incidents()
                if i["correlation_key"].startswith(prefix)]

    def payload(self):
        return os.path.join(self.hot, "payload.sh")

    def persistence_leg(self, severity="HIGH", custody=None, fp="fp-pers",
                        **extra):
        return aegis.finding(
            severity, "persistence", "New persistence item", "d", fp,
            path=os.path.join(self.pers, "com.x.payload.plist"),
            program=self.payload(), custody=custody, **extra)

    def process_leg(self, severity="HIGH", custody=None, fp="fp-proc",
                    **extra):
        return aegis.finding(
            severity, "process", "Suspicious running process", "d", fp,
            path=self.payload(), custody=custody, **extra)


# --------------------------------------------------------------------------- #
# Rule 1 -- an interpreter is never the shared entity of a chain
# --------------------------------------------------------------------------- #


class AnInterpreterIsNeverTheSharedEntity(ChainMixin, Sandbox):

    def test_the_538_pair_does_not_chain(self):
        aegis.record_security_state([_os_update_leg(), _harness_leg()],
                                    now=T0)
        got = [i["correlation_key"] for i in self.chains()]
        # BEFORE: ['chain:persistence-execution:b1fd29aea4dad2af'], MEDIUM.
        self.assertEqual(got, [], "an OS update chained to a harness command "
                                  "on /bin/bash: %r" % got)

    def test_the_538_pair_does_not_chain_across_scans(self):
        """The live legs arrived minutes apart, well inside the 900 s window."""
        aegis.record_security_state([_os_update_leg()], now=T0 - 385)
        aegis.record_security_state([_harness_leg()], now=T0)
        self.assertEqual(self.chains(), [])

    def test_an_attack_defined_rule_does_not_join_on_it_either(self):
        """#517: `chain:clickfix` on the same hash. The rule is attack-defined,
        but the join was still a coincidence of interpreter: the OS update is
        not the persistence a fetch-exec installed."""
        aegis.record_security_state([
            _os_update_leg(),
            _harness_leg(markers=["fileless-fetch-exec"], severity="HIGH")],
            now=T0)
        self.assertEqual(self.chains("chain:clickfix"), [])

    def test_an_interpreter_primary_joins_nothing_from_either_side(self):
        a, b = _os_update_leg(), _harness_leg()
        self.assertIsNone(aegis._shared_entity(a, b))
        self.assertIsNone(aegis._shared_entity(b, a))
        self.assertFalse(aegis._same_entity(a, b))

    def test_every_interpreter_is_excluded_not_only_bash(self):
        for program in ("/usr/bin/python3", "/usr/bin/osascript",
                        "/usr/bin/env", "/opt/homebrew/bin/node"):
            with self.subTest(program=program):
                a = {"path": program, "program": program}
                b = {"program": program, "pid": "1"}
                self.assertIsNone(aegis._shared_entity(a, b))

    def test_the_payload_behind_an_interpreter_still_joins(self):
        """The join looks PAST the interpreter, it does not stop at it: the
        script an interpreter runs is carried as `script_target`, and that is
        the entity another sensor reports."""
        payload = self.payload()
        a = {"program": "/bin/bash", "script_target": payload}
        b = {"path": payload}
        self.assertEqual(aegis._shared_entity(a, b), payload)
        self.assertEqual(aegis._shared_entity(b, a), payload)

    def test_the_value_is_returned_as_the_finding_reported_it(self):
        """The contract correlate() keys on: the reported form, not the
        comparison form."""
        reported = os.path.join(self.hot, ".", "x")
        self.assertEqual(
            aegis._shared_entity({"path": reported},
                                 {"path": os.path.join(self.hot, "x")}),
            reported)

    def test_entity_and_entities_are_unchanged(self):
        """Display, dedup, incident identity and path lineage read these, and
        none of them is a chain join."""
        f = _os_update_leg()
        self.assertEqual(aegis._entity(f), "/bin/bash")
        self.assertEqual(aegis._entities(f), ["/bin/bash"])


# --------------------------------------------------------------------------- #
# Recall -- a chain on a real payload fires exactly as it did
# --------------------------------------------------------------------------- #


class TheOrdinaryChainStillFires(ChainMixin, Sandbox):

    def test_unexplained_persistence_plus_execution_is_critical(self):
        aegis.record_security_state([self.persistence_leg(),
                                     self.process_leg()], now=T0)
        chains = self.chains("chain:persistence-execution")
        self.assertEqual(len(chains), 1, chains)
        self.assertEqual(chains[0]["severity"], "CRITICAL")
        self.assertEqual(
            chains[0]["correlation_key"],
            "chain:persistence-execution:%s" % _entity_hash(self.payload()))


# --------------------------------------------------------------------------- #
# Rule 2 -- an explained finding cannot trigger a chain
# --------------------------------------------------------------------------- #


class AnExplainedFindingCannotTrigger(ChainMixin, Sandbox):

    def test_the_only_new_leg_being_explained_raises_no_chain(self):
        """The execution was already on record; the one new thing is a
        persistence item custody proved the operator committed."""
        aegis.record_security_state([self.process_leg()], now=T0 - 60)
        aegis.record_security_state(
            [self.persistence_leg("LOW", custody="self-committed")], now=T0)
        self.assertEqual(self.chains(), [])

    def test_two_explained_legs_do_not_chain(self):
        for rung in ("self-committed", "operator-vouched", "fleet-signed",
                     "package-managed", "publisher-stable", "os-vendor"):
            with self.subTest(rung=rung):
                self._reset()
                aegis.record_security_state([
                    self.persistence_leg("LOW", custody=rung),
                    self.process_leg("MEDIUM", custody=rung)], now=T0)
                self.assertEqual(self.chains(), [])

    def test_an_attack_defined_leg_is_never_excluded(self):
        """The other-leg rule: an attack-defined execution triggers, and the
        explained persistence item is its other leg. Custody on the hostile
        leg itself changes nothing -- origin is not innocence."""
        aegis.record_security_state([
            self.persistence_leg("LOW", custody="self-committed"),
            self.process_leg("HIGH", custody="self-committed",
                             attack_defined=True)], now=T0)
        chains = self.chains("chain:persistence-execution")
        self.assertEqual(len(chains), 1, chains)
        self.assertEqual(chains[0]["severity"], "CRITICAL")

    def test_an_unexplained_leg_still_triggers_with_an_explained_other_leg(self):
        """The same shape tolerated and allowlisted events already have: they
        leave the trigger set, never `observations`. A new execution custody
        cannot explain still chains against the explained persistence item --
        at one step above its weaker leg, which is LOW."""
        aegis.record_security_state([
            self.persistence_leg("LOW", custody="self-committed"),
            self.process_leg("HIGH")], now=T0)
        chains = self.chains("chain:persistence-execution")
        self.assertEqual(len(chains), 1, chains)
        self.assertEqual(chains[0]["severity"], "MEDIUM")

    def test_a_weak_rung_still_triggers(self):
        """`build-output`, `worktree` and the other weak rungs demote one step
        and explain nothing; they stay in the trigger set."""
        aegis.record_security_state([
            self.persistence_leg("MEDIUM", custody="build-output"),
            self.process_leg("MEDIUM", custody="build-output")], now=T0)
        self.assertEqual(len(self.chains("chain:persistence-execution")), 1)

    def test_the_explained_test(self):
        explained = aegis._custody_explained
        self.assertTrue(explained({"custody": "self-committed"}))
        self.assertTrue(explained({"custody": "os-vendor"}))
        # The agent-surface diff spells the rung `provenance`.
        self.assertTrue(explained({"provenance": "self-attested"}))
        self.assertFalse(explained({"custody": "build-output"}))
        self.assertFalse(explained({"custody": None}))
        self.assertFalse(explained({}))
        self.assertFalse(explained({"custody": "self-committed",
                                    "attack_defined": True}))

    def test_the_severity_cap_needs_no_new_rule(self):
        """A LOW explained leg can still be the OTHER leg, so rule 2 does not
        make the cap moot -- _chain_severity already holds it: below HIGH on
        both legs, a co-occurrence chain is one step above the weaker leg.
        Only attack-defined evidence reaches CRITICAL from a LOW leg."""
        low = {"severity": "LOW", "custody": "os-vendor"}
        high = {"severity": "HIGH"}
        self.assertEqual(aegis._chain_severity([(low, high)]), "MEDIUM")
        self.assertEqual(aegis._chain_severity([(high, low)]), "MEDIUM")
        self.assertEqual(
            aegis._chain_severity([(low, dict(high, attack_defined=True))]),
            "CRITICAL")

    def _reset(self):
        try:
            os.remove(aegis.EVENT_DB)
        except OSError:
            pass
        aegis.init_event_store()


# --------------------------------------------------------------------------- #
# The exit -- #538-shaped chains already in the queue
# --------------------------------------------------------------------------- #


class TheMigrationRetiresUnjoinableChains(ChainMixin, Sandbox):

    def _legacy_chain(self, rule, entity, findings, now=T0):
        """Record `findings` as evidence and stand a chain on them, the way the
        pre-S3 correlator did -- the current one refuses to form it."""
        aegis.record_security_state(findings, now=now)
        db = aegis._event_connection()
        try:
            with db:
                ids = []
                for f in findings:
                    ids.extend(r[0] for r in db.execute(
                        "SELECT id FROM events WHERE json_extract(data_json,"
                        "'$.fingerprint')=?", (f["fingerprint"],)))
                return aegis._upsert_incident(
                    db, "chain:%s:%s" % (rule, _entity_hash(entity)),
                    "Persistence followed by execution", "MEDIUM",
                    "correlation", now, sorted(ids))
        finally:
            db.close()

    def _migrate(self, now=T0 + 1):
        db = aegis._event_connection()
        try:
            with db:
                return aegis._retire_unjoinable_chain_incidents(db, now)
        finally:
            db.close()

    def _row(self, incident_id):
        return aegis.incident_detail(incident_id)

    def test_a_chain_joined_on_an_interpreter_is_retired(self):
        inc = self._legacy_chain("persistence-execution", "/bin/bash",
                                 [_os_update_leg(), _harness_leg()])
        self.assertEqual("OPEN", self._row(inc)["status"])
        self.assertEqual(1, self._migrate())
        row = self._row(inc)
        self.assertEqual("FALSE_POSITIVE", row["status"])
        self.assertIn("superseded", row["resolution"])
        self.assertIn("interpreter (/bin/bash)", row["resolution"])
        self.assertIn("reopens on new evidence", row["resolution"])
        self.assertEqual(0, self._migrate(), "not idempotent")

    def test_a_chain_on_a_real_payload_is_left_standing(self):
        aegis.record_security_state([self.persistence_leg(),
                                     self.process_leg()], now=T0)
        chains = self.chains("chain:persistence-execution")
        self.assertEqual(len(chains), 1)
        self.assertEqual(0, self._migrate())
        self.assertEqual("OPEN", self._row(chains[0]["id"])["status"])

    def test_a_chain_whose_every_leg_is_explained_is_retired(self):
        inc = self._legacy_chain(
            "persistence-execution", self.payload(),
            [self.persistence_leg("LOW", custody="self-committed"),
             self.process_leg("MEDIUM", custody="package-managed")])
        self.assertEqual(1, self._migrate())
        row = self._row(inc)
        self.assertEqual("FALSE_POSITIVE", row["status"])
        self.assertIn("provenance-explained", row["resolution"])
        self.assertIn("reopens on new evidence", row["resolution"])

    def test_a_chain_with_one_unexplained_leg_is_left_standing(self):
        """The forward rule would still form it: the unexplained leg
        triggers, the explained one is its other leg."""
        inc = self._legacy_chain(
            "persistence-execution", self.payload(),
            [self.persistence_leg("LOW", custody="self-committed"),
             self.process_leg("HIGH")])
        self.assertEqual(0, self._migrate())
        self.assertEqual("OPEN", self._row(inc)["status"])

    def test_an_attack_defined_explained_leg_keeps_its_chain(self):
        inc = self._legacy_chain(
            "persistence-execution", self.payload(),
            [self.persistence_leg("LOW", custody="self-committed"),
             self.process_leg("HIGH", custody="self-committed",
                              attack_defined=True)])
        self.assertEqual(0, self._migrate())
        self.assertEqual("OPEN", self._row(inc)["status"])

    def test_this_scans_own_chain_is_out_of_scope(self):
        inc = self._legacy_chain("persistence-execution", "/bin/bash",
                                 [_os_update_leg(), _harness_leg()])
        self.assertEqual(0, self._migrate(now=T0))
        self.assertEqual("OPEN", self._row(inc)["status"])

    def test_a_retired_chain_does_not_re_form(self):
        self._legacy_chain("persistence-execution", "/bin/bash",
                           [_os_update_leg(), _harness_leg()])
        self._migrate()
        aegis.record_security_state(
            [_os_update_leg(fp="persistence:os-program-update:/bin/bash:sha2"),
             _harness_leg(fp="behavior:bash:eval-subshell:0002")],
            now=T0 + 120)
        self.assertEqual(self.chains(), [])

    def test_the_migration_is_registered_once(self):
        keys = [k for k, _fn, _log in aegis._STORE_MIGRATIONS]
        self.assertEqual(1, keys.count("chain_legs_20260923"))
        fn = dict((k, fn) for k, fn, _log in aegis._STORE_MIGRATIONS)[
            "chain_legs_20260923"]
        self.assertIs(aegis._retire_unjoinable_chain_incidents, fn)

    def test_it_runs_inside_record_security_state(self):
        """The migration is stamped by the scan that first sees it, and a
        stamped store is never swept again."""
        aegis.record_security_state([], now=T0)
        db = aegis._event_connection()
        try:
            stamp = db.execute("SELECT value FROM meta WHERE key=?",
                               ("chain_legs_20260923",)).fetchone()
        finally:
            db.close()
        self.assertIsNotNone(stamp)
        self.assertEqual(str(T0), stamp[0])


if __name__ == "__main__":
    unittest.main()
