"""The 2026-09-06 false-alarm batch: nine open incidents, eight of them the
operator's own machine, and the ninth about to be filed as a lie.

Found live on the reference Mac. `aegis.py incidents` held nine rows and the
operator's verdict channel could not reach most of them. Measured against the
live findings ledger that day: of 2061 findings ever recorded, 761 (37%) were
in a category acquired tolerance may learn AND carried an identity it could
key on. The other 1300 were unreachable by ANY number of human verdicts —
795 blocked by the category gate alone, 207 by the identity gate alone, 298
by both. Triage was a treadmill by construction, which is why this was the
third false-alarm batch in three weeks.

Four defects, one per class, each pinned below.

  A. A STATE assertion was put through a lifecycle built for EVENTS.
     `hardening:macos:patchgap:26.0.1` — a real gap, 12 offered updates, the
     oldest 307 days old — sat 6.3 days into a 7-day age-out clock with its
     reminder ladder exhausted. In ~17 hours it would have been written
     FALSE_POSITIVE with the resolution "aged out: nothing new ... reopens on
     new evidence". That promise is unkeepable here: a signal incident embeds
     its fingerprint IN the correlation key, so a matched key always implies
     the same evidence, `_carries_new_evidence` is never true, and the
     reattach branch swallows every later observation. Aegis was about to
     permanently mute its one TRUE finding, and call it a false positive.

  B. A fix undone two lines below itself. `_first_sight_agent_config` lowers
     HIGH to MEDIUM unless `conceal` is present — written 2026-09-03 for
     exactly this problem — and then re-escalated on `_git_provenance` ==
     "remote-foreign". On the CHANGED path that predicate means "a pull
     DELIVERED this directive". On FIRST SIGHT it means "this file lives in a
     repo you cloned", which is the resting state of every vendored checkout
     on the machine. Two SKILL.md files sitting untouched in a third-party
     agent framework were HIGH incidents #353 and #354.

  C. macOS App Translocation minted a new identity per launch. Obsidian —
     Developer-ID signed, notarization stapled — was running from a read-only
     nullfs mount at .../AppTranslocation/<UUID>/d/ because it was launched
     off its DMG. The UUID is per-mount and contains no dotted-decimal run, so
     `_TOLERANCE_VERSION_RE` could not touch it: every identity derived from
     the path was orphaned on every relaunch, and the endpoint-class machinery
     that exists to absorb CDN rotation could never accumulate its verdicts.
     Incidents #359 and #361, one per endpoint, unbounded.

  D. Aegis detected its own test suite. `/tmp/aegis_rt_nr` is written by
     tests/test_regression.py as an ad-hoc-signed Mach-O; a live install on
     the developer's own machine watches /tmp as a hot dir and opened HIGH
     incident #358 on it. The file was already gone when the operator read the
     row. Fixed in test_regression.py by moving the fixtures into the per-run
     sandbox dir the base class already creates — the product grew no
     exclusion, because a hardcoded /tmp exemption is a path an attacker can
     squat. Pinned here so the fixtures cannot drift back.

Platform-independent by construction: findings built directly, recorded
through the real scan path.
"""
import inspect
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import aegis                                    # noqa: E402
from test_regression import Sandbox                           # noqa: E402

T0 = 1_700_000_000
STATE_FP = "hardening:macos:patchgap:26.0.1"
EVENT_FP = "behavior:bash:pipe-to-interpreter:ccf3a161d5d6"

# Shape-accurate, not this machine: the per-user temp segment is a real
# host fingerprint and this repo is public. Only the AppTranslocation
# UUID is under test; what precedes it is inert scaffolding.
TRANSLOCATED = ("/private/var/folders/ab/cd3fgh1jklmn0pqrs7uvwx0000gn/T/"
                "AppTranslocation/%s/d/Obsidian.app/Contents/Frameworks/"
                "Obsidian Helper.app/Contents/MacOS/Obsidian Helper")
UUID_A = "7B17F4CC-E1F8-496C-AB4B-0D02996A5CF8"
UUID_B = "0123ABCD-4567-89EF-0123-456789ABCDEF"


def _state_finding():
    return aegis.finding(
        "HIGH", "hardening", "macOS security updates are offered but not "
        "installed", "12 offered, oldest 307 days", STATE_FP)


def _event_finding():
    return aegis.finding("HIGH", "behavior", "Suspicious process behavior",
                         "curl | sh", EVENT_FP)


def _health(status="OK"):
    return [{"sensor_id": "hardening", "status": status, "detail": ""}]


def _row(fp):
    db = aegis._event_connection()
    try:
        r = db.execute("SELECT * FROM incidents WHERE correlation_key=?",
                       ("signal:" + fp,)).fetchone()
        return dict(r) if r else None
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# A — a persisting CONDITION is not an incident that ran out of news.
# --------------------------------------------------------------------------- #
class AStateAssertionIsNotAgedOut(Sandbox):
    def test_a_true_state_finding_survives_the_age_out_clock(self):
        aegis.record_security_state([_state_finding()], sensor_health=_health(),
                                    now=T0)
        self.assertEqual("OPEN", _row(STATE_FP)["status"])
        db = aegis._event_connection()
        try:
            with db:
                aegis._age_out_incidents(db, T0 + 30 * 86400)
        finally:
            db.close()
        # BEFORE THE FIX: FALSE_POSITIVE, "aged out: nothing new in 7d",
        # and then permanently unreopenable — the exposure outlives the alarm.
        self.assertEqual("OPEN", _row(STATE_FP)["status"],
                         "a still-true posture finding was filed as a false "
                         "positive for having nothing new to say")

    def test_an_event_finding_still_ages_out(self):
        """The exemption is for state, not a blanket age-out repeal."""
        aegis.record_security_state([_event_finding()], now=T0)
        db = aegis._event_connection()
        try:
            with db:
                aegis._age_out_incidents(db, T0 + 30 * 86400)
        finally:
            db.close()
        self.assertEqual("FALSE_POSITIVE", _row(EVENT_FP)["status"],
                         "the state exemption leaked onto ordinary events")


class AClearedConditionClosesItself(Sandbox):
    def test_the_sensor_looking_again_and_finding_nothing_resolves_it(self):
        aegis.record_security_state([_state_finding()], sensor_health=_health(),
                                    now=T0)
        self.assertEqual("OPEN", _row(STATE_FP)["status"])
        # The Mac got patched: the sensor runs, reports OK, emits nothing.
        aegis.record_security_state([], sensor_health=_health(), now=T0 + 3600)
        row = _row(STATE_FP)
        self.assertEqual("RESOLVED", row["status"],
                         "a condition that genuinely went away has no exit")
        self.assertIn("condition cleared", row["resolution"] or "",
                      "the closure does not say WHY: %r" % row["resolution"])

    def test_it_resolves_rather_than_filing_a_false_positive(self):
        """The finding was RIGHT. Filing a corrected posture as a
        misdetection would teach the precision ledger a lie."""
        aegis.record_security_state([_state_finding()], sensor_health=_health(),
                                    now=T0)
        aegis.record_security_state([], sensor_health=_health(), now=T0 + 3600)
        self.assertNotEqual("FALSE_POSITIVE", _row(STATE_FP)["status"])

    def test_a_sensor_that_did_not_answer_is_not_read_as_all_clear(self):
        """Absence of a finding is ambiguous. Reading a dead sensor as a
        cleared condition is how a monitor renders green while blind."""
        aegis.record_security_state([_state_finding()], sensor_health=_health(),
                                    now=T0)
        aegis.record_security_state([], sensor_health=_health("FAILED"),
                                    now=T0 + 3600)
        self.assertEqual("OPEN", _row(STATE_FP)["status"],
                         "a failed sensor silently closed a live exposure")

    def test_a_still_true_condition_stays_open(self):
        aegis.record_security_state([_state_finding()], sensor_health=_health(),
                                    now=T0)
        aegis.record_security_state([_state_finding()], sensor_health=_health(),
                                    now=T0 + 3600)
        self.assertEqual("OPEN", _row(STATE_FP)["status"])

    def test_no_dismissals_row_is_written(self):
        """A machine verdict must never feed backtest precision or acquired
        tolerance — the discipline age-out and re-grade already hold."""
        aegis.record_security_state([_state_finding()], sensor_health=_health(),
                                    now=T0)
        aegis.record_security_state([], sensor_health=_health(), now=T0 + 3600)
        db = aegis._event_connection()
        try:
            self.assertEqual(
                0, db.execute("SELECT COUNT(*) FROM dismissals").fetchone()[0])
        finally:
            db.close()


# --------------------------------------------------------------------------- #
# B — provenance may escalate a CHANGE, never the mere fact of a checkout.
# --------------------------------------------------------------------------- #
class BFirstSightDoesNotEscalateOnAVendoredCheckout(unittest.TestCase):
    def setUp(self):
        self._prov = aegis._git_provenance
        aegis._git_provenance = lambda path: "remote-foreign"

    def tearDown(self):
        aegis._git_provenance = self._prov

    def _sev(self, imperatives):
        out = aegis._first_sight_agent_config(
            "/Users/x/.hermes/hermes-agent/skills/dogfood/SKILL.md",
            {"imperatives": imperatives, "sha256": "a" * 64})
        rows = [f for f in out if "newfile-imperative" in f["fingerprint"]]
        return rows[0]["severity"] if rows else None

    def test_credential_plus_egress_at_rest_is_not_high(self):
        # BEFORE THE FIX: HIGH — the `conceal`-only rule was undone two lines
        # below itself by a predicate true of every vendored checkout.
        self.assertEqual("MEDIUM", self._sev(["credential", "egress"]),
                         "a file sitting untouched in a cloned repo is HIGH "
                         "purely for living in a cloned repo")

    def test_conceal_still_keeps_high_on_first_sight(self):
        """The one attack-defined marker with no benign reading is untouched."""
        self.assertEqual("HIGH", self._sev(["conceal"]))
        self.assertEqual("HIGH", self._sev(["conceal", "egress"]))

    def test_provenance_is_still_recorded_on_the_finding(self):
        """Quieter, not blinder: the operator still sees where it came from."""
        out = aegis._first_sight_agent_config(
            "/Users/x/.hermes/hermes-agent/skills/dogfood/SKILL.md",
            {"imperatives": ["credential", "egress"], "sha256": "a" * 64})
        row = [f for f in out if "newfile-imperative" in f["fingerprint"]][0]
        self.assertEqual("remote-foreign", row.get("provenance"))

    def test_the_changed_path_still_escalates_on_remote_foreign(self):
        """An imperative a PULL delivered is a real event against a reviewed
        baseline. Only the first-sight branch lost the escalation."""
        src = inspect.getsource(aegis.diff_agent_surface)
        self.assertIn('if prov == "remote-foreign"', src,
                      "the fix over-reached into the CHANGED branch")


# --------------------------------------------------------------------------- #
# C — one translocated app is one subject, not one per launch.
# --------------------------------------------------------------------------- #
class CAppTranslocationIsOneSubject(unittest.TestCase):
    def test_the_same_app_has_one_identity_across_relaunches(self):
        a = aegis._program_subject(TRANSLOCATED % UUID_A)
        b = aegis._program_subject(TRANSLOCATED % UUID_B)
        # BEFORE THE FIX: two unrelated subjects, so every verdict the
        # operator gave was orphaned by the next launch.
        self.assertEqual(a, b, "a relaunch minted a brand-new subject")
        self.assertNotIn(UUID_A, a)
        self.assertIn("AppTranslocation/#/", a)

    def test_endpoint_classes_survive_a_relaunch_so_verdicts_accumulate(self):
        """The rotating-endpoint layer already absorbs CDN churn; it was being
        defeated by the path churn underneath it."""
        ca = aegis._beacon_endpoint_classes(
            "beacon:%s:104.26.1.147:443" % aegis._program_subject(
                TRANSLOCATED % UUID_A))
        cb = aegis._beacon_endpoint_classes(
            "beacon:%s:185.199.111.133:443" % aegis._program_subject(
                TRANSLOCATED % UUID_B))
        self.assertTrue(ca and cb)
        self.assertEqual(ca[0][0], cb[0][0],
                         "two launches of one app could never reach the "
                         "verdict floor of a single endpoint class")
        self.assertNotEqual(ca[0][1], cb[0][1],
                            "the distinct ADDRESSES are still the evidence "
                            "rotation is established from")

    def test_an_ordinary_path_is_untouched(self):
        """The regex names one macOS mechanism, not any hex-shaped thing."""
        for path in ("/Applications/Obsidian.app/Contents/MacOS/Obsidian",
                     "/Users/x/7B17F4CC-E1F8-496C-AB4B-0D02996A5CF8/mal",
                     "/tmp/AppTranslocation/not-a-uuid/d/x"):
            self.assertEqual(path, aegis._program_subject(path),
                             "normalization reached a path it does not own")

    def test_a_translocated_attacker_binary_is_still_its_own_subject(self):
        """Collapsing the UUID must not collapse two different programs."""
        good = aegis._program_subject(TRANSLOCATED % UUID_A)
        evil = aegis._program_subject(
            (TRANSLOCATED % UUID_A).replace("Obsidian Helper", "Stealer"))
        self.assertNotEqual(good, evil)


# --------------------------------------------------------------------------- #
# D — the suite must not plant fixtures where the product will find them.
# --------------------------------------------------------------------------- #
class DTheSuiteDoesNotAlarmALiveInstall(unittest.TestCase):
    def test_no_fixture_is_written_to_a_shared_temp_path(self):
        """A live aegis watches /tmp as a hot dir. A fixture binary there is
        detected by the product under test — incident #358 was exactly this,
        and the file was gone before the operator could read the row."""
        here = os.path.dirname(os.path.abspath(__file__))
        # Only paths the suite CREATES matter. A hardcoded /tmp string that is
        # merely fixture data — a fake row handed to a parser, an allowlist
        # entry — never touches the filesystem and cannot be detected by
        # anything. The hazard is a real file at a shared, guessable path.
        # Scoped to the helpers that plant a real artifact a sensor can find
        # (a Mach-O, a plist, a directory). Deliberately NOT bare `open(`:
        # this suite carries fake malware COMMAND LINES as string data, and a
        # payload literal is not a file on disk.
        creates = re.compile(
            r'(?:adhoc_binary|write_plist|makedirs|mkdir)'
            r'\s*\(\s*["\'](?:/private)?/tmp/')
        bad = []
        for name in sorted(os.listdir(here)):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(here, name), encoding="utf-8") as fh:
                for n, line in enumerate(fh, 1):
                    if creates.search(line):
                        bad.append("%s:%d: %s" % (name, n, line.strip()))
        self.assertEqual([], bad,
                         "fixtures created at a shared, guessable path:\n  " +
                         "\n  ".join(bad))


if __name__ == "__main__":
    unittest.main()
