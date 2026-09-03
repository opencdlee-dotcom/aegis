#!/usr/bin/env python3
"""The verbs that BLIND the monitor are gated like the verbs that ACT.

`cmd_unlatch` has always stated the doctrine — "an authorization channel is
worth nothing if malware can just shell out to `aegis.py unlatch`" — and it was
only ever applied to the response tier. Everything that turns the monitor OFF
(`learn start`, `baseline`, `allow`, `canary remove`, `uninstall`,
`mark-uninstalled`, `intent record`) ran with no tty, no code and no dialog,
which is backwards: blinding is silent, self-blessing (each re-watermarks the
trust store it just rewrote) and strictly more valuable to an attacker running
as this same uid than any single destructive act.

Every gate is proved in BOTH directions, because a happy-path-only test proves
nothing here:
  · refuses with no tty — the malware case — AND the state it would have
    written is verified unchanged;
  · proceeds when authorization succeeds.

Plus the two rules that are deliberately NOT gates: `authorization_require_oob`
turns the tty-only fallback into a refusal, and the verdict that crosses the
acquired-tolerance floor is announced rather than gated.

Fully sandboxed: every ~/.aegis-derived global (STATE_DIR, RUN_LOG, EVENT_DB,
ACTION_LOG, the trust stores and the HMAC key) is redirected into a tmp dir.
"""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

NOW = 1786600000  # > 2026-01-01 store floor
PLIST = "/Library/LaunchAgents/com.vendor.updater.plist"

# Every module global that names a file inside the real ~/.aegis, discovered
# rather than listed: a hand-maintained list is exactly how the leak that made
# conftest's backstop necessary happened (two synthetic incidents found sitting
# in the developer's LIVE store months later). Discovery cannot go stale when
# somebody adds a new state file.
_REAL_STATE = aegis.STATE_DIR
_STATE_GLOBALS = tuple(sorted(
    n for n in dir(aegis)
    if isinstance(getattr(aegis, n), str)
    and getattr(aegis, n).startswith(_REAL_STATE + os.sep)))


class _Sandbox(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_blind_")
        self.state = os.path.join(self.tmp, ".aegis")
        os.makedirs(self.state)
        self._saved = {n: getattr(aegis, n)
                       for n in _STATE_GLOBALS + ("STATE_DIR",)}
        for n in _STATE_GLOBALS:
            setattr(aegis, n, os.path.join(
                self.state, os.path.relpath(self._saved[n], _REAL_STATE)))
        aegis.STATE_DIR = self.state
        # Named explicitly as well as swept, so a sweep that silently stopped
        # matching fails here instead of in the developer's real ~/.aegis.
        for n in ("RUN_LOG", "EVENT_DB", "ACTION_LOG", "BASELINE", "ALLOWLIST",
                  "SELFSTATE", "CANARY_STATE", "LATEST_JSON", "INTENT_FILE",
                  "AEGIS_CONFIG", "HMAC_KEY_FILE"):
            self.assertTrue(getattr(aegis, n).startswith(self.state + os.sep),
                            "%s was not sandboxed" % n)
        aegis.init_event_store()

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(aegis, n, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- helpers ----------------------------------------------------------- #

    def _cli(self, *args):
        """Run main() through the dispatcher with NO tty on either end — the
        automation case the gate exists to refuse. Returns (rc, stdout)."""
        buf = io.StringIO()
        saved_stdin = sys.stdin
        sys.stdin = io.StringIO("")          # isatty() False, and no code to type
        try:
            with contextlib.redirect_stdout(buf):
                rc = aegis.main(["aegis.py"] + [str(a) for a in args])
        finally:
            sys.stdin = saved_stdin
        return rc, buf.getvalue()

    @contextlib.contextmanager
    def _authorized(self, channel="gui-dialog"):
        """A human answered the out-of-band challenge correctly."""
        saved = aegis.authorize_interactive
        aegis.authorize_interactive = lambda purpose, target: (True, channel)
        try:
            yield
        finally:
            aegis.authorize_interactive = saved

    def _actions(self):
        try:
            with open(aegis.ACTION_LOG, encoding="utf-8") as f:
                return [json.loads(ln) for ln in f if ln.strip()]
        except OSError:
            return []

    def _blind_auth_records(self, verb):
        return [r for r in self._actions()
                if r.get("action") == "blind-auth" and r.get("verb") == verb]


# --------------------------------------------------------------------------- #
# C1 — the refusal direction. This is the whole point: a script with no tty is
# what an attacker running as this uid has, and each of these must leave the
# state it targets byte-unchanged.
# --------------------------------------------------------------------------- #

class TestBlindingVerbsRefuseWithoutTty(_Sandbox):

    def _assert_refused(self, verb, rc, out):
        self.assertEqual(1, rc)
        self.assertIn("interactive terminal", out)
        records = self._blind_auth_records(verb)
        self.assertTrue(records, "no blind-auth record for %s" % verb)
        self.assertEqual("refused", records[-1]["result"])
        self.assertEqual("refused-not-interactive", records[-1]["channel"])

    def test_learn_start_refused_and_learning_period_not_set(self):
        """`learn start 3650` is ten years of pre-closed non-CRITICAL findings,
        and _set_learning_period re-watermarks the baseline afterwards, so the
        self-protection check would bless its own blinding."""
        rc, out = self._cli("learn", "start", "3650")
        self._assert_refused("learn start", rc, out)
        self.assertEqual(0, aegis._learning_until())
        self.assertFalse(os.path.exists(aegis.BASELINE))

    def test_learn_extend_is_gated_too(self):
        """`extend` writes learning_until through the same call as `start`;
        gating one and not the other would be a gate in name only."""
        rc, out = self._cli("learn", "extend", "90")
        self._assert_refused("learn extend", rc, out)
        self.assertEqual(0, aegis._learning_until())

    def test_learn_status_and_done_are_not_gated(self):
        """Only the blinding direction is gated. `status` reads, and `done`
        RESTORES alerting — putting a dialog in front of either would be
        friction with no security content."""
        rc, out = self._cli("learn", "status")
        self.assertEqual(0, rc)
        self.assertNotIn("interactive terminal", out)
        rc, out = self._cli("learn", "done")
        self.assertEqual(0, rc)
        self.assertNotIn("interactive terminal", out)

    def test_unparseable_day_count_costs_no_dialog(self):
        """A request that blinds nothing must not train the operator that this
        verb prompts. `learn start abc` still just prints usage."""
        rc, out = self._cli("learn", "start", "abc")
        self.assertEqual(1, rc)
        self.assertIn("usage", out)
        self.assertEqual([], self._blind_auth_records("learn start"))

    def test_baseline_refused_and_nothing_adopted(self):
        """`baseline` re-adopts the CURRENT persistence set — the attacker's
        included — and clears any standing tamper accusation."""
        aegis.save_json(aegis.SELFSTATE, {"baseline_tamper_since": NOW})
        rc, out = self._cli("baseline")
        self._assert_refused("baseline", rc, out)
        self.assertFalse(os.path.exists(aegis.BASELINE))
        self.assertEqual(NOW, aegis.load_json(aegis.SELFSTATE, {})
                         .get("baseline_tamper_since"))

    def test_allow_refused_and_allowlist_unchanged(self):
        """The match is a SUBSTRING of the finding path, so `allow /`
        allowlists everything in the report with one character."""
        aegis.save_json(aegis.LATEST_JSON, {"findings": [
            {"fingerprint": "persistence:new:" + PLIST, "path": PLIST},
            {"fingerprint": "process:x:/usr/local/bin/x", "path":
             "/usr/local/bin/x"}]})
        rc, out = self._cli("allow", "/")
        self._assert_refused("allow", rc, out)
        self.assertEqual([], aegis.load_json(aegis.ALLOWLIST, []))
        self.assertFalse(os.path.exists(aegis.ALLOWLIST))

    def test_allow_that_matches_nothing_costs_no_dialog(self):
        aegis.save_json(aegis.LATEST_JSON, {"findings": []})
        rc, _out = self._cli("allow", "/nothing/matches/this")
        self.assertEqual(0, rc)
        self.assertEqual([], self._blind_auth_records("allow"))

    def test_canary_remove_refused_and_tripwire_still_armed(self):
        """The canary is the CRITICAL ransomware tripwire, and removing it
        re-watermarks, so the deletion would read as authorized."""
        decoy = os.path.join(self.tmp, "decoy.txt")
        with open(decoy, "w") as f:
            f.write("x")
        aegis.save_json(aegis.CANARY_STATE, {decoy: "deadbeef"})
        rc, out = self._cli("canary", "remove")
        self._assert_refused("canary remove", rc, out)
        self.assertTrue(os.path.exists(decoy))
        self.assertEqual({decoy: "deadbeef"},
                         aegis.load_json(aegis.CANARY_STATE, {}))

    def test_canary_plant_is_not_gated(self):
        """Planting ARMS a tripwire; only removal blinds. cmd_setup plants
        during its walkthrough and must never reach authorize_interactive."""
        saved = aegis.cmd_canary
        calls = []
        aegis.cmd_canary = lambda action="plant": calls.append(action) or 0
        try:
            rc, _out = self._cli("canary", "plant")
        finally:
            aegis.cmd_canary = saved
        self.assertEqual(0, rc)
        self.assertEqual(["plant"], calls)
        self.assertEqual([], self._blind_auth_records("canary remove"))

    def test_uninstall_refused_and_nothing_ran(self):
        """cmd_uninstall boots out the agent AND clears selfstate['installed'],
        which permanently disarms self:agent:removed."""
        aegis.save_json(aegis.SELFSTATE, {"installed": True})
        saved_run = aegis.run
        ran = []
        aegis.run = lambda argv, **kw: ran.append(argv) or ("", "", 0)
        try:
            rc, out = self._cli("uninstall")
        finally:
            aegis.run = saved_run
        self._assert_refused("uninstall", rc, out)
        self.assertEqual([], ran)
        self.assertIs(True, aegis.load_json(aegis.SELFSTATE, {}).get("installed"))

    def test_mark_uninstalled_refused_and_removal_alarm_stays_armed(self):
        """The disarm WITHOUT the uninstall: one command that silences
        self:agent:removed while the agent is still registered."""
        aegis.save_json(aegis.SELFSTATE, {"installed": True})
        rc, out = self._cli("mark-uninstalled")
        self._assert_refused("mark-uninstalled", rc, out)
        state = aegis.load_json(aegis.SELFSTATE, {})
        self.assertIs(True, state.get("installed"))
        self.assertNotIn("uninstalled_at", state)

    def test_intent_record_refused_and_no_custody_forged(self):
        """`intent record` mints a self-attested custody grade for ANY path,
        aegis.py itself included, which downgrades a payload swap."""
        victim = os.path.join(self.tmp, "payload.py")
        with open(victim, "w") as f:
            f.write("print('pwned')\n")
        rc, out = self._cli("intent", "record", victim)
        self._assert_refused("intent record", rc, out)
        self.assertFalse(os.path.exists(aegis.INTENT_FILE))

    def test_intent_hook_is_not_gated(self):
        """The editor hook is non-interactive BY CONSTRUCTION and only ever
        attests what the harness reports it just wrote; gating it would break
        every tool call and teach nothing."""
        victim = os.path.join(self.tmp, "written.py")
        with open(victim, "w") as f:
            f.write("x = 1\n")
        saved_stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps({"tool_input": {"file_path": victim}}))
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                rc = aegis.main(["aegis.py", "intent", "hook", "claude-code"])
        finally:
            sys.stdin = saved_stdin
        self.assertEqual(0, rc)
        self.assertEqual([], self._blind_auth_records("intent record"))


# --------------------------------------------------------------------------- #
# C1 — the approval direction. A gate that also refuses the operator is a bug.
# --------------------------------------------------------------------------- #

class TestBlindingVerbsProceedWhenAuthorized(_Sandbox):

    def _assert_authorized(self, verb):
        records = self._blind_auth_records(verb)
        self.assertTrue(records, "no blind-auth record for %s" % verb)
        self.assertEqual("authorized", records[-1]["result"])
        self.assertEqual("gui-dialog", records[-1]["channel"])
        # The purpose must say what is being given up, not name the verb: the
        # operator reads it in a dialog with no other context.
        self.assertNotEqual(verb, records[-1].get("purpose"))
        self.assertGreater(len(records[-1].get("purpose") or ""), 20)

    def test_learn_start_proceeds(self):
        with self._authorized():
            rc, out = self._cli("learn", "start", "7")
        self.assertEqual(0, rc)
        self.assertIn("learning period active", out)
        self.assertGreater(aegis._learning_until(), 0)
        self._assert_authorized("learn start")

    def test_baseline_proceeds(self):
        called = []
        saved = aegis.cmd_baseline
        aegis.cmd_baseline = lambda trust="verified": called.append(trust) or 0
        try:
            with self._authorized():
                rc, _out = self._cli("baseline")
        finally:
            aegis.cmd_baseline = saved
        self.assertEqual(0, rc)
        self.assertEqual(["verified"], called)
        self._assert_authorized("baseline")

    def test_allow_proceeds(self):
        fp = "persistence:new:" + PLIST
        aegis.save_json(aegis.LATEST_JSON,
                        {"findings": [{"fingerprint": fp, "path": PLIST}]})
        with self._authorized():
            rc, out = self._cli("allow", PLIST)
        self.assertEqual(0, rc)
        self.assertIn("Allowlisted 1", out)
        self.assertEqual([fp], aegis.load_json(aegis.ALLOWLIST, []))
        self._assert_authorized("allow")

    def test_canary_remove_proceeds(self):
        decoy = os.path.join(self.tmp, "decoy.txt")
        with open(decoy, "w") as f:
            f.write("x")
        aegis.save_json(aegis.CANARY_STATE, {decoy: "deadbeef"})
        with self._authorized():
            rc, out = self._cli("canary", "remove")
        self.assertEqual(0, rc)
        self.assertIn("Removed 1 canary", out)
        self.assertFalse(os.path.exists(decoy))
        self._assert_authorized("canary remove")

    def test_uninstall_proceeds(self):
        called = []
        saved = aegis.cmd_uninstall
        aegis.cmd_uninstall = lambda: called.append(True) or 0
        try:
            with self._authorized():
                rc, _out = self._cli("uninstall")
        finally:
            aegis.cmd_uninstall = saved
        self.assertEqual(0, rc)
        self.assertEqual([True], called)
        self._assert_authorized("uninstall")

    def test_mark_uninstalled_proceeds(self):
        aegis.save_json(aegis.SELFSTATE, {"installed": True})
        with self._authorized():
            rc, _out = self._cli("mark-uninstalled")
        self.assertEqual(0, rc)
        state = aegis.load_json(aegis.SELFSTATE, {})
        self.assertIs(False, state.get("installed"))
        self._assert_authorized("mark-uninstalled")

    def test_intent_record_proceeds(self):
        victim = os.path.join(self.tmp, "mine.py")
        with open(victim, "w") as f:
            f.write("x = 1\n")
        with self._authorized():
            rc, out = self._cli("intent", "record", victim)
        self.assertEqual(0, rc)
        self.assertIn("recorded", out)
        self.assertTrue(os.path.exists(aegis.INTENT_FILE))
        self._assert_authorized("intent record")

    def test_unauditable_approval_is_refused(self):
        """log_action returning False means the approval could not be written
        down. Blinding that leaves no record is the failure the whole gate
        exists to prevent, so an approval that cannot be audited must not
        proceed — the same rule _authorize_response_cli already applies."""
        saved = aegis.log_action
        aegis.log_action = lambda *a, **k: False
        try:
            with self._authorized():
                rc, _out = self._cli("learn", "start", "7")
        finally:
            aegis.log_action = saved
        self.assertEqual(1, rc)
        self.assertEqual(0, aegis._learning_until())


# --------------------------------------------------------------------------- #
# C3 — the tty-only fallback becomes refusable.
# --------------------------------------------------------------------------- #

class _FakeTty(io.StringIO):
    def isatty(self):
        return True


class TestOobRefusalSetting(_Sandbox):

    @contextlib.contextmanager
    def _tty(self, typed):
        """Both ends a tty and a code typed back — a pty-wrapping parent looks
        exactly like this, which is the entire reason the channel matters."""
        saved = (sys.stdin, sys.stdout)
        sys.stdin, sys.stdout = _FakeTty(typed + "\n"), _FakeTty()
        try:
            yield sys.stdout
        finally:
            sys.stdin, sys.stdout = saved

    def _no_oob(self):
        saved = aegis._oob_challenge
        aegis._oob_challenge = lambda code, purpose, target: None
        self.addCleanup(lambda: setattr(aegis, "_oob_challenge", saved))

    def test_default_is_todays_permissive_fallback(self):
        """Nothing breaks by default: an absent setting still degrades to
        tty-only and records the weaker guarantee rather than claiming it."""
        self.assertFalse(aegis._require_oob_channel())
        self._no_oob()
        captured = {}

        def fake_input(prompt=""):
            return captured["code"]

        saved_input = aegis.input if hasattr(aegis, "input") else None
        import builtins
        saved_builtin = builtins.input
        with self._tty("") as out:
            builtins.input = fake_input
            try:
                # Read the code back out of what was printed to the "terminal".
                orig_challenge = aegis._oob_challenge

                def sniff(code, purpose, target):
                    captured["code"] = code
                    return None

                aegis._oob_challenge = sniff
                try:
                    ok, channel = aegis.authorize_interactive("test", "target")
                finally:
                    aegis._oob_challenge = orig_challenge
            finally:
                builtins.input = saved_builtin
        del saved_input
        self.assertTrue(ok)
        self.assertEqual("tty-only", channel)
        self.assertIn("tty-only", out.getvalue())

    def test_setting_turns_the_fallback_into_a_refusal(self):
        aegis.save_json(aegis.AEGIS_CONFIG,
                        {aegis._AUTH_REQUIRE_OOB_KEY: True})
        self.assertTrue(aegis._require_oob_channel())
        self._no_oob()
        with self._tty("123456") as out:
            ok, channel = aegis.authorize_interactive("test", "target")
        self.assertFalse(ok)
        self.assertEqual("refused-no-oob-channel", channel)
        self.assertIn("refuse", out.getvalue())

    def test_refusal_is_recorded_by_the_blinding_gate(self):
        aegis.save_json(aegis.AEGIS_CONFIG,
                        {aegis._AUTH_REQUIRE_OOB_KEY: True})
        self._no_oob()
        with self._tty("123456"):
            rc = aegis.main(["aegis.py", "learn", "start", "30"])
        self.assertEqual(1, rc)
        self.assertEqual(0, aegis._learning_until())
        records = self._blind_auth_records("learn start")
        self.assertEqual("refused-no-oob-channel", records[-1]["channel"])

    def test_a_gui_dialog_still_authorizes_with_the_setting_on(self):
        """The setting refuses a MISSING channel, not a working one."""
        aegis.save_json(aegis.AEGIS_CONFIG,
                        {aegis._AUTH_REQUIRE_OOB_KEY: True})
        saved = aegis._oob_challenge
        aegis._oob_challenge = lambda code, purpose, target: "gui-dialog"
        import builtins
        saved_input = builtins.input
        try:
            with self._tty(""):
                holder = {}

                def sniff(code, purpose, target):
                    holder["code"] = code
                    return "gui-dialog"

                aegis._oob_challenge = sniff
                builtins.input = lambda prompt="": holder["code"]
                ok, channel = aegis.authorize_interactive("test", "target")
        finally:
            aegis._oob_challenge = saved
            builtins.input = saved_input
        self.assertTrue(ok)
        self.assertEqual("gui-dialog", channel)

    def test_a_non_boolean_value_is_treated_as_absent(self):
        """A typo must not silently harden the gate — and, the direction that
        matters, must not silently weaken one the operator believes is on."""
        for value in ("true", "yes", 1, "1", [], {}):
            aegis.save_json(aegis.AEGIS_CONFIG,
                            {aegis._AUTH_REQUIRE_OOB_KEY: value})
            self.assertFalse(aegis._require_oob_channel(),
                             "%r must not read as enabled" % (value,))


# --------------------------------------------------------------------------- #
# C2 — the verdict that crosses the tolerance floor is announced, not gated.
# --------------------------------------------------------------------------- #

def _finding(fp, severity="HIGH", category="persistence"):
    return {"fingerprint": fp, "severity": severity, "category": category,
            "title": "Persistence item CHANGED", "detail": "test",
            "confidence": "medium"}


class TestToleranceEscalationIsAnnounced(_Sandbox):

    def _ingest(self, f, at):
        db = aegis._event_connection()
        try:
            with db:
                cur = db.execute(
                    "INSERT INTO events(occurred_at,observed_at,source,"
                    "event_type,data_json) VALUES(?,?,?,?,?)",
                    (at, at, f["category"], "observation.finding",
                     json.dumps(f)))
                aegis._apply_correlations(db, [(cur.lastrowid, f)], at,
                                          initially_notified=True)
        finally:
            db.close()

    def _incident_for(self, fp):
        db = aegis._event_connection()
        try:
            row = db.execute(
                "SELECT id FROM incidents WHERE correlation_key=? "
                "ORDER BY id DESC LIMIT 1", ("signal:" + fp,)).fetchone()
            return row["id"] if row else None
        finally:
            db.close()

    def _verdict(self, i):
        """The i-th distinct hash-churned observation of one identity, dismissed
        benign-positive through the real CLI verb."""
        fp = "persistence:changed:%s:%016x" % (PLIST, i)
        self._ingest(_finding(fp), NOW + i * 60)
        incident_id = self._incident_for(fp)
        self.assertIsNotNone(incident_id)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = aegis.cmd_incident(incident_id, "benign-positive")
        self.assertEqual(0, rc)
        return buf.getvalue()

    def test_crossing_the_floor_is_announced_and_recorded(self):
        """Three benign-positive verdicts on one identity permanently
        auto-close that identity class. Acquiring that much blindness one
        ordinary keystroke at a time must not be the silent case."""
        self.assertEqual(3, aegis._TOLERANCE_MIN_VERDICTS)
        for i in range(aegis._TOLERANCE_MIN_VERDICTS - 1):
            out = self._verdict(i)
            self.assertNotIn("TOLERANCE GRANTED", out)
        out = self._verdict(aegis._TOLERANCE_MIN_VERDICTS - 1)
        self.assertIn("TOLERANCE GRANTED", out)
        self.assertIn("open PRE-CLOSED", out)
        self.assertIn("reopen", out)
        granted = [r for r in self._actions()
                   if r.get("action") == "tolerance-granted"]
        self.assertEqual(1, len(granted))
        self.assertEqual(3, granted[0]["verdicts"])
        self.assertEqual(180, granted[0]["window_days"])
        self.assertIn(PLIST, granted[0]["target"])

    def test_the_verdict_itself_is_never_gated(self):
        """A dialog in front of the routine daily verdict would only train the
        operator to click through the dialogs that matter."""
        for i in range(aegis._TOLERANCE_MIN_VERDICTS):
            self._verdict(i)
        self.assertEqual([], [r for r in self._actions()
                              if r.get("action") == "blind-auth"])

    def test_later_verdicts_do_not_repeat_the_announcement(self):
        """The escalation already happened; repeating it every verdict is the
        noise this file spends its time removing.

        After the floor is crossed the identity is tolerated, so the NEXT
        observation of it never reaches the operator as an open incident at
        all -- it arrives PRE-CLOSED, which is the whole point of the grant.
        Asserting that directly is stronger than asserting the absence of a
        banner on a verdict that can no longer be given: `benign-positive` on
        an already-closed incident is refused by the transition table, and a
        helper that hid that refusal behind assertEqual(0, rc) would be
        testing its own mock rather than the product."""
        for i in range(aegis._TOLERANCE_MIN_VERDICTS):
            self._verdict(i)

        fp = "persistence:changed:%s:%016x" % (PLIST,
                                               aegis._TOLERANCE_MIN_VERDICTS)
        self._ingest(_finding(fp),
                     NOW + aegis._TOLERANCE_MIN_VERDICTS * 60)
        incident_id = self._incident_for(fp)
        self.assertIsNotNone(incident_id, "the observation is still recorded")

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = aegis.cmd_incident(incident_id, "benign-positive")
        self.assertEqual(1, rc, "a pre-closed incident cannot be re-dismissed")
        self.assertNotIn("TOLERANCE GRANTED", buf.getvalue())

        granted = [r for r in self._actions()
                   if r.get("action") == "tolerance-granted"]
        self.assertEqual(1, len(granted), "granted once, announced once")

    def test_a_false_positive_verdict_never_escalates(self):
        """Only benign-positive verdicts teach tolerance; false-positive means
        the RULE was wrong and feeds the tuning queue instead."""
        for i in range(aegis._TOLERANCE_MIN_VERDICTS):
            fp = "persistence:changed:%s:%016x" % (PLIST, i)
            self._ingest(_finding(fp), NOW + i * 60)
            with contextlib.redirect_stdout(io.StringIO()):
                aegis.cmd_incident(self._incident_for(fp), "false-positive")
        self.assertEqual([], [r for r in self._actions()
                              if r.get("action") == "tolerance-granted"])

    def test_the_threshold_itself_is_unchanged(self):
        """This tier makes the escalation visible; it does not move the bar."""
        self.assertEqual(3, aegis._TOLERANCE_MIN_VERDICTS)
        self.assertEqual(180 * 86400, aegis._TOLERANCE_WINDOW)


if __name__ == "__main__":
    unittest.main()
