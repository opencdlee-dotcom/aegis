"""Auto-Protect tier (ROADMAP.md Phase 1, shadow stage) + operator intel
import (Phase 2 gap-fill).

What these tests hold:
  * evidence_class is a fingerprint-prefix decision — `xprotect:stale:` can
    never ride in on `xprotect:detect:`'s deterministic class.
  * shadow mode records the SAME decision live mode would execute (guards
    included), once per fingerprint, acting on nothing.
  * `intel import` merges the operator's own IOC file into the one intel
    store, and an imported hash grades to a CRITICAL, deterministic finding.
  * the scan pipeline actually calls the shadow hook (a rehearsal nothing
    schedules is a shelf ornament).
"""
import contextlib
import inspect
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis


def _det(fp, **extra):
    """A minimal real finding via the factory, so redaction/defaults apply."""
    return aegis.finding("HIGH", "test", "t", "d", fp, **extra)


class AutoprotectSandbox(unittest.TestCase):
    REBOUND = ("STATE_DIR", "AUTOPROTECT_FILE", "ACTION_LOG", "RUN_LOG",
               "INTEL_DIR", "INTEL_BAZAAR_FILE", "INTEL_THREATFOX_FILE",
               "INTEL_LOCAL_FILE")

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_ap_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.state = os.path.join(self.tmp, ".aegis")
        os.makedirs(self.state)
        self._saved = {}
        binds = {
            "STATE_DIR": self.state,
            "AUTOPROTECT_FILE": os.path.join(self.state, "autoprotect.json"),
            "ACTION_LOG": os.path.join(self.state, "actions.jsonl"),
            "RUN_LOG": os.path.join(self.state, "run.log"),
            "INTEL_DIR": os.path.join(self.state, "intel"),
            "INTEL_BAZAAR_FILE": os.path.join(self.state, "intel",
                                              "malwarebazaar.json"),
            "INTEL_THREATFOX_FILE": os.path.join(self.state, "intel",
                                                 "threatfox.json"),
            "INTEL_LOCAL_FILE": os.path.join(self.state, "intel",
                                             "local.json"),
        }
        for k in self.REBOUND:
            self._saved[k] = getattr(aegis, k)
            setattr(aegis, k, binds[k])
        self._saved_cache = aegis._INTEL_CACHE
        aegis._INTEL_CACHE = None

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(aegis, k, v)
        aegis._INTEL_CACHE = self._saved_cache

    def run_cmd(self, fn, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = fn(*args)
        return rc, out.getvalue()

    def actions(self, kind=None):
        try:
            with open(aegis.ACTION_LOG, encoding="utf-8") as fh:
                rows = [json.loads(l) for l in fh if l.strip()]
        except OSError:
            return []
        return [r for r in rows if kind is None or r.get("action") == kind]

    def ap_state(self):
        return aegis.load_json(aegis.AUTOPROTECT_FILE, {})


class TestEvidenceClass(unittest.TestCase):
    def test_deterministic_prefixes(self):
        for fp in ("decoy:read:/home/x/.aws/credentials.bak",
                   "latch:cleared:/Users/x/Library/LaunchAgents",
                   "xprotect:detect:MRTv3:removed:ab12",
                   "intel:hash:%s:/tmp/payload" % ("a" * 64),
                   "intel:net:1.2.3.4:443:/tmp/beacon"):
            self.assertEqual(aegis.evidence_class(_det(fp)), "deterministic",
                             fp)

    def test_neighbouring_fingerprints_stay_heuristic(self):
        for fp in ("xprotect:stale:v5000",       # freshness, not a verdict
                   "decoy:atime:/home/x/.npmrc.old",
                   "decoy:missing:/home/x/.npmrc.old",
                   "latch:unknown:/Users/x/Library/LaunchAgents",
                   "persistence:new:/x:abc",
                   "gatekeeper:deny:ab12"):
            self.assertEqual(aegis.evidence_class(_det(fp)), "heuristic", fp)

    def test_degenerate_inputs_are_heuristic(self):
        self.assertEqual(aegis.evidence_class({}), "heuristic")
        self.assertEqual(aegis.evidence_class(None), "heuristic")


class TestAutoprotectCmd(AutoprotectSandbox):
    def test_default_status_is_off_and_calm(self):
        rc, out = self.run_cmd(aegis.cmd_autoprotect)
        self.assertEqual(rc, 0)
        self.assertIn("mode: off", out)
        self.assertIn("acting", out.replace("\n", " "))

    def test_shadow_enable_is_audited_then_persisted(self):
        rc, out = self.run_cmd(aegis.cmd_autoprotect, "shadow")
        self.assertEqual(rc, 0)
        state = self.ap_state()
        self.assertEqual(state.get("mode"), "shadow")
        self.assertEqual(state.get("scans_in_shadow"), 0)
        rows = self.actions("autoprotect")
        self.assertEqual([(r["target"], r["result"]) for r in rows],
                         [("shadow", "enabled")])
        # 0600: the state file follows save_json's mode discipline. Windows
        # has no POSIX modes (chmod reports 0666 regardless), so the claim is
        # only checkable where the kernel can hold it.
        if os.name == "posix":
            self.assertEqual(os.stat(aegis.AUTOPROTECT_FILE).st_mode & 0o777,
                             0o600)

    def test_shadow_enable_is_idempotent(self):
        self.run_cmd(aegis.cmd_autoprotect, "shadow")
        rc, out = self.run_cmd(aegis.cmd_autoprotect, "shadow")
        self.assertEqual(rc, 0)
        self.assertIn("already", out)
        self.assertEqual(len(self.actions("autoprotect")), 1)

    def test_off_keeps_the_tally_for_review(self):
        self.run_cmd(aegis.cmd_autoprotect, "shadow")
        state = self.ap_state()
        state["tally"] = {"would-quarantine": 3}
        aegis.save_json(aegis.AUTOPROTECT_FILE, state)
        rc, _ = self.run_cmd(aegis.cmd_autoprotect, "off")
        self.assertEqual(rc, 0)
        state = self.ap_state()
        self.assertEqual(state.get("mode"), "off")
        self.assertEqual(state.get("tally"), {"would-quarantine": 3})

    def test_status_reports_exit_criteria_progress_then_met(self):
        self.run_cmd(aegis.cmd_autoprotect, "shadow")
        rc, out = self.run_cmd(aegis.cmd_autoprotect, "status")
        self.assertEqual(rc, 0)
        self.assertIn("shadow exit criteria:", out)
        self.assertNotIn("criteria MET", out)
        state = self.ap_state()
        state["since"] = aegis.datetime.fromtimestamp(
            time.time() - 8 * 86400).isoformat()
        aegis.save_json(aegis.AUTOPROTECT_FILE, state)
        rc, out = self.run_cmd(aegis.cmd_autoprotect, "status")
        self.assertIn("criteria MET", out)
        # The rehearsal never claims the live stage exists.
        self.assertIn("ships separately", out.replace("\n", " "))

    def test_unknown_action_prints_usage(self):
        rc, out = self.run_cmd(aegis.cmd_autoprotect, "live")
        self.assertEqual(rc, 1)
        self.assertIn("usage:", out)


class TestShadowHook(AutoprotectSandbox):
    def setUp(self):
        super().setUp()
        self._saved_refusal = aegis._freeze_refusal
        aegis._freeze_refusal = lambda pid, parents=None: None
        self.payload = os.path.join(self.tmp, "payload.bin")
        with open(self.payload, "w") as fh:
            fh.write("x")

    def tearDown(self):
        aegis._freeze_refusal = self._saved_refusal
        super().tearDown()

    def arm(self):
        self.run_cmd(aegis.cmd_autoprotect, "shadow")

    def test_off_mode_records_nothing(self):
        f = _det("intel:hash:%s:%s" % ("a" * 64, self.payload),
                 path=self.payload)
        self.assertEqual(aegis._autoprotect_shadow([f]), [])
        self.assertEqual(self.actions("autoprotect"), [])
        self.assertFalse(os.path.exists(aegis.AUTOPROTECT_FILE))

    def test_deterministic_path_would_quarantine_once(self):
        self.arm()
        f = _det("intel:hash:%s:%s" % ("a" * 64, self.payload),
                 path=self.payload)
        recorded = aegis._autoprotect_shadow([f])
        self.assertEqual(len(recorded), 1)
        rows = [r for r in self.actions("autoprotect")
                if r["result"] == "would-quarantine"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["target"], self.payload)
        self.assertEqual(rows[0]["evidence"], "deterministic")
        self.assertEqual(rows[0]["mode"], "shadow")
        # Same finding next scan: counted scans advance, the record does not.
        self.assertEqual(aegis._autoprotect_shadow([f]), [])
        state = self.ap_state()
        self.assertEqual(state["scans_in_shadow"], 2)
        self.assertEqual(state["tally"], {"would-quarantine": 1})

    def test_heuristic_process_would_freeze_with_live_guards(self):
        self.arm()
        f = _det("persistence:new:/x:abc", pid=os.getpid())
        aegis._autoprotect_shadow([f])
        rows = self.actions("autoprotect")
        self.assertEqual(rows[-1]["result"], "would-freeze")
        self.assertEqual(rows[-1]["evidence"], "heuristic")
        # The exact guard live mode would apply speaks in the record.
        aegis._freeze_refusal = lambda pid, parents=None: "other-user"
        f2 = _det("persistence:new:/y:def", pid=os.getpid())
        aegis._autoprotect_shadow([f2])
        rows = self.actions("autoprotect")
        self.assertEqual(rows[-1]["result"], "would-refuse")
        self.assertEqual(rows[-1]["reason"], "other-user")
        self.assertEqual(rows[-1]["verb"], "would-freeze")

    def test_decoy_read_targets_the_reader_not_the_honeytoken(self):
        self.arm()
        f = _det("decoy:read:%s" % self.payload, path=self.payload,
                 pid=os.getpid())
        aegis._autoprotect_shadow([f])
        rows = self.actions("autoprotect")
        self.assertEqual(rows[-1]["result"], "would-freeze")
        self.assertEqual(rows[-1]["target"], str(os.getpid()))

    def test_protected_path_would_refuse(self):
        # STATE_DIR's subtree is protected on EVERY platform (/etc is not a
        # protected tree on Windows), so the guard's verdict is portable.
        self.arm()
        inside = os.path.join(aegis.STATE_DIR, "planted.bin")
        f = _det("intel:hash:%s:%s" % ("b" * 64, inside), path=inside)
        aegis._autoprotect_shadow([f])
        rows = self.actions("autoprotect")
        self.assertEqual(rows[-1]["result"], "would-refuse")
        self.assertEqual(rows[-1]["reason"], "protected-path")

    def test_heuristic_file_and_subjectless_findings_are_skipped(self):
        self.arm()
        fs = [_det("persistence:new:/x:abc", path=self.payload),  # no pid
              _det("xprotect:detect:MRTv3:removed:ab12")]         # no subject
        self.assertEqual(aegis._autoprotect_shadow(fs), [])
        self.assertEqual([r for r in self.actions("autoprotect")
                          if r["result"] != "enabled"], [])

    def test_seen_ledger_is_bounded(self):
        self.arm()
        state = self.ap_state()
        state["seen"] = {"old:%d" % i: "2026-01-01T00:00:%02d" % (i % 60)
                        for i in range(aegis.AUTOPROTECT_SEEN_MAX)}
        aegis.save_json(aegis.AUTOPROTECT_FILE, state)
        f = _det("intel:hash:%s:%s" % ("c" * 64, self.payload),
                 path=self.payload)
        aegis._autoprotect_shadow([f])
        self.assertLessEqual(len(self.ap_state()["seen"]),
                             aegis.AUTOPROTECT_SEEN_MAX)

    def test_scan_pipeline_schedules_the_rehearsal(self):
        src = inspect.getsource(aegis._cmd_scan_locked)
        self.assertIn("_autoprotect_shadow(findings)", src)


class TestDispatcherWiring(AutoprotectSandbox):
    """cmd_* correctness is tested above; these hold the main() chain — the
    part a unit call bypasses — including the argv[3] pass-through `intel
    import` is the first intel action to need."""

    def _main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = aegis.main(["aegis.py"] + list(argv))
        return rc, out.getvalue()

    def test_main_routes_autoprotect_default_status(self):
        rc, out = self._main("autoprotect")
        self.assertEqual(rc, 0)
        self.assertIn("Auto-Protect", out)
        self.assertIn("mode: off", out)

    def test_main_passes_intel_import_argument(self):
        rc, out = self._main("intel", "import",
                             os.path.join(self.tmp, "absent.txt"))
        self.assertEqual(rc, 1)
        self.assertIn("cannot read", out)   # reached _cmd_intel_import
        rc, out = self._main("intel", "import")
        self.assertEqual(rc, 1)
        self.assertIn("usage", out)


class TestIntelImport(AutoprotectSandbox):
    SHA = "d" * 64

    def _import(self, text, name="iocs.txt"):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return self.run_cmd(aegis.cmd_intel, "import", path)

    def test_import_counts_and_persists(self):
        rc, out = self._import(
            "# my feed\n%s Emotet\n%s Emotet\nnot-a-hash\n1.2.3.4:443 C2\n"
            % (self.SHA, self.SHA))
        self.assertEqual(rc, 0)
        self.assertIn("2 added", out)         # the hash and the ip:port
        self.assertIn("1 duplicate", out)
        self.assertIn("1 invalid", out)
        doc = aegis.load_json(aegis.INTEL_LOCAL_FILE, {})
        self.assertEqual(doc["hashes"][self.SHA]["family"], "Emotet")
        self.assertIn("1.2.3.4:443", doc["net"])
        self.assertTrue(self.actions("intel"))

    def test_imported_hash_grades_deterministic_critical(self):
        self._import("%s Emotet\n" % self.SHA)
        aegis._INTEL_CACHE = None
        f = aegis._intel_hash_finding(self.SHA, "/tmp/payload", "a test")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertEqual(f["feed"], "Local")
        self.assertEqual(aegis.evidence_class(f), "deterministic")

    def test_operator_meta_wins_over_feed_meta(self):
        aegis.save_json(aegis.INTEL_THREATFOX_FILE, {
            "feed": "ThreatFox", "fetched_at": aegis.now_iso(),
            "hashes": {self.SHA: {"family": "feed-name"}}, "net": {}})
        self._import("%s operator-name\n" % self.SHA)
        aegis._INTEL_CACHE = None
        hashes, _ = aegis._intel_sets()
        self.assertEqual(hashes[self.SHA]["feed"], "Local")
        self.assertEqual(hashes[self.SHA]["family"], "operator-name")

    def test_status_and_summary_surface_local_intel(self):
        self._import("%s\n" % self.SHA)
        rc, out = self.run_cmd(aegis.cmd_intel, "status")
        self.assertEqual(rc, 0)
        self.assertIn("Local", out)
        aegis._INTEL_CACHE = None
        mark, text = aegis._intel_summary()
        self.assertEqual(mark, "✓")
        self.assertIn("operator-imported", text)

    def test_import_missing_file_fails_cleanly(self):
        rc, out = self.run_cmd(aegis.cmd_intel, "import",
                               os.path.join(self.tmp, "absent.txt"))
        self.assertEqual(rc, 1)
        self.assertIn("cannot read", out)

    def test_import_without_arg_prints_usage(self):
        rc, out = self.run_cmd(aegis.cmd_intel, "import", None)
        self.assertEqual(rc, 1)
        self.assertIn("usage", out)


if __name__ == "__main__":
    unittest.main()
