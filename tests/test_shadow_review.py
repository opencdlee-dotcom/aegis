#!/usr/bin/env python3
"""A shadow record the operator cannot judge is not evidence.

Until 2026-09-03 a would-action record carried only a verb and a fingerprint:

    {"action":"autoprotect","verb":"would-freeze",
     "fingerprint":"behavior:bash:eval-subshell:9be65e30bc6a346e"}

The operator is asked to review that log and decide whether to promote the
heuristic tier to live. It cannot answer the only question that matters --
"would this have hurt me?" On the reference machine every recorded
would-freeze turned out to be one of the operator's own tools, and nothing in
the record said so.

Two rules are pinned here: the record carries redacted IDENTITY, and reaching
the time threshold is reported as time served rather than as a promotion
signal, because Aegis cannot tell the operator's own shell from an attacker's
and must not pretend otherwise.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


class ShadowSandbox(unittest.TestCase):
    REBOUND = ("STATE_DIR", "RUN_LOG", "EVENT_DB", "ACTION_LOG",
               "AUTOPROTECT_FILE")

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis-shadow-")
        self.state = os.path.join(self.tmp, ".aegis")
        os.makedirs(self.state, mode=0o700)
        self._saved = {n: getattr(aegis, n) for n in self.REBOUND}
        aegis.STATE_DIR = self.state
        aegis.RUN_LOG = os.path.join(self.state, "run.log")
        aegis.EVENT_DB = os.path.join(self.state, "aegis.db")
        aegis.ACTION_LOG = os.path.join(self.state, "actions.jsonl")
        aegis.AUTOPROTECT_FILE = os.path.join(self.state, "autoprotect.json")

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(aegis, n, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _records(self):
        out = []
        if not os.path.exists(aegis.ACTION_LOG):
            return out
        with open(aegis.ACTION_LOG, encoding="utf-8") as fh:
            for line in fh:
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
        return out


def _finding(**kw):
    f = {"fingerprint": "behavior:bash:eval-subshell:abc123",
         "category": "behavior", "severity": "MEDIUM", "pid": 4242,
         "owner": "charlie", "executable": "/bin/bash",
         "detail": "bash triggered [eval-subshell]; command sha256=9be6",
         "markers": ["eval-subshell"]}
    f.update(kw)
    return f


class TestTheRecordCanBeJudged(ShadowSandbox):
    def test_identity_travels_with_the_would_action(self):
        aegis.save_json(aegis.AUTOPROTECT_FILE,
                        {"mode": "shadow", "since": aegis.now_iso(),
                         "seen": {}, "tally": {}})
        aegis._autoprotect_shadow([_finding()])
        rec = [r for r in self._records() if r.get("action") == "autoprotect"]
        self.assertEqual(1, len(rec), rec)
        r = rec[0]
        self.assertEqual("/bin/bash", r.get("exe"))
        self.assertEqual("charlie", r.get("owner"))
        self.assertEqual(4242, r.get("pid"))
        self.assertIn("eval-subshell", r.get("cmd_preview", ""))
        self.assertIn("eval-subshell", r.get("markers", []))

    def test_a_secret_in_the_subject_is_redacted_before_the_audit_log(self):
        """This lands in actions.jsonl. A shadow log that leaks a credential
        into the audit trail is a worse defect than the one it fixes."""
        secret = "AKIAIOSFODNN7EXAMPLE"
        aegis.save_json(aegis.AUTOPROTECT_FILE,
                        {"mode": "shadow", "since": aegis.now_iso(),
                         "seen": {}, "tally": {}})
        aegis._autoprotect_shadow([_finding(
            fingerprint="behavior:bash:eval-subshell:secret",
            detail="curl -H 'Authorization: Bearer %s' https://x" % secret)])
        blob = io.open(aegis.ACTION_LOG, encoding="utf-8").read()
        self.assertNotIn(secret, blob, "a secret reached actions.jsonl")

    def test_the_preview_is_capped(self):
        aegis.save_json(aegis.AUTOPROTECT_FILE,
                        {"mode": "shadow", "since": aegis.now_iso(),
                         "seen": {}, "tally": {}})
        aegis._autoprotect_shadow([_finding(detail="A" * 5000)])
        rec = [r for r in self._records() if r.get("action") == "autoprotect"]
        self.assertLessEqual(len(rec[0]["cmd_preview"]),
                             aegis._SHADOW_ARGV_PREVIEW)

    def test_a_finding_with_no_subject_still_records_cleanly(self):
        ident = aegis._shadow_identity({"fingerprint": "x"})
        self.assertEqual({}, ident)


class TestTheClockIsNotAPromotionSignal(ShadowSandbox):
    def _status(self, days_ago, scans):
        since = aegis.now_iso()
        aegis.save_json(aegis.AUTOPROTECT_FILE, {
            "mode": "shadow", "since": since, "seen": {},
            "tally": {"would-freeze": 3}, "scans_in_shadow": scans})
        # Age the record by rewriting `since` to a past ISO stamp.
        st = aegis.load_json(aegis.AUTOPROTECT_FILE, {})
        st["since"] = aegis.iso_from_epoch(
            int(aegis._epoch()) - int(days_ago * 86400)) \
            if hasattr(aegis, "iso_from_epoch") else since
        aegis.save_json(aegis.AUTOPROTECT_FILE, st)
        buf = io.StringIO()
        with redirect_stdout(buf):
            aegis.cmd_autoprotect("status")
        return buf.getvalue()

    def test_threshold_reached_never_reads_as_ready(self):
        out = self._status(days_ago=0, scans=99)
        self.assertIn("time served", out)
        self.assertNotIn("exit criteria MET", out)
        self.assertIn("NOT a promotion signal", out)
        self.assertIn("a tool you run yourself", out)

    def test_below_threshold_reports_progress_without_a_verdict(self):
        out = self._status(days_ago=0, scans=1)
        self.assertIn("time served", out)
        self.assertNotIn("exit criteria MET", out)

    def test_records_are_shown_not_just_counted(self):
        aegis.save_json(aegis.AUTOPROTECT_FILE,
                        {"mode": "shadow", "since": aegis.now_iso(),
                         "seen": {}, "tally": {}, "scans_in_shadow": 1})
        aegis._autoprotect_shadow([_finding()])
        buf = io.StringIO()
        with redirect_stdout(buf):
            aegis.cmd_autoprotect("status")
        out = buf.getvalue()
        self.assertIn("would-actions recorded", out)
        self.assertIn("/bin/bash", out)

    def test_no_records_says_so_rather_than_printing_an_empty_list(self):
        aegis.save_json(aegis.AUTOPROTECT_FILE,
                        {"mode": "shadow", "since": aegis.now_iso(),
                         "seen": {}, "tally": {}, "scans_in_shadow": 1})
        buf = io.StringIO()
        with redirect_stdout(buf):
            aegis.cmd_autoprotect("status")
        self.assertIn("no would-actions recorded yet", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
