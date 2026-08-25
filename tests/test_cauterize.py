"""`cauterize` — the recovery plan — had zero test invocations: only two
setUp blocks redirected CAUTERIZE_FILE, and nothing ever called the command.
By this repo's own doctrine ("a row that cannot fail is not coverage") that
made it the one response verb that could break silently. These drive it.
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


class CauterizeSandbox(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_caut_")
        self.state = os.path.join(self.tmp, ".aegis")
        os.makedirs(self.state)
        self._saved = {}
        for k, v in {
            "STATE_DIR": self.state,
            "ACTION_LOG": os.path.join(self.state, "actions.jsonl"),
            "CAUTERIZE_FILE": os.path.join(self.state, "cauterize.json"),
            "EVENT_DB": os.path.join(self.state, "events.db"),
        }.items():
            self._saved[k] = getattr(aegis, k)
            setattr(aegis, k, v)
        self._saved_present = aegis._credential_surface_present
        # One real stat so ages render; the plan never opens the file.
        probe = os.path.join(self.tmp, "cookies.sqlite")
        with open(probe, "w") as f:
            f.write("x")
        self.st = os.stat(probe)
        self.present = []
        aegis._credential_surface_present = lambda: list(self.present)

    def tearDown(self):
        aegis._credential_surface_present = self._saved_present
        for k, v in self._saved.items():
            setattr(aegis, k, v)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cmd(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = aegis.cmd_cauterize(*args)
        return rc, out.getvalue()

    def _artifacts(self):
        home = os.path.expanduser("~")
        return [
            (os.path.join(home, "Library/Cookies/c1"), "Browser sessions", 1,
             "Sign out everywhere, then rotate passwords", self.st),
            (os.path.join(home, "Library/Cookies/c2"), "Browser sessions", 1,
             "Sign out everywhere, then rotate passwords", self.st),
            (os.path.join(home, ".ssh/id_ed25519"), "SSH keys", 2,
             "Revoke the public key everywhere it is authorized", self.st),
        ]


class TestCauterizeProgress(CauterizeSandbox):
    def test_done_marks_a_step_and_reset_clears_it(self):
        rc, out = self.run_cmd("done", "2")
        self.assertEqual(rc, 0)
        self.assertIn("Step 2 marked done", out)
        self.assertEqual(aegis.load_json(aegis.CAUTERIZE_FILE, {}).keys(),
                         {"2"})
        rc, _out = self.run_cmd("reset")
        self.assertEqual(rc, 0)
        self.assertEqual(aegis.load_json(aegis.CAUTERIZE_FILE, {}), {})

    def test_done_without_a_numeric_step_is_a_usage_error(self):
        for bad in (None, "", "two"):
            rc, out = self.run_cmd("done", bad)
            self.assertEqual(rc, 1, repr(bad))
            self.assertIn("usage", out)
        self.assertFalse(os.path.exists(aegis.CAUTERIZE_FILE))

    def test_progress_is_audited(self):
        self.run_cmd("done", "1")
        with open(aegis.ACTION_LOG, encoding="utf-8") as f:
            rows = [json.loads(line) for line in f if line.strip()]
        self.assertTrue(any(r.get("action") == "cauterize" and
                            r.get("target") == "step-1" for r in rows))


class TestCauterizePlan(CauterizeSandbox):
    def test_no_artifacts_is_a_clean_exit_not_an_empty_plan(self):
        rc, out = self.run_cmd()
        self.assertEqual(rc, 0)
        self.assertIn("No known credential artifacts", out)
        self.assertNotIn("revocation plan", out)

    def test_plan_groups_by_service_and_orders_by_rank(self):
        """A real Chrome install has ~20 profiles; one row per artifact
        printed the same sentence twenty times. The ACTION is per service."""
        self.present = self._artifacts()
        rc, out = self.run_cmd()
        self.assertEqual(rc, 0)
        self.assertIn("revocation plan", out)
        self.assertEqual(out.count("Browser sessions"), 1)
        self.assertIn("(+1 more)", out)
        self.assertLess(out.index("Browser sessions"), out.index("SSH keys"))
        self.assertIn("3 artifacts, 2 steps", out)
        self.assertIn("[ ]  1. Browser sessions", out)
        self.assertIn("[ ]  2. SSH keys", out)

    def test_completed_steps_are_ticked(self):
        self.present = self._artifacts()
        self.run_cmd("done", "1")
        _rc, out = self.run_cmd()
        self.assertIn("[x]  1. Browser sessions", out)
        self.assertIn("[ ]  2. SSH keys", out)

    def test_incident_narrowing_flags_the_artifacts_it_touched(self):
        self.present = self._artifacts()
        db = aegis._event_connection()          # the real schema, in the sandbox
        with db:
            db.execute(
                "INSERT INTO incidents(id,kind,correlation_key,title,severity,"
                "status,created_at,first_seen,last_seen,updated_at) "
                "VALUES(7,'signal','signal:x','x','HIGH','OPEN',1,1,1,1)")
            db.execute(
                "INSERT INTO events(occurred_at,observed_at,source,event_type,"
                "incident_id,data_json) VALUES(?,?,?,?,?,?)",
                (1, 1, "test", "observation.finding", 7,
                 json.dumps({"path": self._artifacts()[2][0]})))
        db.close()
        _rc, out = self.run_cmd("7")
        self.assertIn("narrowed to incident 7 (1 evidence paths)", out)
        touched = [line for line in out.splitlines()
                   if "TOUCHED BY THIS INCIDENT" in line]
        self.assertEqual(len(touched), 1)
        self.assertIn("SSH keys", touched[0])
        self.assertNotIn("Browser sessions", touched[0])

    def test_unknown_incident_still_prints_a_plan(self):
        self.present = self._artifacts()
        rc, out = self.run_cmd("999")
        self.assertEqual(rc, 0)
        self.assertIn("(0 evidence paths)", out)
        self.assertIn("2 steps", out)


if __name__ == "__main__":
    unittest.main()
