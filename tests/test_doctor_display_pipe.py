"""Closed display pipes remain visible without claiming the monitor crashed."""
import contextlib
import io
import time

import aegis
from test_regression import Sandbox


class TestDisplayPipe(Sandbox):
    def _run_record(self, args, exc_type="BrokenPipeError", context=""):
        record = {"epoch": int(time.time()), "argv": ["aegis.py"] + args,
                  "exc_type": exc_type, "exc": "fixture", "context": context}
        aegis.save_json(aegis._crash_file(), record)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            aegis.cmd_doctor()
        self.assertEqual(aegis.read_crash(), record)
        return out.getvalue()

    def test_readonly_pipe_is_informational_and_preserved(self):
        text = self._run_record(["incident", "12"])
        line = next(l for l in text.splitlines() if "display output pipe closed" in l)
        self.assertTrue(line.strip().startswith("i"), line)
        self.assertNotIn("unhandled crash", text)
        self.assertIn("BrokenPipeError", text)

    def test_monitor_and_action_pipes_remain_faults(self):
        for args in (["scan"], ["watch"], [], ["incident", "12", "resolve"]):
            with self.subTest(args=args):
                text = self._run_record(args)
                line = next(l for l in text.splitlines() if "last unhandled crash" in l)
                self.assertTrue(line.strip().startswith("✗"), line)

    def test_context_or_generic_exception_remains_a_fault(self):
        for exc, context in (("ValueError", ""), ("BrokenPipeError", "scan")):
            with self.subTest(exc=exc, context=context):
                text = self._run_record(["incident", "12"], exc, context)
                line = next(l for l in text.splitlines() if "last unhandled crash" in l)
                self.assertTrue(line.strip().startswith("✗"), line)
