#!/usr/bin/env python3
"""doctor's run.err check reported on the FILE, not on the JOB.

Found on the live install, not in a test: a healthy monitor -- heartbeat
fresh, a completed scan every ten minutes -- printed

    ✗ scheduled job stderr   ~/.aegis/run.err is not empty — the scheduled
                             job is writing to stderr

on the strength of a single stack trace written seven weeks earlier, under a
different interpreter, by a bug that no longer exists. The present tense was
the tell: the check never asked *when*, so the file's mere non-emptiness was
a permanent red verdict, and a line that can never go green is a line the
operator learns to skip.

The crash record ten lines above it in the same function already had the rule
(CRASH_FRESH_SECS -- "after a week it is history, not an open fault"). These
pin that the stderr tail now applies the same one: still shown, still
readable, but only counted against the verdict while it is current.
"""
import contextlib
import io
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling import
import aegis  # noqa: E402
from test_regression import Sandbox  # noqa: E402


class TestStderrFreshness(Sandbox):
    TRACE = "Traceback (most recent call last):\n  AttributeError: boom\n"

    def _write_err(self, age_seconds):
        _out, err = aegis._stdio_log_paths()
        with open(err, "w", encoding="utf-8") as f:
            f.write(self.TRACE)
        when = time.time() - age_seconds
        os.utime(err, (when, when))
        return err

    def _doctor(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            aegis.cmd_doctor()
        return out.getvalue()

    def _line(self, text):
        return [l for l in text.splitlines() if "scheduled job stderr" in l][0]

    def test_a_fresh_stderr_is_still_a_problem(self):
        """The signal this check exists for must survive the fix."""
        self._write_err(60)
        line = self._line(self._doctor())
        self.assertTrue(line.strip().startswith("✗"), line)
        self.assertIn("is writing to stderr", line)

    def test_a_months_old_stderr_is_history_not_an_open_fault(self):
        self._write_err(aegis.CRASH_FRESH_SECS + 86400)
        text = self._doctor()
        line = self._line(text)
        self.assertFalse(line.strip().startswith("✗"), line)
        self.assertIn("was writing to stderr", line)
        # Still printed: the operator must be able to read what happened.
        self.assertIn("AttributeError: boom", text)

    def test_the_line_always_says_when(self):
        """Not asking when was the whole defect, so the answer is now shown
        whichever side of the window the file falls on."""
        for age in (60, aegis.CRASH_FRESH_SECS + 86400):
            self._write_err(age)
            self.assertIn("last written", self._line(self._doctor()))

    def test_an_empty_stderr_says_nothing_at_all(self):
        _out, err = aegis._stdio_log_paths()
        with open(err, "w", encoding="utf-8") as f:
            f.write("")
        self.assertNotIn("scheduled job stderr", self._doctor())


if __name__ == "__main__":
    unittest.main()
