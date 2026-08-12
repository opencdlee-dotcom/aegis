#!/usr/bin/env python3
"""XProtect staleness must distinguish its two opposite diagnoses.

Corpus age alone conflates "the update path is broken — go fix Software
Update/MDM" with "the updater is alive and Apple has not shipped — nothing to
fix locally". The `xprotect version` Installed stamp is the updater's own
heartbeat and separates them; these tests pin its parsing (the branch that
consumes it is a plain if/else on the returned age).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

_REAL_OUTPUT = "Version: 5355 Installed: 2026-08-12 03:37:51 +0000"


class TestXprotectUpdaterAge(unittest.TestCase):
    def setUp(self):
        self._run = aegis.run

    def tearDown(self):
        aegis.run = self._run

    def test_parses_the_real_output_shape(self):
        aegis.run = lambda cmd, timeout=15, extra_env=None: (_REAL_OUTPUT, "", 0)
        age = aegis._xprotect_updater_age_days()
        self.assertIsNotNone(age)
        self.assertGreaterEqual(age, 0.0)

    def test_unavailable_cli_returns_none(self):
        # None -> the caller keeps the conservative MEDIUM "check Software
        # Update" diagnosis; absence of the heartbeat is never read as fresh.
        aegis.run = lambda cmd, timeout=15, extra_env=None: ("", "no such", 1)
        self.assertIsNone(aegis._xprotect_updater_age_days())

    def test_garbage_or_non_utc_output_returns_none(self):
        for out in ("Version: 5355", "Installed: yesterday",
                    "Installed: 2026-08-12 03:37:51 +0900"):
            aegis.run = lambda cmd, timeout=15, extra_env=None, o=out: (o, "", 0)
            self.assertIsNone(aegis._xprotect_updater_age_days(), out)


if __name__ == "__main__":
    unittest.main()
