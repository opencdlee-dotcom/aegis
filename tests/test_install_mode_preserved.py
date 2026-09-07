#!/usr/bin/env python3
"""A routine `install` silently downgraded the monitor it was refreshing.

`install` with no positional argument is the documented way to refresh the
runtime copy after editing aegis.py -- CLAUDE.md says to re-run it after every
source edit, and every paste-ready line in this project's history says exactly
`aegis.py install`. main() hard-coded `mode = "scan"` for that form, so each
refresh replaced a watch-mode install (KeepAlive, a resident process, a 600s
beat) with a StartInterval timer at 3600s, without saying so.

The project already knew this hazard: `_refresh_line()` exists specifically to
"preserve the recorded install mode, so pasting it never silently downgrades a
watch-mode install to scan mode". That defence covered the line printed by
`update-check` and could not cover the line an operator actually types.

Measured on the reference machine: watch/600 through 2026-09-04T08:57, then
five bare `install` refreshes, and by 2026-09-05T21:44 the record read
scan/3600. What followed is the cost, stated only as far as it was actually
observed:

    scan mode   2026-09-05T21:46 -> 2026-09-06T10:14   748 min, ZERO scans
    watch mode  2026-09-06T10:35 -> 20:37              109 scans, median gap
                                                       1.8 min, worst 125 min

Both windows are the same laptop cycling sleep/DarkWake on battery, so the
comparison is like-for-like. WHY launchd ran the StartInterval job 0 times
across that window was NOT established -- the job was loaded, its last exit
was 0, and `runs` was still 1 twenty-seven minutes after a full wake, but
that is where the evidence stops. `ProcessType Background` deferral is a
guess and is recorded here as one. The fix does not rest on it: KeepAlive
holds a process rather than arming a timer, and 109 scans against 0 is the
whole argument.

Note what the watch-mode column does NOT claim: a 125-minute worst gap is
70% of HEARTBEAT_STALE_SECS, so a long enough sleep still ages the beat past
tolerance and still trips `watchdog`. Watch mode makes the monitor RESUME
promptly; it does not make a sleeping laptop monitored.

Also pinned here: cmd_install never wrote `install_interval`, though
_expected_scan_gap()'s docstring promises "`install_interval` is read when
present so a custom interval is respected rather than assumed away". Nothing
wrote it, so a custom interval was always assumed away -- a reader with no
writer, which is the same shape as the state-vs-events batch.
"""
import contextlib
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling import
import aegis  # noqa: E402
from test_regression import Sandbox  # noqa: E402


class InstallModeIsPreserved(Sandbox):
    """The scheduler is never touched: all three platform installers are
    stubbed, so this exercises cmd_install's own bookkeeping on any body."""

    def setUp(self):
        super(InstallModeIsPreserved, self).setUp()
        self.installed = []
        for name in ("_install_mac", "_install_linux", "_install_windows"):
            self._saved.setdefault(name, getattr(aegis, name))
            setattr(aegis, name, self._stub)

    def _stub(self, runtime, mode, interval):
        self.installed.append((mode, interval))
        return 0, "stubbed installer"

    def _install(self, *args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = aegis.cmd_install(*args)
        self.assertEqual(0, rc, buf.getvalue())
        return buf.getvalue()

    def _recorded(self):
        st = aegis.load_json(aegis.SELFSTATE, {})
        return st.get("install_mode"), st.get("install_interval")

    # -- mode ---------------------------------------------------------------
    def test_a_bare_refresh_keeps_the_installed_watch_mode(self):
        self._install("watch")
        self.assertEqual("watch", self._recorded()[0])
        out = self._install()               # the refresh an operator types
        self.assertEqual(
            "watch", self._recorded()[0],
            "a bare `install` downgraded a watch-mode monitor to scan mode")
        self.assertEqual("watch", self.installed[-1][0],
                         "the scheduler was re-registered in the wrong mode")
        self.assertIn("watch", out.lower(),
                      "inheriting a mode must be stated, not silent")

    def test_a_bare_refresh_keeps_scan_mode_too(self):
        self._install("scan")
        self._install()
        self.assertEqual("scan", self._recorded()[0])

    def test_an_explicit_mode_still_wins(self):
        """Preserving the record must not make a deliberate change impossible."""
        self._install("watch")
        self._install("scan")
        self.assertEqual("scan", self._recorded()[0])
        self._install("watch")
        self.assertEqual("watch", self._recorded()[0])

    def test_a_first_install_still_defaults_to_scan(self):
        self.assertEqual((None, None), self._recorded())
        self._install()
        self.assertEqual("scan", self._recorded()[0])

    # -- interval -----------------------------------------------------------
    def test_the_installed_interval_is_recorded(self):
        self._install("scan", 300)
        self.assertEqual(300, self._recorded()[1],
                         "cmd_install never wrote the field _expected_scan_gap "
                         "documents itself as reading")

    def test_a_custom_interval_is_respected_by_the_cadence_check(self):
        self._install("scan", 300)
        self.assertEqual((300, True), aegis._expected_scan_gap())

    def test_a_bare_refresh_keeps_the_custom_interval(self):
        self._install("watch", 120)
        self._install()
        self.assertEqual(("watch", 120), self._recorded())


class InstallCliParsesTheMode(unittest.TestCase):
    """main() must pass 'no mode given' through as such, and must accept an
    explicit `scan` so a deliberate downgrade is still expressible."""

    def setUp(self):
        self.calls = []
        self._real = aegis.cmd_install
        aegis.cmd_install = lambda mode=None, interval=None: (
            self.calls.append((mode, interval)) or 0)
        self.addCleanup(setattr, aegis, "cmd_install", self._real)

    def _main(self, *args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = aegis.main(["aegis.py", "install"] + list(args))
        return rc, buf.getvalue()

    def test_no_argument_means_inherit_not_scan(self):
        rc, _out = self._main()
        self.assertEqual(0, rc)
        self.assertEqual([(None, None)], self.calls)

    def test_watch_is_passed_through(self):
        self._main("watch")
        self.assertEqual([("watch", None)], self.calls)

    def test_scan_is_accepted_explicitly(self):
        rc, out = self._main("scan")
        self.assertEqual(0, rc, out)
        self.assertEqual([("scan", None)], self.calls)

    def test_an_interval_survives_each_form(self):
        self._main("watch", "120")
        self._main("scan", "300")
        self._main("900")
        self.assertEqual([("watch", 120), ("scan", 300), (None, 900)],
                         self.calls)


if __name__ == "__main__":
    unittest.main()
