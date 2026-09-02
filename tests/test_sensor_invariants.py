"""The two operational invariants added 2026-09-02 (ARCHITECTURE.md):

  * every sensor reports health on EVERY scan, good or bad, so a dead sensor is
    visible in `doctor` rather than green-by-omission;
  * a benign read is never persisted.

The first is machine-checkable and this file is its roster. A sensor that is
registered in gather_all or the SURFACES registry without landing in the
persisted sensor_status table fails here, by name, on the scan that omits it.
The second is a retention rule the clipboard and paste-guard surfaces set; the
paste-guard tests hold its concrete assertion (a clean command line leaves no
row and no file).
"""
import inspect
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling import
import aegis  # noqa: E402
from test_regression import Sandbox  # noqa: E402

# Sensors gather_all schedules on every body.
PORTABLE = frozenset((
    "persistence.diff", "process", "behavior", "shell-history", "hot-dir",
    "staging", "supply-chain", "session-theft", "canary", "latch", "decoy",
    "assay", "outbound", "web-protection", "hardening", "self-protection",
    "vouch-store", "paste-guard",
))
PLATFORM = {
    "mac": frozenset(("cron", "xprotect", "security-log", "amfid-log")),
    "linux": frozenset(("cron", "auth-log")),
    "win": frozenset(("windows-event-log",)),
}
# Scheduled only when their substrate exists (an intel store, a Sysmon
# channel). Absent is the documented state, not DEGRADED, so they are
# recognised here without being required.
CONDITIONAL = frozenset(("intel",))
# Health rows _cmd_scan_locked writes by hand rather than via _collect_sensor.
DIRECT = frozenset(("persistence.snapshot", "agent-surface-coverage",
                    "process.enumerate", "process.argv", "signature.classify"))


def _body():
    return "win" if aegis.IS_WIN else ("linux" if aegis.IS_LINUX else "mac")


def _registered_in_gather_all():
    src = inspect.getsource(aegis.gather_all)
    return set(re.findall(r'^\s+\("([\w.-]+)",\s*(?:lambda|check_)', src,
                          re.M))


def _expected_ids():
    ids = set(PORTABLE) | PLATFORM[_body()] | DIRECT
    for row in aegis._build_surfaces(aegis.IS_MAC, aegis.IS_LINUX):
        ids.add("surface." + row[0])
    return ids


class TestRosterMatchesSource(unittest.TestCase):
    def test_every_gather_all_sensor_is_on_the_roster(self):
        known = PORTABLE | CONDITIONAL
        for ids in PLATFORM.values():
            known |= ids
        unknown = _registered_in_gather_all() - known
        self.assertEqual(set(), unknown,
                         "sensor(s) registered in gather_all but not in the "
                         "health roster: %s -- add them to PORTABLE/PLATFORM "
                         "(or CONDITIONAL, with the reason)" % sorted(unknown))

    def test_roster_does_not_name_ghosts(self):
        registered = _registered_in_gather_all()
        ghosts = (PORTABLE | PLATFORM[_body()]) - registered
        self.assertEqual(set(), ghosts,
                         "roster names sensor(s) gather_all no longer "
                         "schedules: %s" % sorted(ghosts))


class TestEverySensorReportsHealthEveryScan(Sandbox):
    def _health_ids(self):
        return {row["sensor_id"] for row in aegis.get_sensor_health()}

    def _health_event_counts(self):
        db = aegis._event_connection()
        try:
            rows = db.execute(
                "SELECT source, COUNT(*) AS n FROM events "
                "WHERE event_type='sensor.health' GROUP BY source").fetchall()
            return {r["source"]: r["n"] for r in rows}
        finally:
            db.close()

    def test_first_scan_persists_a_row_for_every_sensor(self):
        aegis.cmd_scan(quiet=True)
        missing = _expected_ids() - self._health_ids()
        self.assertEqual(set(), missing,
                         "sensor(s) ran a scan without a health row: %s"
                         % sorted(missing))

    def test_second_scan_re_reports_every_sensor(self):
        aegis.cmd_scan(quiet=True)
        aegis.cmd_scan(quiet=True)
        counts = self._health_event_counts()
        stale = sorted(s for s in _expected_ids() if counts.get(s, 0) < 2)
        self.assertEqual([], stale,
                         "sensor(s) reported health on one scan but not the "
                         "next -- the row would pin that scan's verdict as "
                         "current: %s" % stale)


if __name__ == "__main__":
    unittest.main()
