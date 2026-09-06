"""The operational invariants of ARCHITECTURE.md that are machine-checkable:

  * every sensor reports health on EVERY scan, good or bad, so a dead sensor is
    visible in `doctor` rather than green-by-omission;
  * a benign read is never persisted;
  * a non-answer is never rendered as a verdict (added 2026-09-05): a sensor
    that found an item and could not examine it says so through the
    unexamined() ledger, never through a bare `continue` that reads as clean.

The first is machine-checkable and this file is its roster. The third is
checked against the SOURCE, by AST: every silent except handler in a sensor
function is either a whole-sensor non-answer (`return None`, which
_collect_sensor turns into DEGRADED), an absence (`FileNotFoundError`, which is
a real answer), on the ledger, or on the allowlist below with its reason. A sensor that is
registered in gather_all or the SURFACES registry without landing in the
persisted sensor_status table fails here, by name, on the scan that omits it.
The second is a retention rule the clipboard and paste-guard surfaces set; the
paste-guard tests hold its concrete assertion (a clean command line leaves no
row and no file).
"""
import ast
import inspect
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling import
import aegis  # noqa: E402
from test_regression import Sandbox, needs_the_real_body  # noqa: E402

# Sensors gather_all schedules on every body.
PORTABLE = frozenset((
    "persistence.diff", "process", "behavior", "shell-history", "clipboard",
    "hot-dir", "staging", "supply-chain", "session-theft", "canary", "latch",
    "decoy", "assay", "outbound", "web-protection", "hardening",
    "self-protection", "vouch-store", "paste-guard",
    # The monitor watching itself, added on main while this roster was being
    # written on a branch: the notary (until then it ran only when a human
    # typed `aegis.py notary`) and the event store's integrity check (until
    # then there was none — a corrupt aegis.db silenced every incident while
    # findings kept flowing and the report kept reading clean).
    "notary", "event-store",
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
DIRECT = frozenset(("persistence.snapshot", "coverage",
                    "process.enumerate", "process.argv", "signature.classify",
                    "scan.cost"))


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


@needs_the_real_body
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


# --- A non-answer is never rendered as a verdict --------------------------- #
# Shared helpers that sensors route their reads through. A silent handler in
# one of these hides a gap from every sensor above it.
SHARED_READERS = (
    "_iter_processes_live", "_process_ancestry_table", "_annotate_ancestry",
    "_iter_package_manifests", "_outbound_rows", "_linux_socket_inode_pids",
    "_agent_repo_roots", "_agent_config_files", "check_persistence",
    "check_agent_surface_coverage", "check_coverage", "check_store_integrity",
)
# Handlers allowed to stay silent, keyed (function, exception spelling, ordinal
# of that spelling within the function, source order) -> the reason. A key
# that no longer matches a silent handler fails test_allowlist_names_no_ghosts,
# so a fixed site cannot leave a stale exemption behind.
SILENT_OK = {
    ("_iter_processes_live", "Exception", 2):
        "exe unreadable = another user's process or a kernel thread; the "
        "same-user boundary drops it downstream, and `ps` on mac has the "
        "same blind spot",
    ("_iter_processes_live", "Exception", 3):
        "cmdline unreadable, same boundary as above",
    ("_linux_socket_inode_pids", "Exception", 1):
        "other users' fd tables are unreadable without root: the documented "
        "unprivileged boundary; a listener is still reported, with an "
        "unknown path",
    ("_linux_socket_inode_pids", "Exception", 2):
        "same boundary, one fd deeper",
    ("check_store_integrity", "Exception", 0):
        "a close() that fails after the read succeeded changes no verdict",
    ("check_store_integrity", "OSError", 0):
        "the failure note is re-read next scan; a failed removal repeats one "
        "finding and can never hide one",
    ("check_xprotect", "Exception", 1):
        "an eventMessage that is not JSON is a non-detection log line; the "
        "status field the next branch requires is what it lacks",
    ("snapshot_btm_store", "Exception", 1):
        "the size is recorded as None -- the non-answer is spelled in the "
        "record itself, beside a hash that was read",
}


def _silent_kind(handler):
    """'pass' | 'continue' | 'return-empty' | 'assign-empty' | None."""
    body = [s for s in handler.body
            if not (isinstance(s, ast.Expr)
                    and isinstance(s.value, ast.Constant))]
    if not body:
        return "pass"
    if len(body) != 1:
        return None
    s = body[0]

    def empty(v):
        if v is None:
            return True
        if isinstance(v, ast.Constant):
            return v.value in (None, False, "", 0)
        if isinstance(v, (ast.List, ast.Tuple, ast.Set)):
            return not v.elts
        if isinstance(v, ast.Dict):
            return not v.keys
        return (isinstance(v, ast.Call) and isinstance(v.func, ast.Name)
                and v.func.id in ("dict", "list", "set") and not v.args)

    if isinstance(s, ast.Pass):
        return "pass"
    if isinstance(s, ast.Continue):
        return "continue"
    if isinstance(s, ast.Return) and empty(s.value):
        return "return-empty"
    if isinstance(s, ast.Assign) and empty(s.value):
        return "assign-empty"
    return None


def _handlers_in(fn):
    """Except handlers of fn in source order, nested defs/lambdas excluded:
    a nested helper's `return None` is its own contract with its caller."""
    out = []

    def walk(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                  ast.Lambda)):
                continue
            if isinstance(child, ast.ExceptHandler):
                out.append(child)
            walk(child)
    walk(fn)
    return out


def _whole_sensor_non_answer(handler):
    """`return None` / bare `return` / `return SURFACE_PRIVILEGED`: the caller
    (_collect_sensor, _scan_surfaces) turns these into DEGRADED/PRIVILEGED."""
    body = [s for s in handler.body
            if not (isinstance(s, ast.Expr)
                    and isinstance(s.value, ast.Constant))]
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        return False
    v = body[0].value
    return (v is None or (isinstance(v, ast.Constant) and v.value is None)
            or (isinstance(v, ast.Name) and v.id == "SURFACE_PRIVILEGED"))


def _sensor_function_names():
    names = set(SHARED_READERS)
    src = inspect.getsource(aegis.gather_all)
    names |= set(re.findall(r'^\s+\("[\w.-]+",\s*(check_\w+)', src, re.M))
    for is_mac, is_linux in ((True, False), (False, True), (False, False)):
        for row in aegis._build_surfaces(is_mac, is_linux):
            names.add(row[1].__name__)
    return sorted(names)


def _silent_handlers():
    """[(fn, spelling, ordinal, lineno, kind)] for every silent handler in a
    sensor function that is neither an absence nor a whole-sensor
    non-answer."""
    tree = ast.parse(inspect.getsource(aegis))
    fns = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    out = []
    for name in _sensor_function_names():
        fn = fns.get(name)
        if fn is None:
            continue
        seen = {}
        for h in _handlers_in(fn):
            spelling = ast.unparse(h.type) if h.type is not None else "bare"
            ordinal = seen.get(spelling, 0)
            seen[spelling] = ordinal + 1
            kind = _silent_kind(h)
            if kind is None:
                continue
            if spelling == "FileNotFoundError":
                continue            # absence is a real answer
            if _whole_sensor_non_answer(h):
                continue
            out.append((name, spelling, ordinal, h.lineno, kind))
    return out


class TestNoSilentNonAnswerInASensor(unittest.TestCase):
    def test_every_silent_handler_is_ledgered_or_justified(self):
        offenders = ["%s:%d  except %s  -> %s  (key %r)"
                     % (fn, line, spelling, kind, (fn, spelling, ordinal))
                     for fn, spelling, ordinal, line, kind in _silent_handlers()
                     if (fn, spelling, ordinal) not in SILENT_OK]
        self.assertEqual([], offenders,
                         "silent except handler(s) in sensor code. A sensor "
                         "that found an item and could not examine it must "
                         "say so: call unexamined(subject, why, exc) in the "
                         "handler, return None for a whole-sensor "
                         "non-answer, or add the key to SILENT_OK with the "
                         "reason it changes no verdict:\n  "
                         + "\n  ".join(offenders))

    def test_allowlist_names_no_ghosts(self):
        live = {(fn, spelling, ordinal)
                for fn, spelling, ordinal, _l, _k in _silent_handlers()}
        ghosts = sorted(k for k in SILENT_OK if k not in live)
        self.assertEqual([], ghosts,
                         "SILENT_OK names handler(s) that are no longer "
                         "silent (fixed, or renumbered by an edit above "
                         "them): %s" % ghosts)

    def test_the_roster_is_not_empty_on_any_body(self):
        # The sweep is only as good as its roster: a regex that stops
        # matching gather_all would pass the test above vacuously.
        names = _sensor_function_names()
        self.assertIn("check_behavior", names)
        self.assertIn("snapshot_agent_surface", names)
        self.assertGreater(len(names), 30)


if __name__ == "__main__":
    unittest.main()
