#!/usr/bin/env python3
"""Every PowerShell probe is sized against one measurement, or it is on a list.

A COLD `powershell.exe` on a real machine was measured at 21.4s just to start.
A cap at or near that is not a timeout, it is a coin flip on whether the
interpreter finished booting. The failure is silent in both directions this
file cares about: a probe that cannot answer returns a non-answer, so a
too-tight cap does not look like a bug, it looks like a machine with nothing
to report.

Two call sites had drifted below the ceiling and each cost something real:

  _snapshot_auth_sessions_win   30s   flaked in CI, in the same session as the
                                      signature probe -- the only other thing
                                      reaching the OS through the same
                                      run(["powershell", ...]) call.
  _process_start_token          15s   BELOW the measured cold start, so it
                                      could not return in time on a cold
                                      interpreter by construction. Fails closed
                                      (a None token reads as PID reuse), so the
                                      cost was every response action declining
                                      on exactly the cold machine where the
                                      first action after boot happens.

This is an AST audit, not a grep: aegis.py embeds installer templates as string
literals, and a grep for run(["powershell" matches inside them.
"""
import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

# fn name -> the tighter cap it is allowed to keep, and why. A hang costs more
# than a miss at each of these; adding a fourth means arguing for it here.
TIGHTER_ON_PURPOSE = {
    # best-effort toast; the finding is already stored, and a 90s hang would
    # stall the scan that produced it
    "notify": 25,
    # up to four calls in one deadfall cycle, so the worst case is 4x this
    "_clipboard_read": 30,
    "_clipboard_write": 30,
}

# The floor every literal cap must clear: ~3x the measured 21.4s cold start.
# Sites well above it (120s, 180s) are sized for their own work and are left
# alone -- this test is about the ones that drifted UNDER a startup cost.
PS_FLOOR_SECS = 60

# One cap is computed rather than literal, and correctly so: it scales with the
# batch it is waiting on. Named here so "not a literal" cannot become a way to
# get under the floor unexamined.
COMPUTED_ON_PURPOSE = {
    "warm_signature_cache": "60s base + 2s per file in the batch",
}

# A refactor that stops matching must fail loudly rather than pass vacuously.
MIN_CALL_SITES = 14


class _PSCalls(ast.NodeVisitor):
    """Every run([... "powershell" ...], timeout=...) with its enclosing def."""

    def __init__(self):
        self.stack = []
        self.calls = []          # (fn_name, lineno, timeout_node)

    def visit_FunctionDef(self, node):
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id == "run" and node.args:
            argv = node.args[0]
            if isinstance(argv, ast.List) and any(
                isinstance(e, ast.Constant)
                and isinstance(e.value, str)
                and e.value.lower() == "powershell"
                for e in argv.elts
            ):
                to = None
                for kw in node.keywords:
                    if kw.arg == "timeout":
                        to = kw.value
                self.calls.append(
                    (self.stack[-1] if self.stack else "<module>",
                     node.lineno, to))
        self.generic_visit(node)


def _ps_calls():
    with open(aegis.__file__, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    v = _PSCalls()
    v.visit(tree)
    return v.calls


class PowerShellTimeoutFloor(unittest.TestCase):
    def test_the_ceiling_clears_the_measured_cold_start(self):
        # 21.4s is the measurement the whole rule rests on; a ceiling that does
        # not clear it with real margin is not a ceiling.
        self.assertGreaterEqual(aegis.WIN_PS_COLD_START_CEILING, 60)

    def test_the_audit_actually_finds_the_call_sites(self):
        calls = _ps_calls()
        self.assertGreaterEqual(
            len(calls), MIN_CALL_SITES,
            "found only %d PowerShell call sites; the AST walk has stopped "
            "matching and every other assertion here is now vacuous"
            % len(calls))

    def test_every_powershell_probe_names_a_timeout(self):
        missing = [(fn, ln) for fn, ln, to in _ps_calls() if to is None]
        self.assertEqual(
            missing, [],
            "PowerShell call sites with no timeout at all (run() would wait on "
            "a hung interpreter): %r" % (missing,))

    def test_no_probe_is_capped_below_the_cold_start_floor(self):
        offenders = []
        for fn, lineno, to in _ps_calls():
            if fn in TIGHTER_ON_PURPOSE:
                # Pinned, not merely permitted: changing one of these should
                # have to come here and say why.
                self.assertTrue(
                    isinstance(to, ast.Constant)
                    and to.value == TIGHTER_ON_PURPOSE[fn],
                    "%s (line %d) is on the deliberately-tighter list at %ds; "
                    "its timeout changed. Update the list and its reason, or "
                    "move it to the ceiling."
                    % (fn, lineno, TIGHTER_ON_PURPOSE[fn]))
                continue
            if isinstance(to, ast.Name) and to.id == "WIN_PS_COLD_START_CEILING":
                continue
            if isinstance(to, ast.Constant) and isinstance(to.value, (int, float)):
                if to.value < PS_FLOOR_SECS:
                    offenders.append((fn, lineno, to.value))
                continue
            if fn in COMPUTED_ON_PURPOSE:
                continue
            offenders.append((fn, lineno, ast.dump(to)))
        self.assertEqual(
            offenders, [],
            "PowerShell probes capped below the cold-start floor of %ds. A "
            "cold powershell.exe was measured at 21.4s just to START, so a cap "
            "near that is a coin flip -- and it fails as silence, not as an "
            "error: %r" % (PS_FLOOR_SECS, offenders))

    def test_the_two_probes_that_flaked_are_at_the_ceiling(self):
        by_fn = {}
        for fn, lineno, to in _ps_calls():
            by_fn.setdefault(fn, []).append(to)
        for fn in ("_snapshot_auth_sessions_win", "_process_start_token",
                   "_classify_windows"):
            self.assertIn(fn, by_fn, "%s no longer runs a PowerShell probe" % fn)
            for to in by_fn[fn]:
                self.assertTrue(
                    isinstance(to, ast.Name)
                    and to.id == "WIN_PS_COLD_START_CEILING",
                    "%s must use the ceiling; this is the regression the two "
                    "CI flakes bought" % fn)


if __name__ == "__main__":
    unittest.main()
