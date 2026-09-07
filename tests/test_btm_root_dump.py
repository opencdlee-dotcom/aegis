#!/usr/bin/env python3
"""The optional root-maintained BTM dump: coverage without a password dialog.

macOS 26 walls `sfltool dumpbtm` behind system.privilege.admin. That right
cannot be granted to this agent interactively -- `shared: false` means no
credential carries to the fresh sfltool each scan spawns, and `timeout: 300`
expires a cached grant before the next 600s scan regardless. It IS
`allow-root: true`, so a root LaunchDaemon can dump the store on a schedule
and leave it for this unprivileged agent to read.

The whole risk of that design is the file itself: anything able to write it
could hand the monitor a background-item list with its own persistence edited
out. So these tests care less about the happy path than about the refusals.
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aegis  # noqa: E402

_DUMP = """#1:
\tUUID: u
\tName: Helper
\tType: login item
\tIdentifier: com.vendor.helper
\tURL: file:///Applications/Vendor.app/
"""


class BtmRootDump(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_btm_dump_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._saved = {k: getattr(aegis, k) for k in
                       ("_BTM_DUMP_FILE", "_root_owned", "run", "SURFACE_WALLS")}
        self.addCleanup(self._restore)
        aegis.SURFACE_WALLS = os.path.join(self.tmp, "surface_walls.json")
        aegis._BTM_DUMP_FILE = os.path.join(self.tmp, "btm.txt")
        self.probes = []
        aegis.run = lambda *a, **k: (self.probes.append(1), ("", "", 1))[1]

    def _restore(self):
        for k, v in self._saved.items():
            setattr(aegis, k, v)

    def _write(self, text=_DUMP, age=0):
        with open(aegis._BTM_DUMP_FILE, "w", encoding="utf-8") as fh:
            fh.write(text)
        if age:
            when = aegis._epoch() - age
            os.utime(aegis._BTM_DUMP_FILE, (when, when))

    def _trust(self, ok):
        aegis._root_owned = lambda path: ok

    def test_absent_dump_changes_nothing(self):
        """The feature is opt-in: with no file, aegis probes exactly as before."""
        self._trust(True)
        aegis.snapshot_btm()
        self.assertEqual(len(self.probes), 1, "must still probe sfltool")

    def test_a_root_owned_fresh_dump_is_used_without_probing(self):
        self._write()
        self._trust(True)
        snap = aegis.snapshot_btm()
        self.assertIn("com.vendor.helper", snap)
        self.assertEqual(self.probes, [], "no probe means no password dialog")

    def test_a_dump_not_owned_by_root_is_never_parsed(self):
        """The blinding attack: a writable dump listing no persistence at all.
        It must not be believed, and must not suppress the real probe either --
        suppressing it would BE the blinding."""
        self._write("#1:\n\tUUID: u\n\tIdentifier: com.attacker.nothing\n")
        self._trust(False)
        aegis.snapshot_btm()
        self.assertEqual(len(self.probes), 1,
                         "an untrusted dump must not replace the probe")

    def test_a_stale_dump_is_a_non_answer_not_an_empty_store(self):
        """A dead daemon must read as 'I could not look', never as 'nothing is
        there' -- a false-empty adopted into the baseline storms bogus 'new
        background item' findings the moment the daemon recovers."""
        self._write(age=aegis._BTM_DUMP_MAX_AGE + 60)
        self._trust(True)
        self.assertIsNone(aegis.snapshot_btm())
        self.assertEqual(self.probes, [],
                         "a stale dump is still a dump, not a reason to prompt")

    def test_a_fresh_dump_clears_a_previously_proven_wall(self):
        """Coverage restored is a wall down: later failures are genuinely new."""
        aegis._wall_record("btm")
        self.assertTrue(aegis._wall_seen("btm"))
        self._write()
        self._trust(True)
        aegis.snapshot_btm()
        self.assertFalse(aegis._wall_seen("btm"))

    def test_an_empty_dump_is_a_non_answer(self):
        self._write("")
        self._trust(True)
        self.assertIsNone(aegis.snapshot_btm())


if __name__ == "__main__":
    unittest.main()
