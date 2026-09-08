"""Aegis raised its loudest alarm about aegis following its own README.

Found live on the reference Mac, 2026-09-07. The optional root BTM helper --
installed by hand exactly as README documents, because macOS 26 moved
`sfltool dumpbtm` behind system.privilege.admin -- is not referenced anywhere
in aegis.py, so the monitor had no idea the file was its own. Both sensors
watching that surface saw it appear:

    persistence.diff  "New persistence item"   (own severity: LOW)
    btm               "New background item"

and `chain:supply-chain` correlates precisely those two categories on one
entity. So a LOW finding escalated to a CRITICAL "Background-item execution
chain" -- which is never auto-tolerated and never aged out -- and re-fired
every scan: 42 events on one path in five hours.

Identity is PROVEN here, never assumed, and the negatives below are the point.
The path must be exactly ours; root must own both it and its directory with
nobody else able to write either (the same _root_owned test aegis already
applies to the dump this daemon writes); and the plist must actually name that
dump. A byte-identical copy somewhere a same-uid attacker CAN write is
rejected -- that is the squat this check exists to refuse. Everything
unreadable or unexpected fails closed and alarms exactly as before.

The suppression is deliberately APPEARANCE-only. A change to a root plist is
worth a look even when the file is ours, so diff_btm's changed path is
untouched -- the same first-sight-vs-changed asymmetry that already governs
agent configs.

Platform-independent by construction: _root_owned is substituted (a test suite
cannot create a root-owned file, and its own docstring says so).
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import aegis                                    # noqa: E402


class SelfDaemonIdentity(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.plist = os.path.join(self.dir, "com.charlie.aegis-btm.plist")
        with open(self.plist, "w", encoding="utf-8") as fh:
            fh.write("<plist><string>%s</string></plist>\n"
                     % aegis._BTM_DUMP_FILE)
        self._saved = (aegis._BTM_DAEMON_PLIST, aegis._root_owned)
        aegis._BTM_DAEMON_PLIST = self.plist
        aegis._root_owned = lambda p: True          # stand in for root
        self.addCleanup(self._restore)

    def _restore(self):
        aegis._BTM_DAEMON_PLIST, aegis._root_owned = self._saved

    def test_our_own_daemon_is_recognised(self):
        self.assertTrue(aegis._is_aegis_btm_daemon(self.plist))

    def test_a_file_root_does_not_own_is_refused(self):
        aegis._root_owned = lambda p: False
        self.assertFalse(aegis._is_aegis_btm_daemon(self.plist))

    def test_a_world_writable_directory_is_refused(self):
        """_root_owned covers the DIRECTORY too: a plist nobody can edit in a
        directory anybody can replace it in is not proof of anything."""
        aegis._root_owned = lambda p: p != os.path.dirname(self.plist)
        self.assertFalse(aegis._is_aegis_btm_daemon(self.plist))

    def test_a_plist_that_does_not_name_our_dump_is_refused(self):
        with open(self.plist, "w", encoding="utf-8") as fh:
            fh.write("<plist><string>/tmp/somewhere/else</string></plist>\n")
        self.assertFalse(aegis._is_aegis_btm_daemon(self.plist))

    def test_any_other_path_is_refused(self):
        for p in (None, "", "/Library/LaunchDaemons/com.apple.x.plist",
                  self.plist + ".bak"):
            self.assertFalse(aegis._is_aegis_btm_daemon(p), repr(p))

    def test_an_identical_copy_elsewhere_is_refused(self):
        """The squat: same name, same bytes, somewhere the user can write."""
        other = os.path.join(tempfile.mkdtemp(),
                             "com.charlie.aegis-btm.plist")
        with open(other, "w", encoding="utf-8") as fh:
            fh.write(open(self.plist, encoding="utf-8").read())
        self.assertFalse(aegis._is_aegis_btm_daemon(other))

    def test_an_unreadable_plist_fails_closed(self):
        os.remove(self.plist)
        self.assertFalse(aegis._is_aegis_btm_daemon(self.plist))


class NeitherSensorFiresOnIt(unittest.TestCase):
    def setUp(self):
        self._saved = aegis._is_aegis_btm_daemon
        aegis._is_aegis_btm_daemon = lambda p: p == aegis._BTM_DAEMON_PLIST
        self.addCleanup(lambda: setattr(aegis, "_is_aegis_btm_daemon",
                                        self._saved))

    def test_persistence_does_not_report_our_own_daemon(self):
        snap = {aegis._BTM_DAEMON_PLIST: {
            "label": "com.charlie.aegis-btm", "program": "/bin/sh",
            "trust": "unknown", "sha256": "a" * 64}}
        # BEFORE THE FIX: one "New persistence item", every scan, forever.
        self.assertEqual([], aegis.check_persistence({}, snap))

    def test_persistence_still_reports_everything_else(self):
        """The skip is one path, not a hole in the sensor."""
        snap = {"/Library/LaunchDaemons/com.evil.plist": {
            "label": "com.evil", "program": "/tmp/x",
            "trust": "adhoc", "sha256": "b" * 64}}
        self.assertEqual(1, len(aegis.check_persistence({}, snap)))

    def test_btm_does_not_report_our_own_daemon_on_first_sight(self):
        cur = {"com.charlie.aegis-btm": {
            "name": "aegis-btm", "type": "daemon", "team": None,
            "url": "file://" + aegis._BTM_DAEMON_PLIST}}
        self.assertEqual([], aegis.diff_btm({}, cur))

    def test_btm_still_reports_other_new_background_items(self):
        cur = {"com.evil": {"name": "evil", "type": "login", "team": None,
                            "url": "file:///tmp/evil"}}
        self.assertEqual(1, len(aegis.diff_btm({}, cur)))

    def test_a_change_to_our_daemon_is_still_reported(self):
        """Appearance is silent; an EDIT to a root plist is not."""
        prior = {"com.charlie.aegis-btm": {
            "name": "aegis-btm", "type": "daemon", "team": "T1",
            "url": "file://" + aegis._BTM_DAEMON_PLIST}}
        cur = {"com.charlie.aegis-btm": {
            "name": "aegis-btm", "type": "daemon", "team": None,
            "url": "file://" + aegis._BTM_DAEMON_PLIST}}
        self.assertEqual(1, len(aegis.diff_btm(prior, cur)),
                         "a swapped root daemon went unreported")


if __name__ == "__main__":
    unittest.main()
