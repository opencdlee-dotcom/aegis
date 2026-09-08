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
every scan: 54 events on one path in six hours.

Identity is PROVEN here, never assumed, and the negatives below are the point.
The path must be exactly ours; root must own both it and its directory with
nobody else able to write either (the same _root_owned test aegis already
applies to the dump this daemon writes); and the BYTES must be the ones aegis
ships. A byte-identical copy somewhere a same-uid attacker CAN write is
rejected -- that is the squat this check exists to refuse -- and so is an
edited copy in the right place.

WHY THE CONTENT HASH IS LOAD-BEARING, not belt-and-braces. The first version of
this fix suppressed only first sight and left the two CHANGED paths alone, on
the theory that an edit to a root plist would still alert. It would not:
neither sensor can reach a changed-branch for this file, so the suppression
would have been PERMANENT and the comment claiming otherwise would have been
false in production. `test_neither_sensor_can_ever_diff_a_change_to_it` pins
both halves of that reasoning against the real registry, so the day someone
makes a change-diff reachable, this file says so.

Platform-independent by construction: _root_owned is substituted (a test suite
cannot create a root-owned file, and its own docstring says so).
"""
import hashlib
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import aegis, SUSPICIOUS_TRUST                  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIPPED = os.path.join(REPO, "aegis-btm-daemon.plist")


class ThePinnedHashTracksTheShippedFile(unittest.TestCase):
    """aegis.py is installed ALONE (~/.aegis/aegis.py), so the shipped plist is
    not a sibling at runtime and the expected bytes must live in the source as
    a constant. That constant can go stale in exactly one way -- someone edits
    the plist -- and this is the guard that refuses to let them."""

    def test_the_constant_is_the_hash_of_the_shipped_plist(self):
        self.assertTrue(os.path.isfile(SHIPPED), SHIPPED)
        with open(SHIPPED, "rb") as fh:
            want = hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual(
            want, aegis._BTM_DAEMON_SHA256,
            "aegis-btm-daemon.plist changed but _BTM_DAEMON_SHA256 did not -- "
            "every install of the new plist would alarm as a stranger")


class SelfDaemonIdentity(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.plist = os.path.join(self.dir, "com.charlie.aegis-btm.plist")
        shutil.copyfile(SHIPPED, self.plist)   # the real shipped bytes
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

    def test_a_single_edited_byte_is_refused(self):
        """The edit case. No sensor can diff a change to this file, so this
        assertion IS aegis's change detection for it."""
        with open(self.plist, "ab") as fh:
            fh.write(b"<!-- -->")
        self.assertFalse(aegis._is_aegis_btm_daemon(self.plist))

    def test_a_plist_that_runs_something_else_is_refused(self):
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
        shutil.copyfile(self.plist, other)
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
        """The skip is one path, not a hole in the sensor.

        SUSPICIOUS_TRUST, not the literal "adhoc": that word is a verdict only
        macOS's codesign can produce, so hard-coding it would make this
        assertion exercise a branch Windows and Linux can never take --
        silently, on green CI. tests/test_cross_platform.py guards the class.
        """
        snap = {"/Library/LaunchDaemons/com.evil.plist": {
            "label": "com.evil", "program": "/tmp/x",
            "trust": SUSPICIOUS_TRUST, "sha256": "b" * 64}}
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

    def test_the_changed_path_is_untouched_by_the_patch(self):
        """diff_btm's changed_fn still fires for this identifier when it is
        given a prior record.

        Read this narrowly. It proves the patch touched only new_fn -- NOT that
        production ever reaches here for this daemon. It does not; see
        test_neither_sensor_can_ever_diff_a_change_to_it, which is why the
        identity check pins content instead.
        """
        prior = {"com.charlie.aegis-btm": {
            "name": "aegis-btm", "type": "daemon", "team": "T1",
            "url": "file://" + aegis._BTM_DAEMON_PLIST}}
        cur = {"com.charlie.aegis-btm": {
            "name": "aegis-btm", "type": "daemon", "team": None,
            "url": "file://" + aegis._BTM_DAEMON_PLIST}}
        self.assertEqual(1, len(aegis.diff_btm(prior, cur)))


class WhyTheHashIsLoadBearing(unittest.TestCase):
    """Both halves of the reasoning above, pinned against the real code.

    If either stops holding -- someone opts `btm` into per-item adoption, or
    the persistence baseline stops being write-once -- a changed-diff becomes
    reachable and the comment in aegis.py should be revisited. This test is how
    that day announces itself instead of passing silently.
    """

    @unittest.skipUnless(aegis.IS_MAC, "the btm surface is macOS-only")
    def test_neither_sensor_can_ever_diff_a_change_to_it(self):
        # _build_surfaces(IS_MAC, IS_LINUX), not the module-level
        # SURFACES: under simbody the flags move but the constant was
        # built at import time, so ask for this body's registry.
        rows = [r for r in aegis._build_surfaces(aegis.IS_MAC,
                                                 aegis.IS_LINUX)
                if r[0] == "btm"]
        self.assertEqual(1, len(rows), "btm surface not registered")
        _key, _snap, _diff, _scope, _live, adopt_new = \
            aegis._surface_row(rows[0])
        self.assertFalse(
            adopt_new,
            "btm now adopts new entries, so diff_btm's changed_fn CAN reach "
            "this daemon -- revisit the comment on _is_aegis_btm_daemon")

    def test_check_persistence_cannot_report_an_unbaselined_change(self):
        """The other half: the changed branch needs `path in base`, and
        baseline["persistence"] is written only on first_run."""
        rec = {"label": "x", "program": "/bin/sh", "trust": "unknown",
               "sha256": "c" * 64, "args_sha256": "d" * 64}
        moved = dict(rec, args_sha256="e" * 64)
        # Not in the baseline: the ONLY branch reachable is "new".
        out = aegis.check_persistence({}, {"/Library/LaunchDaemons/x.plist":
                                           moved})
        self.assertEqual(1, len(out))
        self.assertIn("New persistence item", out[0]["title"])


if __name__ == "__main__":
    unittest.main()
