#!/usr/bin/env python3
"""Four durable at-rest surfaces that had no sensor.

Everything Aegis does is a poll — hourly, or a 600s floor under watch — so a
smash-and-grab leaves filesystem residue, not a process. That makes at-rest
artifacts worth more than another argv regex, and these four were the largest
gaps for a macOS developer box:

  · TCC grants. The user database is readable WITHOUT Full Disk Access and
    this file already opened it as a self-test, yet nothing baselined which
    applications hold ScreenCapture, Accessibility, Microphone or Camera —
    exactly the grants a RAT needs and exactly what an "approve this dialog"
    social-engineering step produces.
  · The BackgroundItems store. `sfltool dumpbtm` needs interactive admin
    authorization on macOS 26, so the BTM surface is PERMANENTLY privileged
    here and SMAppService persistence — the modern path that leaves no
    LaunchAgents plist — was a standing zero.
  · Configuration-profile PAYLOADS and network config. The profiles snapshot
    stored identifiers only, so a new trusted root CA or proxy under an
    existing identifier was undetectable, and DNS/proxy had no sensor at all.
  · sitecustomize.py / usercustomize.py / .pth, which execute on every Python
    start and live under site-packages, which supply-chain scanning skips.
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

# Gate on the flag the SIMULATED body sets, not on the host's sys.platform.
# tests/simbody.py flips aegis's platform flags before test modules import, so
# a class gated on sys.platform still runs under SIM_BODY=win on a Mac and then
# fails against the Windows branch of the code it is testing. That is the exact
# defect class simbody exists to surface, and it surfaced this file.
IS_MAC = aegis.IS_MAC


def _fingerprints(found):
    return [f.get("fingerprint", "") for f in found]


def _sev(found, needle):
    """Severity of the finding ABOUT `needle`.

    Deliberately searches the detail, not the fingerprint: diff_tcc hashes the
    client into the fingerprint so the identity is stable and opaque, and the
    human-readable client name lives in the detail. A test that grepped the
    fingerprint would be asserting the identity scheme, not the verdict."""
    for f in found:
        if needle in f.get("detail", "") or needle in f.get("title", ""):
            return f["severity"]
    return None


@unittest.skipUnless(IS_MAC, "TCC is a macOS database")
class TestTccGrants(unittest.TestCase):
    """Grade by what the grant BUYS. A new Reminders grant and a new
    ScreenCapture grant are not the same event, and flattening them is how a
    sensor becomes noise the operator scrolls past."""

    def test_screen_and_accessibility_outrank_ordinary_grants(self):
        self.assertNotEqual(aegis._tcc_grade("kTCCServiceScreenCapture"),
                            aegis._tcc_grade("kTCCServiceReminders"))
        self.assertNotEqual(aegis._tcc_grade("kTCCServiceAccessibility"),
                            aegis._tcc_grade("kTCCServiceReminders"))

    def test_a_newly_granted_critical_capability_is_reported(self):
        prior = {}
        cur = {"kTCCServiceScreenCapture|com.evil.app": {"auth": 2}}
        found = aegis.diff_tcc(prior, cur)
        self.assertTrue(found, "a new ScreenCapture grant must not be silent")
        self.assertIn(_sev(found, "com.evil.app"), ("HIGH", "CRITICAL"))

    def test_a_denied_entry_is_not_a_grant(self):
        """auth 0/1 is denied/unknown. Reporting those as capability would
        alarm on every app the operator has ever said no to."""
        found = aegis.diff_tcc({}, {"kTCCServiceCamera|com.x": {"auth": 0}})
        self.assertEqual([], found)

    def test_revoking_a_grant_is_not_an_alarm(self):
        prior = {"kTCCServiceCamera|com.x": {"auth": 2}}
        cur = {"kTCCServiceCamera|com.x": {"auth": 0}}
        for f in aegis.diff_tcc(prior, cur):
            self.assertNotIn(f.get("severity"), ("HIGH", "CRITICAL"))

    def test_the_live_database_is_readable_and_shaped_as_expected(self):
        snap = aegis.snapshot_tcc()
        if snap is None:
            self.skipTest("TCC db unreadable on this host — DEGRADED, honest")
        self.assertIsInstance(snap, dict)
        for key, rec in list(snap.items())[:20]:
            self.assertIn("|", key, "identity is service|client")
            self.assertIn("auth", rec)

    def test_an_unreadable_database_is_degraded_not_empty(self):
        """A false empty is a lie: it would read as 'no app holds any grant'.

        The precondition is BUILT, not borrowed from the host. snapshot_tcc
        answers {} for an ABSENT store and only reaches _sqlite_readonly once
        the file exists, so stubbing the opener alone asserts nothing on a
        machine that has no TCC.db — which is every simbody run of this file on
        a non-Mac runner, where IS_MAC is a flag and the filesystem is not.
        The simbody gate caught exactly that: green here, red on ubuntu."""
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        present = os.path.join(tmp, "TCC.db")
        with open(present, "wb") as fh:
            fh.write(b"not a database")
        real_db = aegis.TCC_USER_DB
        self.addCleanup(setattr, aegis, "TCC_USER_DB", real_db)
        aegis.TCC_USER_DB = present
        real = aegis._sqlite_readonly
        self.addCleanup(setattr, aegis, "_sqlite_readonly", real)
        aegis._sqlite_readonly = lambda *a, **k: None
        # PRIVILEGED, not DEGRADED, corrected 2026-09-04 against the live
        # install: this refusal is the NORMAL answer for the scheduled agent,
        # which has no Full Disk Access, while an interactive shell reads 365
        # rows on the same machine. Grading the expected answer as a failure
        # opened a permanent HIGH sensor incident (24 consecutive "failures"
        # inside a day), which is how the coverage panel becomes noise.
        self.assertIs(aegis.SURFACE_PRIVILEGED, aegis.snapshot_tcc())

    def test_a_schema_it_cannot_read_is_still_degraded(self):
        """The other side of that line: a privilege wall is expected and is
        fixed by granting access; a database this code cannot parse is neither,
        and must not be filed under the same honest-limitation heading."""
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        present = os.path.join(tmp, "TCC.db")
        with open(present, "wb") as fh:
            fh.write(b"not a database")
        self.addCleanup(setattr, aegis, "TCC_USER_DB", aegis.TCC_USER_DB)
        aegis.TCC_USER_DB = present

        class _Db(object):
            def execute(self, *a, **k):
                raise RuntimeError("unreadable schema")

            def close(self):
                pass
        real = aegis._sqlite_readonly
        self.addCleanup(setattr, aegis, "_sqlite_readonly", real)
        aegis._sqlite_readonly = lambda *a, **k: _Db()
        self.assertIsNone(aegis.snapshot_tcc())


class TestPythonStartupHooks(unittest.TestCase):
    """sitecustomize/usercustomize/.pth run at EVERY interpreter start and are
    pure persistence. site-packages is skipped by supply-chain scanning, so
    nothing looked at them."""

    def test_the_startup_file_names_are_the_ones_site_imports(self):
        self.assertIn("sitecustomize.py", aegis._PY_STARTUP_FILES)
        self.assertIn("usercustomize.py", aegis._PY_STARTUP_FILES)


@unittest.skipUnless(IS_MAC, "BTM store is macOS-only")
class TestBtmStoreTripwire(unittest.TestCase):
    """The format is not parseable without private frameworks and this makes
    no attempt to pretend otherwise. 'The background-items store changed and
    no launchd plist did' is actionable on its own — that correlation is the
    entire point."""

    def test_a_changed_store_is_reported(self):
        prior = {"BackgroundItems-v13.btm": {"sha256": "a" * 64}}
        cur = {"BackgroundItems-v13.btm": {"sha256": "b" * 64}}
        self.assertTrue(aegis.diff_btm_store(prior, cur))

    def test_an_unchanged_store_is_silent(self):
        same = {"BackgroundItems-v13.btm": {"sha256": "a" * 64}}
        self.assertEqual([], aegis.diff_btm_store(same, dict(same)))

    def test_the_snapshot_never_raises_on_this_host(self):
        aegis.snapshot_btm_store()   # absent or present, both fine


class TestNetworkConfigAndProfilePayloads(unittest.TestCase):
    def test_netconfig_snapshot_never_raises(self):
        aegis.snapshot_netconfig()

    def test_a_changed_resolver_is_reported(self):
        prior = {"dns:Wi-Fi": {"value": "1.1.1.1"}}
        cur = {"dns:Wi-Fi": {"value": "6.6.6.6"}}
        self.assertTrue(aegis.diff_netconfig(prior, cur))

    def test_an_unchanged_network_config_is_silent(self):
        same = {"dns:Wi-Fi": {"value": "1.1.1.1"}}
        self.assertEqual([], aegis.diff_netconfig(same, dict(same)))

    def test_a_payload_change_under_a_stable_identifier_is_caught(self):
        """The whole reason payload hashing replaced identifier collection: a
        profile that swaps in a trusted root CA keeps its identifier."""
        prior = {"com.corp.profile": {"sha256": "a" * 64}}
        cur = {"com.corp.profile": {"sha256": "b" * 64}}
        self.assertTrue(aegis.diff_profile_payloads(prior, cur))

    def test_profile_payload_snapshot_never_raises(self):
        aegis.snapshot_profile_payloads()


class TestSurfacesAreRegistered(unittest.TestCase):
    """Each of these existed as functions before; the defect being fixed is
    that a sensor which is never called is not a sensor."""

    def test_all_four_are_in_the_surface_table(self):
        import inspect
        src = inspect.getsource(aegis._build_surfaces)
        for name in ("tcc", "netconfig", "btm_store"):
            self.assertIn('("%s"' % name, src, name)


if __name__ == "__main__":
    unittest.main()
