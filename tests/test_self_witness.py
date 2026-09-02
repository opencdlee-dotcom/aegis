"""The self-protection witness must not be re-derived from the file it guards.

Found on the reference machine as incident #292: `self:baseline:tampered` with
exactly ONE evidence event, opened 2026-08-25 and never re-emitted across ~150
scans — a condition that were still true would re-fire like every other
standing fact. The mechanism: `record_selfstate()` runs unconditionally at the
end of every scan and re-records each trust store's sha/mac from the file's
CURRENT bytes, with no exclusion for a store that just failed the tamper check.
So tampering — real or self-inflicted — alarms exactly once, and the detecting
scan itself blesses the tampered bytes as the new ground truth. `doctor` and
`status` read clean afterwards, and the open incident is unfalsifiable.

The sibling defect: `_migrate_baseline` hand-writes `baseline_sha` only, while
`check_self_protection` PREFERS the mac — so on a MAC-bearing store, Aegis's
own schema migration reads as out-of-band tampering on the next scan.

Platform-independent by construction: every test builds its own trust-store
files inside the Sandbox tmp dir; no launchd, plists, or platform vocabulary.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import aegis                                    # noqa: E402
from test_regression import Sandbox                           # noqa: E402


def _tamper_fps():
    return [f["fingerprint"] for f in aegis.check_self_protection()
            if ":tampered:" in f["fingerprint"]]


class TamperedTrustStoreStaysAccused(Sandbox):
    """An out-of-band edit must alarm on EVERY scan until an authorized write."""

    def _arm(self):
        aegis.save_json(aegis.BASELINE,
                        {"schema_version": aegis.BASELINE_SCHEMA_VERSION})
        aegis.record_selfstate()            # authorized witness of clean state

    def test_tamper_alarms_on_every_scan_until_an_authorized_write(self):
        self._arm()
        with open(aegis.BASELINE, "a") as fh:   # out-of-band edit
            fh.write("\n")
        first = _tamper_fps()
        self.assertTrue(any("self:baseline:tampered" in fp for fp in first),
                        "the out-of-band edit was not detected at all")
        aegis.record_selfstate()            # end-of-scan re-record
        second = _tamper_fps()
        # BEFORE THE FIX: empty — the detecting scan blessed the edit.
        self.assertTrue(any("self:baseline:tampered" in fp for fp in second),
                        "a tampered trust store was adopted as ground truth by "
                        "the very scan that detected the tampering")

    def test_deletion_stays_accused_too(self):
        """Deletion is the more dangerous tamper (it forces a silent
        re-baseline); it must not be blessed by the next record either."""
        self._arm()
        os.remove(aegis.BASELINE)
        self.assertTrue(_tamper_fps())
        aegis.record_selfstate()
        self.assertTrue(
            _tamper_fps(),
            "a deleted trust store stopped alarming after one scan")

    def test_authorized_rewrite_clears_the_standing_accusation(self):
        self._arm()
        with open(aegis.BASELINE, "a") as fh:
            fh.write("\n")
        self.assertTrue(_tamper_fps())      # accusation stands...
        aegis.record_selfstate()
        self.assertTrue(_tamper_fps())      # ...and persists...
        aegis._record_baseline_watermark()  # ...until an AUTHORIZED write
        self.assertEqual([], _tamper_fps(),
                         "an authorized re-watermark did not clear the alarm")

    def test_an_unflagged_store_is_still_witnessed_normally(self):
        """The fix must be scoped: while the baseline stands accused, the OTHER
        stores' watermarks keep advancing with each record_selfstate."""
        self._arm()
        aegis.save_json(aegis.ALLOWLIST, [])
        aegis.record_selfstate()            # witnesses the allowlist
        with open(aegis.BASELINE, "a") as fh:
            fh.write("\n")                  # baseline tampered
        self.assertTrue(_tamper_fps())
        aegis.save_json(aegis.ALLOWLIST, ["fp1"])   # aegis's own allow-write
        aegis.record_selfstate()            # scan end: allowlist re-witnessed
        fps = _tamper_fps()
        self.assertTrue(any("baseline" in fp for fp in fps))
        self.assertFalse(any("allowlist" in fp for fp in fps),
                         "the scoped skip wrongly froze an unflagged store")


class MigrationDoesNotAccuseItself(Sandbox):
    def test_schema_migration_is_not_read_as_tampering_on_a_mac_store(self):
        """No test has ever put a MAC-carrying selfstate through a schema
        migration — `TestBaselineSchemaMigration` seeds `baseline_sha` only.
        `_migrate_baseline` must re-witness with BOTH sha and mac, or every
        MAC-bearing install alarms HIGH at the next schema bump."""
        aegis.save_json(aegis.BASELINE, {
            "schema_version": aegis.BASELINE_SCHEMA_VERSION - 1,
            "persistence": {}})
        aegis.record_selfstate()            # store now carries a MAC
        aegis.load_baseline()               # triggers _migrate_baseline
        # BEFORE THE FIX: baseline_mac is stale → HIGH self:baseline:tampered.
        self.assertEqual([], _tamper_fps(),
                         "Aegis's own schema migration read as tampering")


if __name__ == "__main__":
    unittest.main()
