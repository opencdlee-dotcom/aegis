#!/usr/bin/env python3
"""The vouch store is memoized. It is a TRUST store, so the cache must be
provably unable to serve a stale answer.

`load_vouches` verifies a hash-chained log by shelling out to `ssh-keygen`
once per record, and callers ask repeatedly. Profiled 2026-09-01: `rehunt` over
a 30-day store called it 4,520 times, spawned 9,043 ssh-keygen processes, and
spent 63 of that command's 70 seconds inside them (74s -> 1.28s after this).

Everything except EXPIRY is clock-independent, which is what makes the cache
sound — expiry is re-applied per call from the cached records.
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


class VouchCacheBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._saved = (aegis.VOUCH_FILE, aegis.VOUCH_SIGNERS)
        aegis.VOUCH_FILE = os.path.join(self.tmp, "vouches.jsonl")
        aegis.VOUCH_SIGNERS = os.path.join(self.tmp, "vouch_signers")
        aegis._VOUCH_CACHE.update({"key": None, "active": None, "reason": None})
        self.calls = []
        self._real = aegis._vouch_read_and_verify

        def counting():
            self.calls.append(1)
            return self._real()
        aegis._vouch_read_and_verify = counting

    def tearDown(self):
        aegis._vouch_read_and_verify = self._real
        aegis.VOUCH_FILE, aegis.VOUCH_SIGNERS = self._saved
        aegis._VOUCH_CACHE.update({"key": None, "active": None, "reason": None})
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestCacheHitsAndMisses(VouchCacheBase):
    def test_repeated_calls_verify_once(self):
        for _ in range(25):
            aegis.load_vouches()
        self.assertEqual(len(self.calls), 1,
                         "the expensive verification ran more than once")

    def test_a_changed_vouch_log_invalidates(self):
        aegis.load_vouches()
        with open(aegis.VOUCH_FILE, "w") as f:      # file appears
            f.write('{"seq": 1}\n')
        aegis.load_vouches()
        self.assertEqual(len(self.calls), 2,
                         "a modified vouch log served a cached answer")

    def test_a_changed_signer_roster_invalidates(self):
        with open(aegis.VOUCH_FILE, "w") as f:
            f.write('{"seq": 1}\n')
        aegis.load_vouches()
        with open(aegis.VOUCH_SIGNERS, "w") as f:   # roster pinned after
            f.write("someone ssh-ed25519 AAAA\n")
        aegis.load_vouches()
        self.assertEqual(len(self.calls), 2,
                         "a re-pinned signer roster served a cached answer")

    def test_same_size_different_content_still_invalidates(self):
        """The nastiest case for a stat-keyed cache: identical length."""
        with open(aegis.VOUCH_FILE, "w") as f:
            f.write("AAAA\n")
        aegis.load_vouches()
        before = len(self.calls)
        os.utime(aegis.VOUCH_FILE, (1, 1))          # force a distinct mtime
        with open(aegis.VOUCH_FILE, "w") as f:
            f.write("BBBB\n")                       # same size, new bytes
        aegis.load_vouches()
        self.assertGreater(len(self.calls), before,
                           "same-size edit went undetected")


class TestExpiryIsNotCached(VouchCacheBase):
    def test_expiry_is_reapplied_per_call(self):
        """A record cached as active must still expire on the next call. If
        expiry were folded into the cache, a vouch would outlive its own
        expires_at for as long as the file sat unchanged."""
        rec = {"subject": "workload:x", "expires_at": 1000}
        aegis._VOUCH_CACHE.update({"key": aegis._vouch_cache_key(),
                                   "active": {"workload:x": rec},
                                   "reason": None})
        live, reason = aegis.load_vouches(now=999)
        self.assertIsNone(reason)
        self.assertIn("workload:x", live, "unexpired vouch was dropped")

        live, reason = aegis.load_vouches(now=1001)
        self.assertNotIn("workload:x", live,
                         "EXPIRED vouch survived because expiry was cached")

    def test_a_tamper_reason_is_never_softened_by_the_cache(self):
        aegis._VOUCH_CACHE.update({"key": aegis._vouch_cache_key(),
                                   "active": {"workload:x": {}},
                                   "reason": "chain broken"})
        live, reason = aegis.load_vouches()
        self.assertEqual(live, {}, "records survived a tamper verdict")
        self.assertEqual(reason, "chain broken")


class TestNoVouchStoreIsStillNormal(VouchCacheBase):
    def test_absent_store_is_not_a_tamper_event(self):
        live, reason = aegis.load_vouches()
        self.assertEqual((live, reason), ({}, None))

    def test_log_without_a_roster_is_a_tamper_reason(self):
        with open(aegis.VOUCH_FILE, "w") as f:
            f.write('{"seq": 1}\n')
        live, reason = aegis.load_vouches()
        self.assertEqual(live, {})
        self.assertIsNotNone(reason)
        self.assertIn("roster", reason)


if __name__ == "__main__":
    unittest.main()
