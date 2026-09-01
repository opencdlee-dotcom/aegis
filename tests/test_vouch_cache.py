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
        """The case that killed the stat-keyed version.

        Caught by windows-latest/py3.9: the Windows system clock ticks about
        every 15.6 ms, so a rewrite inside one tick keeps st_mtime_ns, and with
        the size unchanged the key was identical — a modified TRUST store
        served from cache. Deliberately writes back-to-back with no utime
        nudge, because "fast enough to share a clock tick" is exactly the
        window an attacker would use."""
        with open(aegis.VOUCH_FILE, "w") as f:
            f.write("AAAA\n")
        aegis.load_vouches()
        before = len(self.calls)
        with open(aegis.VOUCH_FILE, "w") as f:
            f.write("BBBB\n")                       # same size, new bytes
        aegis.load_vouches()
        self.assertGreater(len(self.calls), before,
                           "same-size edit went undetected")

    def test_a_rewrite_with_identical_bytes_is_not_a_change(self):
        """The other half: rewriting the same content must NOT bust the cache,
        or a touch-happy sync client would re-verify the chain every scan."""
        with open(aegis.VOUCH_FILE, "w") as f:
            f.write("AAAA\n")
        aegis.load_vouches()
        before = len(self.calls)
        with open(aegis.VOUCH_FILE, "w") as f:
            f.write("AAAA\n")
        aegis.load_vouches()
        self.assertEqual(len(self.calls), before,
                         "identical bytes forced a needless re-verification")


class TestCoarseClockCannotHideAnEdit(VouchCacheBase):
    """Pin the Windows failure mode so ANY body can fail on it.

    The stat-keyed cache broke only on windows-latest/py3.9, because macOS and
    Linux hand out nanosecond mtimes and a back-to-back rewrite therefore looks
    different there. That is the exact shape tests/simbody.py exists for: a
    macOS run cannot fail on a platform-shaped defect BY CONSTRUCTION. So this
    simulates the coarse clock instead of relying on one — quantising mtime to
    Windows' ~15.6 ms tick — and then the same-size edit must STILL invalidate.
    """

    WINDOWS_TICK_NS = 15_600_000

    def _coarsen(self):
        real_stat = os.stat

        def coarse(path, *a, **k):
            st = real_stat(path, *a, **k)

            class _S:
                def __getattr__(self, name):
                    return getattr(st, name)
                st_mtime_ns = (st.st_mtime_ns //
                               TestCoarseClockCannotHideAnEdit.WINDOWS_TICK_NS
                               ) * TestCoarseClockCannotHideAnEdit.WINDOWS_TICK_NS
            return _S()
        return coarse

    def test_same_size_edit_survives_a_coarse_mtime(self):
        real_stat = os.stat
        os.stat = self._coarsen()
        try:
            with open(aegis.VOUCH_FILE, "w") as f:
                f.write("AAAA\n")
            aegis.load_vouches()
            before = len(self.calls)
            with open(aegis.VOUCH_FILE, "w") as f:
                f.write("BBBB\n")          # same size, same 15.6ms tick
            aegis.load_vouches()
        finally:
            os.stat = real_stat
        self.assertGreater(
            len(self.calls), before,
            "a same-size edit inside one clock tick served a cached TRUST "
            "store — this is the windows-latest/py3.9 failure")

    def test_the_key_does_not_consult_mtime_at_all(self):
        """Stronger and refactor-proof: coarsening the clock must not change
        the key, because the key is content-addressed."""
        with open(aegis.VOUCH_FILE, "w") as f:
            f.write("AAAA\n")
        fine = aegis._vouch_cache_key()
        real_stat = os.stat
        os.stat = self._coarsen()
        try:
            coarse = aegis._vouch_cache_key()
        finally:
            os.stat = real_stat
        self.assertEqual(fine, coarse, "the cache key still depends on mtime")


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
