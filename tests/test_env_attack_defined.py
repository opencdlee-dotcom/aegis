"""A benign PATH variable must not disqualify a job from custody grading.

`check_persistence` treated ANY EnvironmentVariables dict as attack-defined
(`attack_defined = bool(rec.get("env"))`), and `_custody_persistence` refused
to return a rung on the same test. But an env dict containing only `PATH`,
`LANG` or `HOME` is an ordinary launchd/systemd idiom — the injection vectors
the refusal exists for are the DYLD_*/LD_PRELOAD family the file already
names (`_DYLD_INJECT_KEYS`, `_LD_INJECT_KEYS`). Found live as incident #319:
a plist whose env is a plain `PATH` was permanently disqualified from
grading, so a one-time benign change sat at HIGH with no path down but the
7-day age-out.

The boundary that must hold (and is pinned here from both sides): a real
injection env — any DYLD_* key, LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT —
keeps its full severity under perfect custody, exactly as before.

Platform-independent by construction: plain dict records through
check_persistence; env-key semantics are cross-platform vocabulary, not
platform behavior.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import SUSPICIOUS_TRUST, aegis                  # noqa: E402
from test_regression import Sandbox                           # noqa: E402


class EnvAttackDefinedPredicate(unittest.TestCase):
    def test_benign_env_is_not_attack_defined(self):
        for env in (None, {}, {"PATH": "/opt/bin:/usr/bin"},
                    {"LANG": "en_US.UTF-8", "HOME": "/Users/x"}):
            self.assertFalse(aegis._env_attack_defined(env), env)

    def test_injection_env_is_attack_defined(self):
        for env in ({"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib"},
                    {"DYLD_FRAMEWORK_PATH": "/tmp"},
                    {"LD_PRELOAD": "/tmp/evil.so"},
                    {"LD_AUDIT": "/tmp/a.so"},
                    {"PATH": "/usr/bin", "LD_PRELOAD": "/tmp/evil.so"}):
            self.assertTrue(aegis._env_attack_defined(env), env)

    def test_an_unknown_dyld_key_stays_attack_defined(self):
        """Fail toward suspicion for the whole DYLD_ namespace — new keys
        appear across OS releases and an allowlist would rot."""
        self.assertTrue(aegis._env_attack_defined({"DYLD_WHATEVER_NEW": "x"}))


class BenignEnvDoesNotBlockCustody(Sandbox):
    def _relocated(self, env):
        """The `relocated` shape: same bytes, same basename, new directory."""
        old = {"label": "j", "program": "/old/dir/tool", "args": None,
               "trust": SUSPICIOUS_TRUST, "sha256": "samebytes",
               "run_at_load": True}
        new = {"label": "j", "program": "/new/dir/tool", "args": None,
               "trust": SUSPICIOUS_TRUST, "sha256": "samebytes",
               "run_at_load": True, "env": env}
        fs = aegis.check_persistence({"/fake/j.plist": old},
                                     {"/fake/j.plist": new})
        self.assertEqual(1, len(fs), fs)
        return fs[0]["severity"]

    def test_a_plain_path_env_lets_relocation_grade_down(self):
        """BEFORE THE FIX: the PATH dict alone forced attack_defined, custody
        was refused, and a proven byte-identical relocation sat at HIGH."""
        sev = self._relocated({"PATH": "/opt/homebrew/bin:/usr/bin"})
        self.assertLess(aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"],
                        "a benign PATH env blocked all custody grading: %s"
                        % sev)

    def test_an_injection_env_is_still_never_graded_down(self):
        """The control, from the other side of the boundary: perfect custody
        must never quiet a dylib injection."""
        sev = self._relocated({"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib"})
        self.assertGreaterEqual(
            aegis.SEV_ORDER[sev], aegis.SEV_ORDER["HIGH"],
            "an injection env was graded down by custody: %s" % sev)


if __name__ == "__main__":
    unittest.main()
