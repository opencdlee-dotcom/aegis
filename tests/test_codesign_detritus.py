#!/usr/bin/env python3
"""A strict-only complaint about Finder detritus is not a broken signature.

`_classify_mac` runs `codesign --verify --strict` after reading the chain, and
filed EVERY non-zero exit that did not say "not signed" as `broken`. `broken`
is in suspicious_sig(), so it gates the process, listener and beacon sensors
at HIGH. Measured on the reference Mac, 2026-09-23:

    /Applications/zoom.us.app/Contents/MacOS/zoom.us
    /Applications/Zotero.app/Contents/MacOS/zotero
        --strict:  resource fork, Finder information, or similar detritus not
                   allowed                                          (exit 1)
        plain:     (silent)                                         (exit 0)

Both carry a full Developer ID chain and an intact seal. The complaint is
Finder extended attributes inside the bundle, which only --strict refuses.
It produced 36 HIGH interrupts in 30 days. A real tamper reads differently
and fails WITHOUT --strict too: "invalid signature (code or signature have
been modified)", "a sealed resource is missing or invalid".

So the discriminator is the tool's own: when --strict fails with a detritus
complaint, ask again without --strict. The seal holds -> the chain's trust
stands and the verdict records `strict: detritus`. The seal fails -> `broken`,
as before. A second probe that does not answer is the same non-answer PR #52
made of the first one: `unknown`, probe_failed, never cached.

The parser tests mock `run`, so they run on every body. The live tests are the
ones that matter -- a fixture cannot test a parser -- and they build their
subjects from /bin/ls on the real Mac, so they do not depend on which apps
happen to be installed; the Zoom/Zotero checks run where those apps exist.
"""
import os
import shutil
import struct
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import aegis                                    # noqa: E402
from test_regression import Sandbox                           # noqa: E402

# `codesign -dv --verbose=4` on a Developer ID binary: detail on STDERR, exit
# 0. Field names and order are the real ones; the identity is an example.
DEV_ID_DV = (
    "Executable=/Applications/Example.app/Contents/MacOS/Example\n"
    "Identifier=com.example.app\n"
    "Format=app bundle with Mach-O universal (x86_64 arm64)\n"
    "CodeDirectory v=20500 size=1234 flags=0x10000(runtime) hashes=27+7 "
    "location=embedded\n"
    "Authority=Developer ID Application: Example Ltd (ABCDE12345)\n"
    "Authority=Developer ID Certification Authority\n"
    "Authority=Apple Root CA\n"
    "TeamIdentifier=ABCDE12345\n")

# The verify failures, verbatim from codesign on this Mac (path prefix
# included, exactly as codesign prints it).
DETRITUS = ("%s: resource fork, Finder information, or similar detritus "
            "not allowed\n")
MODIFIED = ("%s: invalid signature (code or signature have been modified)\n"
            "In architecture: x86_64\n")
SEALED = "%s: a sealed resource is missing or invalid\n"

TIMED_OUT = ("", "timeout", 124)     # exactly what run() returns on a timeout
CLEAN_VERIFY = ("", "", 0)           # a passing verify prints NOTHING

# Gated on BOTH, as test_signature_corpus is: CI runs a Linux leg with
# aegis.IS_MAC forced on, and that leg has no codesign to be right about.
REAL_MAC = sys.platform == "darwin" and aegis.IS_MAC

ZOOM = "/Applications/zoom.us.app/Contents/MacOS/zoom.us"
ZOTERO = "/Applications/Zotero.app/Contents/MacOS/zotero"

# A Finder-info blob with one flag set: the shape Finder itself writes, and
# the attribute codesign --strict names as detritus.
FINDER_INFO_HEX = "00000000000000000004" + "00" * 22


def _mac_codesign(test, dv, strict=CLEAN_VERIFY, plain=CLEAN_VERIFY):
    """Answer the codesign calls _classify_mac makes, telling the strict verify
    from the plain one. Anything else goes to the real run() -- a store-level
    test reaches other probes that are not under test here."""
    calls = []
    real = test._saved["run"]

    def fake(cmd, timeout=15, extra_env=None, stdin_data=None):
        cmd = list(cmd)
        if cmd[:2] == ["codesign", "-dv"]:
            calls.append("dv")
            return dv
        if cmd[:2] == ["codesign", "--verify"]:
            if "--strict" in cmd:
                calls.append("strict")
                return strict
            calls.append("plain")
            return plain
        return real(cmd, timeout=timeout, extra_env=extra_env,
                    stdin_data=stdin_data)
    aegis.run = fake
    return calls


class StrictDetritusIsNotTamper(Sandbox):
    """The parser's reading of the two verify answers, on every body."""

    def setUp(self):
        super().setUp()
        # Sandbox.tearDown restores everything in _saved.
        self._saved["run"] = aegis.run
        self._saved["_SIG_PROBE_FAILURES"] = aegis._SIG_PROBE_FAILURES
        aegis._SIG_PROBE_FAILURES = 0
        self.path = os.path.join(self.tmp, "Example")
        with open(self.path, "wb") as fh:
            fh.write(b"\xcf\xfa\xed\xfe fixture bytes")

    def _strict(self, template, rc=1):
        return ("", template % self.path, rc)

    def test_detritus_with_an_intact_seal_keeps_the_chain_trust(self):
        calls = _mac_codesign(self, ("", DEV_ID_DV, 0),
                              strict=self._strict(DETRITUS))
        result = aegis._classify_mac(self.path)
        # BEFORE: {"trust": "broken"} -- a non-zero strict verify that did not
        # say "not signed". Live: Zoom and Zotero, 36 HIGH interrupts.
        self.assertEqual("developer-id", result["trust"], result)
        self.assertEqual("ABCDE12345", result["team"])
        self.assertEqual("detritus", result.get("strict"),
                         "the strict complaint must stay on the record")
        self.assertNotIn("probe_failed", result)
        self.assertEqual(0, aegis._SIG_PROBE_FAILURES)
        self.assertEqual(["dv", "strict", "plain"], calls)

    def test_a_modified_signature_is_still_broken(self):
        _mac_codesign(self, ("", DEV_ID_DV, 0),
                      strict=self._strict(MODIFIED),
                      plain=self._strict(MODIFIED))
        result = aegis._classify_mac(self.path)
        self.assertEqual("broken", result["trust"])
        self.assertNotIn("strict", result)
        self.assertNotIn("probe_failed", result)

    def test_detritus_over_a_broken_seal_is_still_broken(self):
        """Detritus cannot launder a tamper: the plain verify is the one that
        decides, and here it fails with a reason."""
        _mac_codesign(self, ("", DEV_ID_DV, 0),
                      strict=self._strict(DETRITUS),
                      plain=self._strict(SEALED))
        result = aegis._classify_mac(self.path)
        self.assertEqual("broken", result["trust"])
        self.assertNotIn("strict", result)
        self.assertNotIn("probe_failed", result)
        self.assertEqual(0, aegis._SIG_PROBE_FAILURES)

    def test_only_detritus_earns_a_second_probe(self):
        """Every other strict failure is `broken` exactly as before, and is
        not re-asked -- even if a plain verify would have passed."""
        for template in (SEALED, MODIFIED):
            with self.subTest(template=template):
                calls = _mac_codesign(self, ("", DEV_ID_DV, 0),
                                      strict=self._strict(template),
                                      plain=CLEAN_VERIFY)
                result = aegis._classify_mac(self.path)
                self.assertEqual("broken", result["trust"])
                self.assertNotIn("plain", calls)

    def test_a_timed_out_second_probe_is_a_non_answer(self):
        _mac_codesign(self, ("", DEV_ID_DV, 0),
                      strict=self._strict(DETRITUS), plain=TIMED_OUT)
        result = aegis._classify_mac(self.path)
        self.assertEqual("unknown", result["trust"])
        self.assertIs(True, result.get("probe_failed"), result)
        self.assertEqual(1, aegis._SIG_PROBE_FAILURES)

    def test_a_silent_second_probe_failure_is_a_non_answer(self):
        _mac_codesign(self, ("", DEV_ID_DV, 0),
                      strict=self._strict(DETRITUS), plain=("", "", 1))
        result = aegis._classify_mac(self.path)
        self.assertEqual("unknown", result["trust"])
        self.assertIs(True, result.get("probe_failed"), result)
        self.assertEqual(1, aegis._SIG_PROBE_FAILURES)

    def test_a_timed_out_strict_verify_is_unchanged(self):
        """PR #52's non-answer, untouched: nothing to re-ask when the first
        verify said nothing."""
        calls = _mac_codesign(self, ("", DEV_ID_DV, 0), strict=TIMED_OUT)
        result = aegis._classify_mac(self.path)
        self.assertEqual("unknown", result["trust"])
        self.assertIs(True, result.get("probe_failed"), result)
        self.assertEqual(1, aegis._SIG_PROBE_FAILURES)
        self.assertEqual(["dv", "strict"], calls)

    def test_a_timed_out_dv_probe_is_unchanged(self):
        calls = _mac_codesign(self, TIMED_OUT)
        result = aegis._classify_mac(self.path)
        self.assertEqual("unknown", result["trust"])
        self.assertIs(True, result.get("probe_failed"), result)
        self.assertEqual(["dv"], calls)

    # ---- the cache -----------------------------------------------------------

    def _classify_as_mac(self):
        """classify_signature with this body's dispatch routed through the REAL
        mac classifier; everything behind it runs against the mocked codesign.
        On Windows the Sandbox pins classify_signature itself to a stub."""
        name = ("_classify_linux" if aegis.IS_LINUX else
                "_classify_windows" if aegis.IS_WIN else "_classify_mac")
        if name != "_classify_mac":
            self._saved[name] = getattr(aegis, name)
            setattr(aegis, name, aegis._classify_mac)
        return self._saved.get("classify_signature", aegis.classify_signature)

    def test_a_cached_broken_from_older_logic_is_re_probed(self):
        """The fix changes no file on disk, so without a logic bump the live
        cache would keep serving Zoom's `broken` for as long as its stat holds
        -- until Zoom's next update."""
        classify = self._classify_as_mac()
        aegis._sigcache[self.path] = {
            "stat": aegis._sig_stat(self.path),
            "result": {"trust": "broken", "team": "ABCDE12345",
                       "authority": "Developer ID Application: Example Ltd "
                                    "(ABCDE12345)"},
            "v": aegis._SIGCACHE_LOGIC_VERSION - 1}
        _mac_codesign(self, ("", DEV_ID_DV, 0), strict=self._strict(DETRITUS))
        self.assertEqual("developer-id", classify(self.path)["trust"])
        entry = aegis._sigcache[self.path]
        self.assertEqual(aegis._SIGCACHE_LOGIC_VERSION, entry["v"])
        self.assertEqual("developer-id", entry["result"]["trust"])
        self.assertEqual("detritus", entry["result"].get("strict"))

    def test_logic_version_is_bumped(self):
        self.assertGreaterEqual(aegis._SIGCACHE_LOGIC_VERSION, 4)


# --------------------------------------------------------------------------- #
# The exit: incidents the misread opened close when the verdict is re-asked.
# --------------------------------------------------------------------------- #
T0 = 1_700_000_000
REMOTE = "203.0.113.7"          # TEST-NET-3: an address that routes nowhere


def _health(sensor, status="OK"):
    return [{"sensor_id": sensor, "status": status, "detail": "",
             "duration_ms": 0, "item_count": 0}]


# Gated on the FLAG, not the kernel: nothing here touches codesign or the
# filesystem's trust (run and is_risky_location are replaced), but the verdict
# the mac classifier produces is mac vocabulary -- `developer-id` is a
# publisher only on a body whose flags say mac. The body-neutral half of this
# exit is test_false_alarm_batch_20260922.A2AFlippedVerdictClosesItsIncident.
@unittest.skipUnless(aegis.IS_MAC and not aegis.IS_WIN and not aegis.IS_LINUX,
                     "mac trust vocabulary only")
class DetritusVerdictReachesTheReverifyExit(Sandbox):
    """The live incidents were `outbound` beacons on /Applications paths,
    gated on `broken`. With the parser fixed the sensor stops emitting, and
    _close_reverified_incidents is what closes what the misread opened."""

    def setUp(self):
        super().setUp()
        self._saved["run"] = aegis.run
        self._saved["_SIG_PROBE_FAILURES"] = aegis._SIG_PROBE_FAILURES
        self._saved.setdefault("is_risky_location", aegis.is_risky_location)
        # An /Applications path is not risky; the sandbox's tmp dir may be.
        aegis.is_risky_location = lambda path: False
        self.path = os.path.join(self.tmp, "zoom.us")
        with open(self.path, "wb") as fh:
            fh.write(b"\xcf\xfa\xed\xfe fixture bytes")

    def _beacon(self):
        key = "beacon:%s:%s:443" % (self.path, REMOTE)
        return aegis.finding(
            "HIGH", "net-beacon",
            "Persistent outbound connection (beacon shape)",
            "%s [broken] has held a connection to %s:443" % (self.path, REMOTE),
            key, case_fingerprint=key, path=self.path, program=self.path,
            remote=REMOTE, port="443", trust="broken", sensor_id="outbound")

    def _row(self, f):
        db = aegis._event_connection()
        try:
            r = db.execute("SELECT * FROM incidents WHERE correlation_key=?",
                           ("signal:" + f["case_fingerprint"],)).fetchone()
            return dict(r) if r else None
        finally:
            db.close()

    def _open(self, f):
        aegis.record_security_state([f], sensor_health=_health("outbound"),
                                    now=T0)
        self.assertEqual("OPEN", self._row(f)["status"], "fixture did not open")

    def _rescan(self):
        aegis.record_security_state([], sensor_health=_health("outbound"),
                                    now=T0 + 600)

    def test_a_detritus_misread_closes_as_re_verified(self):
        f = self._beacon()
        self._open(f)
        _mac_codesign(self, ("", DEV_ID_DV, 0),
                      strict=("", DETRITUS % self.path, 1))
        self._rescan()
        row = self._row(f)
        self.assertEqual("FALSE_POSITIVE", row["status"])
        self.assertIn("re-verified", row["resolution"] or "")
        self.assertIn("developer-id", row["resolution"] or "")

    def test_a_real_tamper_stays_open(self):
        f = self._beacon()
        self._open(f)
        _mac_codesign(self, ("", DEV_ID_DV, 0),
                      strict=("", MODIFIED % self.path, 1),
                      plain=("", MODIFIED % self.path, 1))
        self._rescan()
        self.assertEqual("OPEN", self._row(f)["status"])

    def test_the_scan_that_opens_it_does_not_close_it(self):
        """The exit runs inside record_security_state: an incident opened in
        this very call is asserted this scan and is never its to judge, even
        with the classifier already answering a publisher."""
        _mac_codesign(self, ("", DEV_ID_DV, 0),
                      strict=("", DETRITUS % self.path, 1))
        f = self._beacon()
        self._open(f)
        self.assertEqual("OPEN", self._row(f)["status"])


# --------------------------------------------------------------------------- #
# The real tool on the real body.
# --------------------------------------------------------------------------- #
def _codesign_verify(path, strict):
    cmd = ["codesign", "--verify"] + (["--strict"] if strict else []) + [path]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def _add_finder_info(path):
    subprocess.run(["xattr", "-wx", "com.apple.FinderInfo", FINDER_INFO_HEX,
                    path], check=True, capture_output=True)


def _flip_a_signed_byte(path):
    """Flip one byte a quarter of the way into the first Mach-O slice: inside
    the code the signature's page hashes cover, well before the signature."""
    with open(path, "rb") as fh:
        data = bytearray(fh.read())
    if struct.unpack(">I", bytes(data[:4]))[0] == 0xCAFEBABE:   # fat header
        offset, size = struct.unpack(">II", bytes(data[16:24]))
    else:
        offset, size = 0, len(data)
    data[offset + size // 4] ^= 0xFF
    with open(path, "wb") as fh:
        fh.write(data)


@unittest.skipUnless(REAL_MAC, "classifies real codesign output; macOS only")
class LiveCodesignDetritus(Sandbox):
    """What codesign actually prints, on this Mac, for both classes."""

    def _copy_of_ls(self, name):
        # Bytes and mode only: copy2's copystat is refused on a system file's
        # flags, and the signature is embedded in the bytes anyway.
        path = os.path.join(self.tmp, name)
        shutil.copyfile("/bin/ls", path)
        os.chmod(path, 0o755)
        return path

    def test_finder_info_on_a_platform_binary_keeps_apple(self):
        path = self._copy_of_ls("ls-detritus")
        _add_finder_info(path)
        rc, text = _codesign_verify(path, strict=True)
        self.assertNotEqual(0, rc, "fixture: --strict did not refuse it")
        self.assertIn("detritus", text, "fixture: not the detritus class")
        self.assertEqual(0, _codesign_verify(path, strict=False)[0],
                         "fixture: the plain verify should pass")
        result = aegis._classify_mac(path)
        self.assertEqual("apple", result["trust"], result)
        self.assertEqual("detritus", result.get("strict"))

    def test_a_modified_platform_binary_is_still_broken(self):
        """The adversarial case: bytes changed AND Finder info added, as if to
        steer the verdict into the lenient path."""
        path = self._copy_of_ls("ls-modified")
        _flip_a_signed_byte(path)
        _add_finder_info(path)
        rc, text = _codesign_verify(path, strict=False)
        self.assertNotEqual(0, rc, "fixture: the tamper did not land in "
                                   "signed code: %s" % text)
        result = aegis._classify_mac(path)
        self.assertEqual("broken", result["trust"], result)
        self.assertNotIn("strict", result)

    def test_the_apps_that_raised_the_alarms_classify_developer_id(self):
        present = [p for p in (ZOOM, ZOTERO) if os.path.exists(p)]
        if not present:
            self.skipTest("neither Zoom nor Zotero is installed here")
        for path in present:
            with self.subTest(path=path):
                self.assertEqual("developer-id",
                                 aegis.classify_signature(path)["trust"])


if __name__ == "__main__":
    unittest.main()
