"""The precision tier: identity fixes for the sensors that re-alert on standing state.

Measured cause, on the reference machine 2026-08-21: 283 incidents lifetime,
215 adjudicated FALSE_POSITIVE, 46 OPEN, and ZERO true positives. A live scan
produced 52 findings of which exactly TWO were new fingerprints; the other 50
were standing observations re-rendered as though they were fresh.

Two of those re-renders were pure identity bugs, and this file pins both:

  * amfid hashed the whole log MESSAGE, so one file rejected twice minted two
    fingerprints, and no `path` ever reached the custody ladder -- 26 findings
    for 19 distinct files, none of them graded, though 18 sit under a Homebrew
    receipt the grader already understands.
  * an editor extension was identified by its DIRECTORY name, which carries the
    version. `anthropic.claude-code` had four versions installed and
    `openai.chatgpt` five: nine directories, two actual extensions, and a fresh
    MEDIUM "New editor extension" on every upgrade.

Each class pins the fix AND the safety property that keeps the fix from
becoming a blind spot -- the safety half is the point, because both fixes
suppress something.
"""
import inspect
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


# A real message, copied from the reference machine's unified log.
_REAL_MSG = (
    "/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/"
    "Versions/3.14/lib/python3.14/lib-dynload/_hashlib.cpython-314-darwin.so "
    'not valid: Error Domain=AppleMobileFileIntegrityError Code=-423 "The file '
    'is adhoc signed or signed by an unknown certificate chain" '
    "UserInfo={NSURL=file:///opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/"
    "Python.framework/Versions/3.14/lib/python3.14/lib-dynload/"
    "_hashlib.cpython-314-darwin.so}")


class AmfidIdentityIsTheFileNotTheMessage(unittest.TestCase):
    """Fix 1 -- an amfid denial is identified by the rejected FILE."""

    def test_path_is_extracted_from_the_message(self):
        got = aegis._amfid_path(_REAL_MSG)
        self.assertEqual(got, (
            "/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/"
            "Versions/3.14/lib/python3.14/lib-dynload/_hashlib.cpython-314-darwin.so"))

    def test_same_file_twice_is_one_identity(self):
        """The 26-findings-for-19-files bug: seven files were counted twice
        because two log lines about one file differ in trailing detail."""
        variant = _REAL_MSG.replace("Code=-423", "Code=-423 ")
        self.assertEqual(aegis._amfid_path(_REAL_MSG),
                         aegis._amfid_path(variant))

    def test_a_message_with_no_path_never_raises_and_stays_visible(self):
        """Safety: an unparsable message must not vanish. Format varies by OS
        build; a parser miss that silently dropped the finding would be a blind
        spot introduced to buy quiet."""
        self.assertIsNone(aegis._amfid_path("amfid: something we cannot parse"))
        self.assertIsNone(aegis._amfid_path(""))
        self.assertIsNone(aegis._amfid_path(None))


class ExtensionIdentityIsThePublisherNotTheVersion(unittest.TestCase):
    """Fix 2 -- an extension is identified by publisher.name, version is an
    attribute. An upgrade is a transition, not a new extension."""

    def test_version_and_platform_are_split_off(self):
        for raw, ident, ver in (
            ("anthropic.claude-code-2.1.238-darwin-arm64",
             "anthropic.claude-code", "2.1.238"),
            ("openai.chatgpt-26.818.31338-darwin-arm64",
             "openai.chatgpt", "26.818.31338"),
            ("ms-playwright.playwright-1.1.19",
             "ms-playwright.playwright", "1.1.19"),
            # A name whose own text contains a dash must not be truncated.
            ("reditorsupport.r-syntax-0.1.4",
             "reditorsupport.r-syntax", "0.1.4"),
        ):
            self.assertEqual(aegis._ext_identity(raw), (ident, ver), raw)

    def test_an_unversioned_directory_keeps_its_whole_name(self):
        """Safety: no version suffix means the whole name IS the identity --
        never silently truncate an extension we cannot parse."""
        self.assertEqual(aegis._ext_identity("some.extension"),
                         ("some.extension", None))

    def test_upgrading_an_extension_is_not_a_new_extension(self):
        """The measured bug: four claude-code versions and five chatgpt versions
        on disk, each upgrade a fresh MEDIUM."""
        prior = {".vscode:anthropic.claude-code-2.1.235-darwin-arm64": "claude-code"}
        cur = dict(prior)
        cur[".vscode:anthropic.claude-code-2.1.238-darwin-arm64"] = "claude-code"
        new = [f for f in aegis.diff_ide_ext(prior, cur)
               if f["title"] == "New editor extension"]
        self.assertEqual(new, [], "an upgrade must not report a new extension")

    def test_a_genuinely_new_publisher_still_alerts(self):
        """Safety: this fix must not blind the supply-chain surface it exists
        for. A backdoored extension arrives as a publisher we have never seen."""
        prior = {".vscode:anthropic.claude-code-2.1.235-darwin-arm64": "claude-code"}
        cur = dict(prior)
        cur[".vscode:evil.stealer-1.0.0"] = "stealer"
        new = [f for f in aegis.diff_ide_ext(prior, cur)
               if f["title"] == "New editor extension"]
        self.assertEqual(len(new), 1)
        self.assertIn("evil.stealer", new[0]["detail"])

    def test_a_swapped_publisher_at_the_same_version_still_alerts(self):
        """Safety: identity is publisher.name, so a DIFFERENT publisher shipping
        the same version string is a different extension, not an upgrade."""
        prior = {".vscode:anthropic.claude-code-2.1.238-darwin-arm64": "claude-code"}
        cur = {".vscode:attacker.claude-code-2.1.238-darwin-arm64": "claude-code"}
        new = [f for f in aegis.diff_ide_ext(prior, cur)
               if f["title"] == "New editor extension"]
        self.assertEqual(len(new), 1)
        self.assertIn("attacker.claude-code", new[0]["detail"])


if __name__ == "__main__":
    unittest.main()


class OneCasePerSubjectNotPerContentHash(unittest.TestCase):
    """Fix 3 -- an incident is keyed on the SUBJECT, not the subject plus the
    content hash of whatever it changed to.

    Measured cause: the persistence correlation key was
    `signal:persistence:changed:<path>:<content-hash>`, so every edit to one
    launchd plist opened a brand-new HIGH incident. On the reference machine
    that produced SEVENTEEN open persistence incidents across roughly SEVEN
    distinct files -- `com.SESSION-KEEPER.*` alone held four. The menu-bar
    plugin counts OPEN INCIDENTS, so this was the single largest contributor
    to the number the operator actually reads.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_case_")
        state = os.path.join(self.tmp, ".aegis")
        os.makedirs(state)
        self._saved = {}
        for k, v in (("STATE_DIR", state),
                     ("EVENT_DB", os.path.join(state, "aegis.db"))):
            self._saved[k] = getattr(aegis, k)
            setattr(aegis, k, v)
        aegis.init_event_store()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(aegis, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def _changed(path, content_hash):
        """A 'Persistence item CHANGED' finding, as the sensor builds it."""
        return aegis.finding(
            "HIGH", "persistence", "Persistence item CHANGED",
            "%s changed" % path,
            "persistence:changed:%s:%s" % (path, content_hash),
            case_fingerprint="persistence:changed:%s" % path, path=path)

    def _keys(self):
        db = aegis._event_connection()
        try:
            return [r[0] for r in db.execute(
                "SELECT correlation_key FROM incidents").fetchall()]
        finally:
            db.close()

    def test_editing_one_file_three_times_opens_one_case(self):
        for i, h in enumerate(("aaaa1111", "bbbb2222", "cccc3333")):
            aegis.record_security_state(
                [self._changed("/L/com.SESSION-KEEPER.plist", h)],
                now=1787000000 + i * 3600)
        keys = self._keys()
        self.assertEqual(len(keys), 1, keys)
        self.assertEqual(keys[0],
                         "signal:persistence:changed:/L/com.SESSION-KEEPER.plist")

    def test_each_change_is_still_its_own_finding(self):
        """Safety: collapsing the CASE must not collapse the EVIDENCE. Every
        edit keeps its own content-addressed fingerprint, so a genuinely new
        change is still a new signal and still notifies once."""
        a = self._changed("/L/x.plist", "aaaa1111")
        b = self._changed("/L/x.plist", "bbbb2222")
        self.assertNotEqual(a["fingerprint"], b["fingerprint"])
        self.assertEqual(a["case_fingerprint"], b["case_fingerprint"])

    def test_two_different_files_stay_two_cases(self):
        """Safety: the subject is the FILE. Two files must never merge."""
        aegis.record_security_state(
            [self._changed("/L/one.plist", "aaaa1111"),
             self._changed("/L/two.plist", "bbbb2222")], now=1787000000)
        self.assertEqual(len(self._keys()), 2)

    def test_a_finding_without_a_case_key_is_unchanged(self):
        """Safety: every sensor that has not opted in keeps byte-identical
        behaviour -- the case key is additive, never a global rewrite."""
        f = aegis.finding("HIGH", "process", "Suspicious running process",
                          "d", "process:/tmp/x:abcd")
        aegis.record_security_state([f], now=1787000000)
        self.assertEqual(self._keys(), ["signal:process:/tmp/x:abcd"])


class ProgramIdentitySurvivesAnUpgrade(unittest.TestCase):
    """Fix 4 -- process and beacon cases are keyed on the PROGRAM, not the
    versioned path the program currently lives at.

    Measured cause: after the persistence fix, what remained open on the
    reference machine was editor-extension churn -- `codex` open at three
    versions and `claude` at two, each version a distinct path and therefore a
    distinct incident. Every extension update minted more, forever.
    """

    def test_versions_of_one_program_share_a_subject(self):
        a = ("/Users/x/.vscode/extensions/openai.chatgpt-26.814.41407-"
             "darwin-arm64/bin/macos-aarch64/codex")
        b = ("/Users/x/.vscode/extensions/openai.chatgpt-26.818.31338-"
             "darwin-arm64/bin/macos-aarch64/codex")
        self.assertEqual(aegis._program_subject(a), aegis._program_subject(b))

    def test_two_different_programs_never_merge(self):
        """Safety: only the VERSION generalizes. Different software at
        different paths must stay different subjects."""
        a = "/Users/x/.vscode/extensions/openai.chatgpt-1.2.3/bin/codex"
        b = "/Users/x/.vscode/extensions/evil.stealer-1.2.3/bin/codex"
        self.assertNotEqual(aegis._program_subject(a), aegis._program_subject(b))

    def test_a_beacon_case_still_carries_its_endpoint(self):
        """Safety, and the objection Codex raised: normalizing the program must
        NOT drop the endpoint from the case. A new destination for a known
        binary is the exfil shape -- it has to land as its own case, not as
        more evidence on an existing one."""
        f1 = aegis.finding(
            "HIGH", "net-beacon", "Persistent outbound connection (beacon shape)",
            "d", "beacon:/p/claude-1.0.0/claude:1.2.3.4:443",
            case_fingerprint="beacon:%s:1.2.3.4:443"
                             % aegis._program_subject("/p/claude-1.0.0/claude"))
        f2 = aegis.finding(
            "HIGH", "net-beacon", "Persistent outbound connection (beacon shape)",
            "d", "beacon:/p/claude-1.0.0/claude:9.9.9.9:443",
            case_fingerprint="beacon:%s:9.9.9.9:443"
                             % aegis._program_subject("/p/claude-1.0.0/claude"))
        self.assertNotEqual(f1["case_fingerprint"], f2["case_fingerprint"])


class VenvOutputIsGroupedButNeverGraded(unittest.TestCase):
    """Fix 5 -- a project virtualenv is grouped, but claims no provenance.

    Measured 2026-08-23: a `.venv` appeared under ~/Ai/001/ARC/Vaultkeeper and
    its 22 ad-hoc signed wheels each became their own amfid finding, taking the
    sensor from 8 back to 27. Same class as the Homebrew case, but pip and uv
    write wheels straight into site-packages with no receipt beside the file --
    so `_package_receipt` cannot see it and MUST NOT pretend to.
    """

    def test_the_owning_site_packages_dir_is_found(self):
        self.assertEqual(
            aegis._sitepackages_root(
                "/p/.venv/lib/python3.12/site-packages/foo/_c.so"),
            "/p/.venv/lib/python3.12/site-packages")

    def test_windows_separators_resolve_too(self):
        """CI caught this on both Windows runners: the first implementation
        split on os.sep, so every forward-slash path returned None off posix.
        These paths arrive as TEXT out of a log message, not from the local
        filesystem, so os.sep was never the right authority."""
        self.assertEqual(
            aegis._sitepackages_root(
                r"C:\proj\.venv\Lib\site-packages\foo\_c.pyd"),
            r"C:\proj\.venv\Lib\site-packages")
        self.assertEqual(
            aegis._sitepackages_root(
                r"C:\proj\.venv\Lib\site-packages"),
            r"C:\proj\.venv\Lib\site-packages")

    def test_a_path_outside_a_venv_has_no_root(self):
        self.assertIsNone(aegis._sitepackages_root("/opt/homebrew/bin/rg"))
        self.assertIsNone(aegis._sitepackages_root(""))

    def test_grouping_is_not_grading(self):
        """The safety property that separates this from the receipt tier: a
        venv group is reported at MEDIUM, never demoted. Nothing vouches for a
        directory just because a package manager wrote it."""
        src = inspect.getsource(aegis.check_amfid_log)
        venv_block = src.split("venvs, ungrouped")[1].split("for path in sorted(ungrouped)")[0]
        self.assertIn('"MEDIUM"', venv_block)
        self.assertNotIn("_grade_binary", venv_block)

    def test_a_new_file_in_a_reported_venv_still_alerts(self):
        """The blind spot a plain directory-keyed group would have opened: a
        malicious .so dropped into an already-reported venv must not inherit
        that group's identity and vanish. The member digest is in the
        fingerprint precisely so it does not."""
        a = "amfid:deny:venv:%s:%s" % (
            aegis._sha_key("/p/site-packages"),
            aegis._sha_key("\n".join(["/p/site-packages/a.so"])))
        b = "amfid:deny:venv:%s:%s" % (
            aegis._sha_key("/p/site-packages"),
            aegis._sha_key("\n".join(["/p/site-packages/a.so",
                                      "/p/site-packages/evil.so"])))
        self.assertNotEqual(a, b)
