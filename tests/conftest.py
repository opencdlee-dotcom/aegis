"""Platform scoping for the legacy (macOS-era) test suite.

test_regression.py, test_research_layers.py and test_roadmap.py were written
when Aegis was macOS-only, so a number of their classes assert macOS-specific
truths: kqueue watch internals, `.app` bundle scoring, `sfltool` background
items, the launchd installer, `codesign` trust verdicts (`adhoc`/`developer-id`),
Homebrew prefixes, and `lsof`/`netstat` output shapes. Those assertions are
correct and worth keeping — they just describe one platform.

Rather than weaken them into platform-agnostic mush (which would delete real
macOS coverage), they are skipped when the suite runs elsewhere. Everything
NOT listed here runs on every platform, and the portable behaviour those
classes cover is re-asserted cross-platform in test_cross_platform.py.

The list is by class name and deliberately explicit: if a class is renamed it
simply stops being skipped and fails loudly on Linux/Windows — a visible
failure mode, never a silent loss of coverage.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

# --------------------------------------------------------------------------- #
# The suite promises it "never touches real ~/.aegis". That promise was broken
# once and nobody could tell: two synthetic incidents (a CRITICAL lineage chain
# and a HIGH risk roll-up on /opt/shared/helper-bin, stamped with the test's
# hardcoded epoch 1700000000) were found sitting in the developer's LIVE
# incident store months later, at the top of a real security tool's alert list.
# The leak came through _event_connection() while EVENT_DB still pointed at the
# real path — a sandbox gap, not a bad test.
#
# The sandbox fixtures are the primary defence; this is the backstop that makes
# the promise enforceable rather than aspirational. It wraps the two writers
# that actually reach durable state and FAILS the test that tries, naming the
# global that was left unsandboxed. It fires only on a real attempt, so pure
# read-only tests (most of the suite) are unaffected, and there is no race with
# the developer's own hourly agent because nothing here inspects the real dir's
# contents — only the path a write is aimed at.
# --------------------------------------------------------------------------- #
_REAL_STATE = os.path.join(os.path.expanduser("~"), ".aegis")


# RUN_LOG is its own module constant, so a test that sandboxes STATE_DIR but
# forgets RUN_LOG writes straight into the operator's live forensic log. That
# happened: 128 fabricated "migrated baseline schema" lines and a run of
# "deadfall latch-cleared -> firing" entries were found in the real
# ~/.aegis/run.log -- the exact file an incident tells the operator to read.
# Every suppressed write is reported at session end so this stays visible
# rather than becoming a silently-tolerated leak.
REAL_RUN_LOG_WRITES = []


def _targets_real_state(path):
    if not path:
        return False
    try:
        p = os.path.realpath(str(path))
    except (TypeError, ValueError, OSError):
        return False
    return p == _REAL_STATE or p.startswith(_REAL_STATE + os.sep)


@pytest.fixture(autouse=True)
def _forbid_real_state_writes():
    """Refuse any durable write aimed at the developer's real ~/.aegis."""
    real_conn = aegis._event_connection
    real_save = aegis.save_json
    real_ensure = aegis.ensure_state
    real_log_run = aegis.log_run
    leaked = []

    def _refuse(what, path):
        leaked.append("%s -> %s" % (what, path))
        raise AssertionError(
            "TEST TRIED TO WRITE REAL STATE: %s points at %s. Sandbox that "
            "global in the test's setUp (see tests/test_regression.py Sandbox)."
            % (what, path))

    def guarded_conn(*a, **k):
        if _targets_real_state(aegis.EVENT_DB):
            _refuse("aegis.EVENT_DB", aegis.EVENT_DB)
        return real_conn(*a, **k)

    def guarded_save(path, *a, **k):
        if _targets_real_state(path):
            _refuse("save_json(path=...)", path)
        return real_save(path, *a, **k)

    def guarded_ensure(*a, **k):
        if _targets_real_state(aegis.STATE_DIR):
            _refuse("aegis.STATE_DIR", aegis.STATE_DIR)
        return real_ensure(*a, **k)

    def guarded_log_run(msg):
        # log_run() writes RUN_LOG with a bare open(), not save_json, and it
        # swallows every exception -- so raising here would be silently eaten
        # and the write would still be the caller's business. Refuse the write
        # instead and record it: a suppressed forensic line is a test problem,
        # a fabricated one in the operator's live run.log is a safety problem.
        if _targets_real_state(aegis.RUN_LOG):
            REAL_RUN_LOG_WRITES.append(str(msg)[:200])
            return None
        return real_log_run(msg)

    aegis._event_connection = guarded_conn
    aegis.save_json = guarded_save
    aegis.ensure_state = guarded_ensure
    aegis.log_run = guarded_log_run
    try:
        yield leaked
    finally:
        aegis._event_connection = real_conn
        aegis.save_json = real_save
        aegis.ensure_state = real_ensure
        aegis.log_run = real_log_run

IS_MAC = sys.platform == "darwin"


# --------------------------------------------------------------------------- #
# The trust vocabulary is PER-PLATFORM, and a test that hard-codes one body's
# word reads as platform-neutral while being anything but.
#
# Earned 2026-08-24: tests/test_outbound_subject.py stubbed
# `classify_signature` to return `{"trust": "adhoc"}` and its own class
# docstring promised the assertions held "on every OS". Ad-hoc signing is a
# codesign concept with no Authenticode equivalent, so `suspicious_sig()`
# rightly rejects "adhoc" on Windows -- every sensor gated on it minted ZERO
# findings there and all 12 cases in the file failed. macOS and Linux were
# green (Linux never consults the verdict: its branch keys on the structural
# exec tell), so the only thing that could see it was a Windows runner, and it
# took 24 minutes of CI to say so.
#
# So ask for the CONCEPT, never for one body's spelling. `suspicious_trust_for`
# mirrors the split in `aegis.suspicious_sig`; a mirror can drift from what it
# mirrors, which is why tests/test_cross_platform.py asserts it against the
# real predicate on all three bodies rather than trusting this comment.
# --------------------------------------------------------------------------- #
def suspicious_trust_for(is_win, is_linux):
    """A trust verdict that `aegis.suspicious_sig()` accepts on that body.

    Linux keys on 'broken' alone ('unmanaged' is true of every locally built
    binary); Windows on Authenticode's 'unsigned'/'broken'; macOS additionally
    on codesign's 'adhoc'.

    One honest caveat, because the obvious reading of this function is wrong:
    on Linux `_classify_linux` emits ONLY 'os-managed' and 'unmanaged', so
    'broken' is a verdict a real Linux host can never produce. The
    suspicious_sig arm is dead by construction there and Linux takes its signal
    from structure instead (see _exec_alert). 'broken' is returned so a STUBBED
    gate opens on all three bodies with one helper; it is not a claim about
    what Linux observes. A test that means to assert Linux behaviour must
    exercise the structural arm, not this verdict.
    """
    if is_linux:
        return "broken"
    return "unsigned" if is_win else "adhoc"


def publisher_trust_for(is_win, is_linux):
    """A trust verdict `aegis.publisher_sig()` accepts on that body — the
    positive twin of suspicious_trust_for, mirroring aegis.publisher_sig.

    macOS returns "apple" rather than "developer-id" so the conversion of the
    existing fixtures is a no-op there: those records already said "apple", and
    a fixture rewrite that silently changes what a macOS assertion means would
    be a worse bug than the one being fixed.
    """
    if is_linux:
        return "os-managed"
    return "os-signed" if is_win else "apple"


PUBLISHER_TRUST = publisher_trust_for(aegis.IS_WIN, aegis.IS_LINUX)

SUSPICIOUS_TRUST = suspicious_trust_for(aegis.IS_WIN, aegis.IS_LINUX)

# Fail at COLLECTION, not 200 assertions later as an unexplained "0 != 1": if
# the product's vocabulary moves, the suite says so in the words of the thing
# that changed.
#
# A bare `assert` would be the obvious spelling and the wrong one: `python -O`
# strips assert statements outright, so the guard would vanish on exactly the
# invocation nobody thinks to re-check, and the `0 != N` noise it exists to
# prevent would come back silently. Raise explicitly.
if not aegis.publisher_sig(PUBLISHER_TRUST):
    raise RuntimeError(
        "conftest.PUBLISHER_TRUST is %r, which aegis.publisher_sig() rejects "
        "on this body -- the trust vocabulary moved and this mirror did not."
        % (PUBLISHER_TRUST,))
if not aegis.suspicious_sig(SUSPICIOUS_TRUST):
    raise RuntimeError(
        "conftest.SUSPICIOUS_TRUST is %r, which aegis.suspicious_sig() rejects "
        "on this body -- the trust vocabulary moved and this mirror did not."
        % (SUSPICIOUS_TRUST,))

# Classes whose assertions are inherently macOS-specific.
_MAC_ONLY_CLASSES = frozenset((
    # kqueue / live log-stream watch internals
    "TestWatchKqueue", "TestLiveStreamTail",
    # .app bundles, Gatekeeper/spctl, quarantine xattr provenance
    "TestHotDirAppBundle", "TestQuarantineProvenance", "TestTimestomp",
    # codesign trust verdicts (adhoc / developer-id / Team ID)
    "TestSigcacheKeying", "TestOptHomebrewRisky", "TestRiskyLocations",
    "TestOutbound", "TestListenerSurface", "TestCheckBehavior",
    "TestBehaviorKeychainCp", "TestBehaviorCommSpace",
    "TestProgramArgv0Decoy", "TestDyldInjection", "TestFingerprintContentHash",
    "TestNeverRepeat", "TestFirstRunScoping", "TestCorruptBaseline",
    # launchd plists, sfltool BTM, macOS ASEP dirs, Apple daemon names
    "TestInstaller", "TestSelfProtection", "TestParseBtmUrlAfterIdentifier",
    "TestBtmChangedItem", "TestResidualAsep", "TestClickLockSignals",
    # macOS response-tier + system-tool path/environment assertions
    "TestResponseTier", "TestSensorHealthCore",
    "TestDurabilityAndCommandBoundary",
))


# --------------------------------------------------------------------------- #
# POSIX-shaped assertions (correct on BOTH macOS and Linux, meaningless on
# Windows). These are a different bucket from the macOS-only list above: adding
# them there would silently delete their Linux coverage, which is real and
# passing. They are keyed by test NAME rather than by class, because in most of
# these classes only one or two cases are path-shaped and the rest are portable
# scoring logic that must keep running on Windows.
#
# What makes a case POSIX-only here: it feeds a literal POSIX path (`/tmp/x`,
# `~/.agent`), a POSIX-only mechanism (setuid, cron, `sudo -u`, `caffeinate`,
# utmp sessions, macOS BTM team IDs), or the macOS `/tmp`->`/private/tmp`
# firmlink pair. In every case the FUNCTION under test is cross-platform and
# stays covered on Windows by tests/test_cross_platform.py; it is the fixture
# that does not translate.
# --------------------------------------------------------------------------- #
_POSIX_ONLY_TESTS = frozenset((
    # setuid bits, and /tmp as a risky prefix
    "test_new_suid_in_tmp_is_critical",
    # utmp/`who` login sessions
    "test_live_remote_session_alerts_on_first_run",
    # macOS BTM items keyed on Developer-ID team IDs
    "test_new_noteam_item_in_writable_path_is_high",
    # `~/.hidden` script payloads behind a POSIX interpreter
    "test_bash_hidden_home_script_is_high",
    "test_interpreter_tmp_script_is_high",
    "test_clean_hidden_home_script_is_high_control",
    "test_normpath_dodge_is_high",
    "test_phexia_osascript_userlib_script_is_medium",
    "test_env_injection_escalates_above_the_high_floor",
    # /tmp <-> /private/tmp firmlink canonicalisation
    "test_chain_joins_across_tmp_private_tmp_firmlink",
    "test_lineage_joins_across_tmp_private_tmp_firmlink",
    "test_same_entity_unifies_firmlink_forms",
    "test_relative_entities_are_ignored",
    # POSIX wrapper launchers (sudo -u, caffeinate, env)
    "test_caffeinate_wrapping_hidden_home_payload_is_hostile",
    "test_script_target_sees_through_the_wrapper",
    "test_sudo_u_wrapper_unwrapped",
    "test_wrapper_value_flag_does_not_eat_the_payload",
    # cron (no Windows equivalent; Windows persistence is schtasks)
    "test_interpreter_aimed_at_a_temp_script_is_high",
    "test_script_payload_is_joinable_to_its_drop",
    "test_interpreter_fronted_persistence_joins_its_script",
    # WHO_CMD-specific: snapshot_auth_sessions() no longer even LOOKS at
    # WHO_CMD when IS_WIN — it dispatches to _snapshot_auth_sessions_win()
    # instead (2026-08-30, the RDP/WinRM sensor). The equivalent invariant
    # (a failed probe is a non-answer, never a false-empty) is covered on
    # Windows by test_cross_platform.py's
    # test_auth_session_win_probe_failure_is_a_non_answer.
    "test_snapshot_none_on_hard_fail",
))


def pytest_collection_modifyitems(config, items):
    if not IS_MAC:
        skip_mac = pytest.mark.skip(
            reason="macOS-specific assertions; portable behaviour is covered by "
                   "tests/test_cross_platform.py")
        for item in items:
            cls = getattr(item, "cls", None)
            if cls is not None and cls.__name__ in _MAC_ONLY_CLASSES:
                item.add_marker(skip_mac)

    if os.name != "posix":
        skip_posix = pytest.mark.skip(
            reason="POSIX-shaped fixture (literal POSIX path, setuid, cron, "
                   "utmp, or the /private/tmp firmlink); the function under "
                   "test is covered on Windows by test_cross_platform.py")
        for item in items:
            if item.name in _POSIX_ONLY_TESTS:
                item.add_marker(skip_posix)


def pytest_sessionfinish(session, exitstatus):
    """Report suppressed live-log writes loudly; the guard is not a licence."""
    if REAL_RUN_LOG_WRITES:
        n = len(REAL_RUN_LOG_WRITES)
        sys.stderr.write(
            "\n%d log_run() write(s) aimed at the REAL ~/.aegis/run.log were "
            "suppressed by tests/conftest.py. Sandbox aegis.RUN_LOG in the "
            "offending test's setUp. First: %s\n" % (n, REAL_RUN_LOG_WRITES[0]))
