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

IS_MAC = sys.platform == "darwin"

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
