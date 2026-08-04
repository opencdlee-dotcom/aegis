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


def pytest_collection_modifyitems(config, items):
    if IS_MAC:
        return
    skip = pytest.mark.skip(
        reason="macOS-specific assertions; portable behaviour is covered by "
               "tests/test_cross_platform.py")
    for item in items:
        cls = getattr(item, "cls", None)
        if cls is not None and cls.__name__ in _MAC_ONLY_CLASSES:
            item.add_marker(skip)
